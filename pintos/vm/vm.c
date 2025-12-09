/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#define USER_STACK (void *)0x47480000 // Pintos 스택의 최상단 주소 (0xc0000000 또는 0x47480000 근처)
#define STACK_LIMIT (USER_STACK - (1 << 20)) // 8MB 경계

static struct list_elem *clock_hand;
static struct lock frame_table_lock; //프레임 테이블 접근 동기화
static struct list frame_table; //물리 메모리 프레임의 메타데이터를 관리하는 테이블

static unsigned page_hash (const struct hash_elem *e, void *aux);
static bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void page_vm_destroy(struct hash_elem *e, void *aux);
void vm_free_frame (struct frame *frame);

static bool is_valid_stack_access (void *addr, void *rsp);
static bool vm_stack_growth (void *fault_addr);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	/* vm_free_frame() 등에서 frame_table_lock과 
	frame_table을 사용하므로 반드시 초기화 */
	lock_init(&frame_table_lock);
    list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
        vm_initializer *init, void *aux) {

    ASSERT (VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current ()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page (spt, upage) == NULL) {
        //새 페이지 구조체 할당
        struct page *page = (struct page *)calloc(1, sizeof(struct page));
        if (page == NULL)
            goto err;
        
        //vm 타입에 따라 initializer 선택
        bool (*page_initializer)(struct page *, enum vm_type, void *);

        switch (VM_TYPE(type)) {
            case VM_ANON:
                page_initializer = anon_initializer;
                break;
            case VM_FILE:
                page_initializer = file_backed_initializer;
                break;
            default:
                free(page);
                goto err;
        }

        //uninit 페이지 생성
        uninit_new(page, upage, init, type, aux, page_initializer);

        //writable 설정
        page->writable = writable;

        //SPT에 삽입
        if(!spt_insert_page(spt, page)) {
            // 파일 닫기 및 aux 해제 (원래 코드 유지):
            if (VM_TYPE(page->uninit.type) == VM_FILE) {
                struct file_page *f_page = (struct file_page *)page->uninit.aux;
                if (f_page->file != NULL) file_close(f_page->file);
            }
            if (page->uninit.aux != NULL) free(page->uninit.aux);
        
            vm_dealloc_page(page); 
            goto err;
        }

        return true;
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page p;
    memset(&p, 0, sizeof(struct page));
    struct hash_elem *e;

    p.va = pg_round_down(va);
    e = hash_find(&spt->pages, &p.hash_elem);

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page ) {
	return hash_insert(&spt->pages, &page->hash_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	struct hash_elem *deleted_elem = hash_delete(&spt->pages, &page->hash_elem);
    
    // 제거할 항목이 SPT에 없었으면 vm_dealloc_page를 호출하지 않고 종료합니다.
    if (deleted_elem == NULL) {
        return;
    }
	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
    struct frame *victim = NULL;
    
    lock_acquire(&frame_table_lock);
    
    if (list_empty(&frame_table)) {
        goto done; // 프레임 테이블이 비어있으면 종료
    }

    // 시계 바늘 초기화: 리스트의 끝을 가리키거나 NULL이면 시작 지점으로 돌립니다.
    if (clock_hand == NULL || clock_hand == list_end(&frame_table)) {
        clock_hand = list_begin(&frame_table);
    }
    
    // Clock 알고리즘 순회 (희생자를 찾을 때까지 반복)
    while (true) {
        // 1. 현재 시계 바늘이 가리키는 프레임 구조체 획득
        struct frame *f = list_entry(clock_hand, struct frame, elem);
        struct page *p = f->page;

        // 2. 다음 위치로 시계 바늘 이동 (순환 구조)
        clock_hand = list_next(clock_hand);
        if (clock_hand == list_end(&frame_table)) {
            clock_hand = list_begin(&frame_table); // 리스트 끝에 도달하면 시작으로 돌아감
        }

        // 3. 페이지가 프레임에 연결되어 있지 않다면 건너뜀 (이미 해제된 프레임일 수 있음)
        if (p == NULL) {
            continue;
        }
        
        if (pml4_is_accessed(thread_current()->pml4, p->va)) {
            // R = 1 인 경우 (접근됨): 두 번째 기회 부여
            
            // 접근 비트를 0 (Accessed = false)으로 설정
            pml4_set_accessed(thread_current()->pml4, p->va, false);
        } 
        else {
            // R = 0 인 경우 (접근 안 됨): 희생자 선정
            victim = f;
            break; // 희생자 발견, 루프 종료
        }
    }

done:
    lock_release(&frame_table_lock);
    
    return victim;
}

/* Evict one page and return the corresponding frame. */
static struct frame *
vm_evict_frame (void) {
    struct frame *victim = vm_get_victim ();
    
    if (victim == NULL || victim->page == NULL) {
        return NULL;
    }

    struct page *page = victim->page;
    struct thread *curr = thread_current();

    // 2. 페이지의 swap_out 핸들러 호출
    // VM_FILE 페이지는 file_backed_swap_out, VM_ANON 페이지는 anon_swap_out 호출
    if (!page->operations->swap_out(page)) {
        // swap_out 실패 시, 이 프레임을 쫓아낼 수 없으므로 NULL 반환
        return NULL;
    }

	if (pml4_get_page(curr->pml4, page->va) != NULL) { // 현재 스레드에 매핑되어 있을 경우만
         pml4_clear_page(curr->pml4, page->va);
    }
    
    // 3. victim 프레임 반환 (이 프레임은 vm_get_frame에서 재활용됩니다.)
    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	//사용자 풀에서 물리 페이지 할당
	void *kva = palloc_get_page(PAL_USER);
	bool is_new_frame = true; // 새로 할당된 프레임인지 추적

	if (kva == NULL) {
        frame = vm_evict_frame();

        if (frame == NULL) {
			return NULL;
            // PANIC("Physical memory is exhausted even after eviction.");
        }

        kva = frame->kva;
		is_new_frame = false; 
		frame->page = NULL;
    }
	else {
		frame = (struct frame *)calloc(1, sizeof(struct frame));
		if(frame == NULL) {
			palloc_free_page(kva);
			PANIC("todo: Handle malloc failure gracefully"); //앞으로 eviction(스왑 아웃)하면서 구현 예정
		}

		frame->kva = kva;
	}

	// 💡 프레임 테이블 동기화 및 등록 (조건부 삽입)
    // 새로 할당된 경우에만 리스트에 추가합니다. (기존 프레임은 이미 리스트에 있음)
    if (is_new_frame) {
        lock_acquire(&frame_table_lock);
        list_push_back(&frame_table, &frame->elem);
        lock_release(&frame_table_lock);
    }

	ASSERT (frame != NULL);
	// ASSERT (frame->page == NULL);
	return frame;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	return false;
}

bool 
vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    
    if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

	if (not_present) 
    {
        void *rsp_on_stack = (user ? f->rsp : thread_current()->rsp);
        page = spt_find_page(spt, addr);
        
        //조건문통합
		if (page == NULL) {
            printf("3");
            if (addr >= STACK_LIMIT && addr <= USER_STACK) {
                printf("4");
               if (addr >= rsp_on_stack - 8 && addr < (void *)USER_STACK) {
                    if (vm_stack_growth(addr)) { 
                        page = spt_find_page(spt, addr);
                        if (page != NULL) {
                             return vm_do_claim_page(page);
                        }
                    }
                }
            }
            return false; 
        }
        printf("5");
        if (write && !page->writable)
            return false;

        return vm_do_claim_page(page);
    }
    printf("6");
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	vm_destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	//SPT에서 페이지 찾기
	page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL)
		return false;

	//물리 메모리 할당 및 로드
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *curr = thread_current();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	//VA->PA 매핑 추가
	if(!pml4_set_page(curr->pml4, page->va, frame->kva, page->writable)) {
		//매핑 실패 : 프레임만 정리
		frame->page = NULL;
		page->frame = NULL;
		vm_free_frame(frame);
		return false;
	}

	// 페이지 내용 로드 (UNINIT -> ANON/FILE)
    if (!vm_swap_in(page, frame->kva)) {
        // printf("7");
        // vm_swap_in 실패 시: 매핑 제거 및 프레임 정리 (Clean Up)
        pml4_clear_page(curr->pml4, page->va);
        frame->page = NULL;
        page->frame = NULL;
        vm_free_frame(frame);
        return false;
    }
    // printf("8");
    return true;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	//SPT 초기화
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
        struct supplemental_page_table *src) {

    struct hash_iterator i;
    hash_first(&i, &src->pages);

    while(hash_next(&i)) {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type src_type = page_get_type(src_page); // 원본 페이지의 실제 타입

        void *upage = src_page->va;
        bool writable = src_page->writable;

        /* 1. 🔍 UNINIT 페이지 (Lazy Loading: VM_ANON 또는 VM_FILE) 처리 */
        if (src_type == VM_UNINIT) {
            
            struct uninit_page *uninit = &src_page->uninit;
            void *aux = uninit->aux;
            bool aux_copied = false;
            
            // VM_FILE 타입인 경우에만 aux 구조체를 깊은 복사하고 file_reopen
            if (VM_TYPE(uninit->type) == VM_FILE && uninit->aux != NULL) {
                
                // VM_FILE의 aux 구조체를 복사하여 파일 포인터 독립성 확보 (file_page 사용)
                struct file_page *src_aux = uninit->aux; // 이전의 vm_load_arg 역할
                struct file_page *dst_aux = NULL;

                dst_aux = (struct file_page *)calloc(1, sizeof(struct file_page));
                if (dst_aux == NULL) goto fail;

                // file_page 내용을 복사
                memcpy (dst_aux, src_aux, sizeof(struct file_page));
   
                // ★ 독립적인 파일 포인터 할당
                dst_aux->file = file_reopen(src_aux->file); 
                if (dst_aux->file == NULL) {
                    free (dst_aux);
                    goto fail;
                }

                aux = dst_aux;
                aux_copied = true;
            }
            // VM_ANON UNINIT은 aux가 NULL이므로 기존 aux를 그대로 사용합니다.

            /* 자식 SPT에 부모와 똑같은 UNINIT 페이지 생성 */
            if (!vm_alloc_page_with_initializer (
                    uninit->type, 
                    upage, 
                    writable,
                    uninit->init, 
                    aux)) // aux는 독립된 파일 포인터 또는 NULL
            {
                if (aux_copied) {
                    // 실패 시 파일 포인터 및 aux 메모리 정리
                    file_close(((struct file_page *)aux)->file); // file_page 타입으로 캐스팅
                    free (aux);
                }
                goto fail;
            }
            
            // 💡 UNINIT 페이지는 Lazy Loading이므로 vm_claim_page를 호출하지 않습니다.

            continue;
        } 
        
        /* 2. 🗃️ ANON 페이지 (이미 로드됨) 처리 (Deep Copy) */
        // ... (VM_ANON 페이지 처리는 변경 없음) ...
        else {
            // VM_ANON 페이지 또는 로드된 VM_FILE 페이지를 Deep Copy합니다.
            
            // 1. 자식 SPT에 페이지 항목을 생성
            if (!vm_alloc_page (src_type, upage, writable)) {
                goto fail;
            }

            struct page *dst_page = spt_find_page (dst, upage);
            if (dst_page == NULL) {
                goto fail; 
            }

            // 2. 페이지에 프레임 할당 및 매핑 (Claim)
            struct frame *dst_frame = vm_get_frame();
            if (dst_frame == NULL) {
                goto fail;
            }
            dst_page->frame = dst_frame;
            dst_frame->page = dst_page;

            // b. 자식의 PML4에 매핑 
            if (!pml4_set_page(thread_current()->pml4, dst_page->va, dst_frame->kva, dst_page->writable)) {
                vm_free_frame(dst_frame); // 정리
                goto fail;
            }

            // c. 부모 페이지가 실제 프레임을 가졌는지 확인
            struct frame *src_frame = src_page->frame;
            if (src_frame == NULL) {
                // 부모가 Swapped Out된 경우: Claim 실패 처리 후 정리 (혹은 continue 처리)
                pml4_clear_page(thread_current()->pml4, dst_page->va);
                vm_free_frame(dst_frame);
                goto fail; 
            }

            // 4. 부모 페이지의 내용(kva 물리프레임)을 자식 페이지로 복사 (Deep Copy)
            memcpy (dst_frame->kva, src_frame->kva, PGSIZE);
            continue;
        }
    }

    return true;

fail:
    supplemental_page_table_kill (dst);
    return false;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
if (spt == NULL)
		return;

	hash_clear(&spt->pages, page_vm_destroy);
	// free(spt->pages.buckets);
}

static unsigned
page_hash (const struct hash_elem *e, void *aux) {
    const struct page *p = hash_entry(e, struct page, hash_elem);
    /* 해시함수로 가상주소를 사용 */
    return hash_bytes(&p->va, sizeof p->va);
}

/* page_hash로 버킷 위치는 알았지만, 충돌 때문에 여러 페이지가 묶여있을 수 있으므로, 
이 함수를 사용해 "이 페이지가 내가 찾던 그 VA를 가진 페이지가 맞는지" 최종적으로 확인 */
static bool
page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    const struct page *pa = hash_entry(a, struct page, hash_elem);
    const struct page *pb = hash_entry(b, struct page, hash_elem);
	//a가 크면 참 : 1 반환, b가 크면 거짓 : 0 반환
    return pa->va < pb->va;
}

static void
page_vm_destroy (struct hash_elem *e, void *aux) {
    struct page *page = hash_entry (e, struct page, hash_elem);

    if (page->operations->type == VM_UNINIT) {
        struct uninit_page *uninit = &page->uninit;
        
        if (VM_TYPE (uninit->type) == VM_FILE && uninit->aux != NULL) {
            
            // aux 포인터를 file_page 구조체로 캐스팅하여 파일 자원에 접근
            struct file_page *f_page = (struct file_page *)uninit->aux; // 이전의 vm_load_arg 역할
            
            // 1. 파일 자원을 닫습니다 (파일 포인터 누수 방지).
            if (f_page->file != NULL) {
                file_close(f_page->file);
            }
            
            // 2. aux 구조체 메모리 해제.
            free (uninit->aux); 
            
            // 3. 이중 해제 방지를 위해 포인터를 NULL로 설정합니다.
            uninit->aux = NULL; 
        }
    }

    // 페이지 구조체 자체와 타입별 자원 정리 (vm_destroy + free)
    vm_dealloc_page (page); 
}
/* Free the frame. */
void
vm_free_frame (struct frame *frame) {
    if (frame == NULL)
        return;

    // 1. 프레임 테이블 접근 동기화 (락 획득)
    // frame_table은 전역으로 접근되므로 반드시 락을 사용해야 합니다.
    lock_acquire(&frame_table_lock);
    list_remove(&frame->elem);
    lock_release(&frame_table_lock);

    // 4. 물리 페이지(PAGES) 해제
    // frame->kva에 연결된 물리 페이지를 시스템에 반환합니다.
    palloc_free_page (frame->kva);

    // 5. frame 구조체 자체 메모리 해제
    // struct frame 구조체 메모리를 해제합니다.
    free (frame);
}

/*
 * 폴트 주소 addr과 스택 포인터 rsp를 사용하여
 * 해당 접근이 유효한 스택 확장 시도인지 확인합니다.
 */
static bool
is_valid_stack_access (void *addr, void *rsp) {
    // 1. 주소는 스택의 최대 경계(8MB)를 넘어서는 안 됩니다.
    if (addr < STACK_LIMIT) {
        return false;
    }

    return true;
}

/*
 * Increases the stack size by allocating one or more anonymous pages so that addr is no longer a faulted address.
 * Limits the stack size to 1MB at maximum.
 */
static bool
vm_stack_growth (void *addr) {
    void *stack_bottom = pg_round_down(addr);
    
    // 1. 최대 스택 한도 검사
    if (stack_bottom < STACK_LIMIT) {
        return false;
    }
    
    // 2. 새 스택 페이지 (VM_ANON 타입, 쓰기 가능) 할당
    // VM_MARKER_0 (== VM_WRITABLE)을 사용하여 쓰기 가능 플래그를 설정합니다.
    if (!vm_alloc_page_with_initializer(VM_ANON | VM_MARKER_0, stack_bottom, true, NULL, NULL)) {
        return false;
    }
    
    // 3. 페이지 클레임 (물리 메모리 할당 및 매핑)
    if (!vm_claim_page(stack_bottom)) {
        // 클레임 실패 시, 할당된 SPT 항목을 정리해야 합니다.
        struct page *page_to_kill = spt_find_page(&thread_current()->spt, stack_bottom);
        if (page_to_kill) {
            spt_remove_page(&thread_current()->spt, page_to_kill);
        }
        return false;
    }
    
    return true;
}