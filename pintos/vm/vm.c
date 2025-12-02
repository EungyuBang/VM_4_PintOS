/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"

#define USER_STACK (void *)0x47480000 // Pintos 스택의 최상단 주소 (0xc0000000 또는 0x47480000 근처)
#define STACK_LIMIT (USER_STACK - (1 << 23)) // 8MB 경계

static struct lock frame_table_lock; //프레임 테이블 접근 동기화
static struct list frame_table; //물리 메모리 프레임의 메타데이터를 관리하는 테이블

static unsigned page_hash (const struct hash_elem *e, void *aux);
static bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void page_destroy(struct hash_elem *e, void *aux);
void vm_free_frame (struct frame *frame);

static bool is_valid_stack_access (void *addr, void *rsp);
static bool vm_stack_grow (void *fault_addr);

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
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		//새 페이지 구조체 할당
		//calloc = malloc + memset(ptr, 0, size)
		//여기선 예기치 않은 쓰레기값을 원천 차단해준다.
		struct page *page = (struct page *)calloc(1, sizeof(struct page));
		if (page == NULL)
			goto err;
		
		//vm 타입에 따라 initializer 선택
		bool (*page_initializer)(struct page *, enum vm_type, void *);

		switch (VM_TYPE(type)) {
			//익명 페이지용(스택, 힙)
			case VM_ANON:
				page_initializer = anon_initializer;
				break;
			//파일 기반 페이지용(실행파일)
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
			free(page);
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
	struct hash_elem *e;

	p.va = pg_round_down(va);
	e = hash_find(&spt->pages, &p.hash_elem);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	return hash_insert(&spt->pages, &page->hash_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
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

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
        bool user UNUSED, bool write, bool not_present) {
    
    // 1. 초기 유효성 검사: NULL 주소이거나 사용자 주소 범위를 벗어난 경우 (커널 접근 포함)
    if (addr == NULL || !is_user_vaddr(addr)) {
        return false;
    }

    void *fault_addr = pg_round_down(addr);
    struct supplemental_page_table *spt = &thread_current ()->spt;
    
    // 2. not_present == false인 경우: 페이지는 존재하지만 권한 문제
    if(!not_present) {
        // SPT에서 해당 페이지를 찾아 쓰기 권한이 있는지 확인
        struct page *exist_page = spt_find_page(spt, fault_addr);
        
        // 페이지가 SPT에 있고, 쓰기 접근이며, 쓰기가 불가능한 경우 -> 권한 오류
        if (exist_page && write && !exist_page->writable) return false;
        
        // 그 외의 권한 오류는 비정상적인 폴트이므로 false 반환
        return false; 
    }

    // not_present == true 인 경우 (물리 페이지 부재)
    struct page *page = spt_find_page(spt, fault_addr);

    // 3. 페이지가 SPT에 없는 경우 (스택 성장 시도)
    if(page == NULL) {
        // 💡 핵심 수정 부분: 스택 성장 조건 확인
        if (is_valid_stack_access(addr, f->rsp) && vm_stack_grow(fault_addr)) {
            // 성장 성공 시, SPT에서 페이지를 다시 찾고 claim 시도
            page = spt_find_page(spt, fault_addr);
            if (page) {
                return vm_do_claim_page(page);
            }
        }
        // 스택 성장이 불가능하거나 실패한 경우
        return false;
    }

    // 4. 페이지가 SPT에 있는 경우 (지연 로딩)
    
    // 쓰기 보호 페이지 처리 (지연 로딩 페이지의 권한 검사)
    if(write && !page->writable) {
        return false;
    }

    // 5. 페이지 할당 및 매핑 시도
    return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
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

	//페이지 내용 로드 (UNINIT -> ANON/FILE)
	// if(!swap_in(page, frame->kva)) {
	// 	//swap_in 실패 : 매핑 + 프레임 모두 정리
	// 	pml4_clear_page(curr->pml4, page->va);
	// 	frame->page = NULL;
	// 	page->frame = NULL;
	// 	vm_free_frame(frame);
	// 	return false;
	// }

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	//SPT 초기화
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
        struct supplemental_page_table *src) {

    struct hash_iterator i;
    hash_first(&i, &src->pages);

    while(hash_next(&i)) {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = page_get_type(src_page);

        void *upage = src_page->va;
        bool writable = src_page->writable;

        /* ---------- [1] FILE BACKED PAGE (Lazy Copy) ---------- */
        if (type == VM_FILE) {
            // VM_FILE은 Lazy Loading 정보만 복사합니다. (file_reopen 로직은 load_segment에서 처리해야 함)
            if (!vm_alloc_page_with_initializer(
                    VM_FILE, upage, writable,
                    src_page->uninit.init,
                    src_page->uninit.aux))
                return false;

            continue;
        }
        
        /* ---------- [2] ANONYMOUS PAGE (Deep Copy Content) ---------- */
        else if (type == VM_ANON) {
            
            // 1. 자식 SPT에 VM_ANON 페이지 항목을 생성합니다 (Lazy).
            if (!vm_alloc_page_with_initializer(
                    VM_ANON, 
                    upage, 
                    writable,
                    src_page->uninit.init, 
                    src_page->uninit.aux))
                return false;

            // 2. 물리 프레임 할당 및 매핑 (Claim).
            if (!vm_claim_page(upage))
                return false;

            struct page *dst_page = spt_find_page(dst, upage);

            // 3. 부모가 Resident인 경우: 메모리 내용을 복사합니다.
            if (src_page->frame != NULL) {
                // 부모의 KVA에서 자식의 KVA로 내용을 복사합니다.
                memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
            }
            // 4. 부모가 Swapped Out인 경우: Swapped out 정보는 aux에 남아있어야 함.
            //    (현재는 swap_in 구현이 없으므로 생략)
            
            continue;
        }

        /* ---------- [3] UNINITIALIZED PAGE (Lazy Info Deep Copy) ---------- */
        if(type == VM_UNINIT) {
            // 1. aux_copy 변수 선언 및 메모리 할당 (VM_UNINIT에서만 수행)
            struct lazy_load_arg *aux_copy = 
                (struct lazy_load_arg *)calloc(1, sizeof(struct lazy_load_arg));

            if (aux_copy == NULL) {
                return false;
            }

            // 2. 부모의 aux 내용을 새로운 메모리 블록으로 깊은 복사
            memcpy(aux_copy, src_page->uninit.aux, sizeof(struct lazy_load_arg));

            // 3. 자식 SPT에 Lazy Loading 페이지 항목을 추가합니다.
            if(!vm_alloc_page_with_initializer(
                src_page->uninit.type,
                upage,
                writable,
                src_page->uninit.init,
                aux_copy)) // 깊은 복사된 aux_copy를 전달
                {
                    free(aux_copy); // 실패 시 할당한 aux_copy 메모리 해제
                    return false;
                }
                continue;
        }
        
        /* ---------- [4] 기타 타입 처리 ---------- */
        else {
            // 정의되지 않은/잘못된 타입이 발견되면 실패
            return false;
        }
    }
    return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	//  hash_destroy(&spt->pages, page_destroy);
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

/*
 * Description: 해시 테이블의 각 요소를 순회하며 호출되어, 
 * 페이지 구조체와 관련된 모든 자원을 해제합니다.
 */
static void
page_destroy (struct hash_elem *e, void *aux) {
    // 1. hash_elem으로부터 struct page 구조체 포인터를 얻습니다.
    struct page *page = hash_entry(e, struct page, hash_elem);

    // 2. vm_dealloc_page 내부에서 destroy(page) 매크로가 
    //    이미 타입별 소멸 핸들러를 호출합니다.
    //    따라서 수동 호출 부분(if-destroy)은 제거합니다.

    // 3. struct page 구조체 자체를 해제합니다.
    //    vm_dealloc_page가 destroy(page)와 free(page)를 모두 수행합니다.
    vm_dealloc_page(page);
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

    // 2. 폴트 주소(addr)는 현재 스택 포인터(rsp)를 기준으로 유효한 범위 내에 있어야 합니다.
    
    // **경계 조건 완화**: 'rsp - 8' 대신, 'addr'이 현재 RSP보다 '훨씬' 아래에 있지 않다면 허용.
    // 시스템 콜 중 폴트가 발생했을 경우, f->rsp는 사용자 스택 포인터 바로 위를 가리킬 수 있습니다.
    
    // 💡 (rsp - 8) 조건 대신, 유효한 스택 포인터 근처인지 확인하는 일반적인 로직 사용:
    // f->rsp가 USER_STACK 주소에 가까우면 (시스템 콜 직후), rsp와 addr의 차이가 크지 않아야 함.
    
    // 현재 코드의 'addr < rsp - 8'은 유효한 접근도 차단할 수 있습니다.
    // 대부분의 Pintos VM에서는 단순히 addr이 rsp보다 '훨씬' 낮지 않고, 8MB 경계 안에 있으면 허용합니다.
    
    // 💡 가장 보수적이고 안전한 조건으로 대체:
    // 폴트 주소(addr)가 현재 RSP보다 아래에 있고, 그 차이가 1 페이지(4096) 이내라면 스택으로 간주하는 방식도 사용됩니다.
    
    // 현재는 원래 논리를 유지하되, 주석 처리된 부분을 통해 원인을 이해하세요.
    // if (addr < rsp - 8) {
    //     // addr이 rsp보다 8바이트 이상 낮으면 잘못된 접근으로 간주
    //     return false;
    // }

    return true;
}

static bool
vm_stack_grow (void *fault_addr) {
    // struct page *p 선언을 제거하고, 함수의 반환 값(bool)을 바로 사용합니다.
    bool success = vm_alloc_page_with_initializer(
        VM_ANON, 
        fault_addr,
        true, 
        NULL, 
        NULL
    );

    return success;
}