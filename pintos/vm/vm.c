/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include "include/lib/string.h"
#include "filesys/file.h"

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

// 가상 주소 해시 값으로 변경해주는 함수
unsigned va_to_hash (const struct hash_elem *p_, void *aux) 
{
	const struct page *p = hash_entry(p_ , struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

// 가상 주소 비교 함수
bool comp_va (const struct hash_elem *a_, const struct hash_elem *b_, void *aux) 
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	
	return a->va < b->va;
}

static void spt_destroy(struct hash_elem *e, void *aux) 
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	destroy(page);
	free(page);
}

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
// 11주차 여기서 SPT에 aux - 메타데이터 등록하는 로직 들어간다
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) 
{
	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	// spt_find_page == NULL -> spt에 페이지 넣을 공간 있다는 뜻
	if (spt_find_page (spt, upage) == NULL) {
		struct page *p = (struct page*)malloc(sizeof(struct page));
		if(p == NULL) goto err;

		bool (*page_initializer)(struct page *, enum vm_type, void *);

		switch (VM_TYPE(type)) {
			case VM_ANON :
				page_initializer = anon_initializer;
				break;
			case VM_FILE :
				page_initializer = file_backed_initializer;
				break;
			default :
				free(p);				
				goto err;
		}

		// 페이지 타입을 VM_UNINIT 으로 설정 + init(lazy_load_segment) 함수 등록 + 타입에 따른 page_initializer 등록
		uninit_new(p, upage, init, type, aux, page_initializer);

		p->writable = writable;
		/* TODO: Insert the page into the spt. */
		// spt에 page 구조체 등록
		if(!spt_insert_page(spt, p)) {
			free(p);
			goto err;
		}
		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
// spt 순회하면서 가상주소 찾기
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) 
{
	struct page page;
	/* TODO: Fill this function. */
	page.va = pg_round_down(va);

	struct hash_elem *e = hash_find(&spt->pages, &page.hash_elem);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
// 새로 만들어진 페이지 spt에 넣기
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) 
{
	// int succ = false;
	/* TODO: Fill this function. */

	return hash_insert(&spt->pages, &page->hash_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
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
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER);

	if(kva == NULL) {
		// 할당 받을 메모리가 부족한거임
		// todo : victim 정해서 swap 실행
		PANIC("todo : swap out");
	}

	frame = (struct frame *)malloc(sizeof(struct frame));
	if(frame == NULL) {
		palloc_free_page(kva);
		PANIC("frame allocation failed");
	}
	frame->kva = kva;
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void *stack_bottm = pg_round_down(addr);

	vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottm, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
// 여기서 유효성 검사 + SPT 탐색 + 처리 해줘야 함 (rsp 부근이면 스택 확장까지) -> 이 조건에 다 안 걸린다 -> segmentation fault
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) 
{
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	if(addr == NULL) return false;
	if(is_kernel_vaddr(addr)) return false;
	// present_bit 가 1 인데 fault -> 권한 문제
	if(!not_present) return false;

	/* TODO: Your code goes here */
	page = spt_find_page(spt, addr);

	// stack_growth -> addr 가
	// 스택 확장 조건 : 1. USER_STACK 아래 2. rsp - 8 까진 허용 3. 스택 최대크기 -> 1MB 이하
	if(page == NULL) {
		void *rsp = user ? f->rsp : thread_current()->rsp;

		const uint64_t STACK_LIMIT = USER_STACK - (1 << 20);

		if(addr >= (void *)STACK_LIMIT && (void *)addr <= USER_STACK && addr >= ((void *)(rsp - 8))) {
			vm_stack_growth(addr);
			page = spt_find_page(spt, addr);
		}
	}

	if(page == NULL) {
		return false;
	}

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
	struct supplemental_page_table *spt = &thread_current()->spt;
	page = spt_find_page(spt, va);

	if(page == NULL) {
		return false;
	}

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
// 11주차 여기서 물리 프레임 연결하고 할당? -> 그럼 여기서 lazy_load + swap 해결?
static bool
vm_do_claim_page (struct page *page) {
	// frame 할당
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 페이지 테이블에 VA -> PA 매핑 등록
	struct thread *cur_thread = thread_current();
	if(!pml4_set_page(cur_thread->pml4, page->va, frame->kva, page->writable)) {
		palloc_free_page(frame->kva);
		free(frame);
		return false;
	}

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
// spt 초기화
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) 
{
	hash_init(&spt->pages, va_to_hash, comp_va, NULL);
}

/* Copy supplemental page table from src to dst */
/* vm/vm.c */

// 부모 -> 자식 복사시 , 페이지의 타입에 따라 나눠야함 UNINIT -> aux 복사 , ANON,LOADED -> 실제 메모리에 있는 data 복사
// src -> 부모 (출발지) , dst = 자식 (도착지)
bool
supplemental_page_table_copy (struct supplemental_page_table *dst, struct supplemental_page_table *src) 
{
	struct hash_iterator i; 
	// 부모 해시 테이블의 첫 번째 요소부터 탐색 시작 
	hash_first(&i, &src->pages);

	while(hash_next(&i)) {
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);		

		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		bool writable = src_page->writable;

		if(type == VM_UNINIT) {
			vm_initializer *init = src_page->uninit.init; // lazy_load_segment 함수 
			void *aux = src_page->uninit.aux; // lazy_load_info 구조체

			struct lazy_load_info *new_aux = malloc(sizeof(struct lazy_load_info));
			if(new_aux == NULL) {
				return false;
			} 
			// 부모 aux 자식에게 그대로 복사하고
			memcpy(new_aux, aux, sizeof(struct lazy_load_info));

			// 자식이 실제 실행될 때 실행될 정보 spt에 담아놓기
			if(!vm_alloc_page_with_initializer(src_page->uninit.type, upage, writable, init, new_aux)) {
				free(new_aux);
				return false;
			}
		}
		else {
			// 부모랑 똑같은 type, upage, writable 상태로 spt에 페이지 만들고
			if(!vm_alloc_page(type, upage, writable)) {
				return false;
			}
			
			// 새로운 물리 메모리 할당
			if(!vm_claim_page(upage)) {
				return false;
			}

			// 자식 페이지 주소 spt에서 찾아주고
			struct page *dst_page = spt_find_page(dst, upage);

			// 복사 
			memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
	}
	return true;
}


/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
		hash_destroy(&spt->pages, spt_destroy);
}
