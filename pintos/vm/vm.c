/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "userprog/process.h"

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


/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
// 11주차 여기서 SPT에 aux - 메타데이터 등록하는 로직 들어간다
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
				goto err;
		}

		uninit_new(p, upage, init, type, aux, page_initializer);

		p->writable = writable;
		/* TODO: Insert the page into the spt. */
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
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page page;
	/* TODO: Fill this function. */
	page.va = pg_round_down(va);

	struct hash_elem *e = hash_find(&spt->pages, &page.hash_elem);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
// 새로 만들어진 페이지 spt에 넣기
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
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
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
// 여기서 유효성 검사 + SPT 탐색 + 처리 해줘야 함 (rsp 부근이면 스택 확장까지) -> 이 조건에 다 안 걸린다 -> segmentation fault
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	if(addr == NULL) return false;
	if(is_kernel_vaddr(addr)) return false;
	// present_bit 가 1 인데 fault -> 권한 문제
	if(!not_present) return false;

	/* TODO: Your code goes here */
	page = spt_find_page(spt, addr);

	if(page == NULL) {
		// todo : stack growth
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
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 페이지 테이블에 VA -> PA 매핑 등록
	struct thread *cur_thread = thread_current();
	if(!pml4_set_page(cur_thread->pml4, page->va, frame->kva, page->writable)) {
		free(frame);
		palloc_free_page(frame->kva);
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

bool
supplemental_page_table_copy (struct supplemental_page_table *dst, struct supplemental_page_table *src) 
{    }

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
}
