/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

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

		//새 페이지 구조체 할당
		//calloc = malloc + memset(ptr, 0, size)
		struct page *page = (struct page *)calloc(sizeof(struct page));
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
//주어진 보충 페이지 테이블에서 va에 해당하는 구조 페이지를 찾습니다. 
//실패하면 NULL을 반환합니다.
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page p;
	struct hash_elem *e;

	p.va = pg_round_down(va);
	e = hash_find(&spt->pages, &p.hash_elem);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
/*
주어진 보충 페이지 테이블에 구조 페이지를 삽입합니다. 
이 함수는 주어진 보충 페이지 테이블에 가상 주소가 존재하지 않는지 확인해야 합니다.
*/
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
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
 //프레임 관리 인터페이스를 구현할 때 더 많은 멤버를 추가
 /*
사용자 풀에서 palloc_get_page를 호출하여 새 물리 페이지를 가져옵니다. 
사용자 풀에서 페이지를 성공적으로 얻으면 프레임을 할당하고 멤버를 초기화한 후 반환합니다.
vm_get_frame을 구현한 후에는 이 기능을 통해 모든 사용자 공간 페이지(PALOC_USER)를 할당해야 합니다.
페이지 할당 실패 시 스왑 아웃을 처리할 필요는 없습니다. 
현재는 이 경우를 PANIC("할 일")로 표시하기만 하면 됩니다.
 */
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

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
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

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
/*
va를 할당할 페이지를 요청합니다. 
먼저 페이지를 받은 다음 해당 페이지와 함께 vm_do_claim_page를 호출해야 합니다.
*/
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
/*
클레임, 즉 물리적 프레임, 페이지를 할당하는 것을 의미합니다. 
먼저 템플릿에서 이미 완료된 vm_get_frame을 호출하여 프레임을 얻습니다.
그런 다음 MMU를 설정해야 합니다. 
즉, 가상 주소에서 페이지 테이블의 물리적 주소로 매핑을 추가합니다. 
반환 값은 작업이 성공했는지 여부를 표시해야 합니다.
*/
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
//보충 페이지 테이블 초기화 : 
//새 프로세스가 시작될 때(userprog/process.c의 initd)와 
//프로세스가 포크될 때 호출됩니다(userprog/process.c의 __do_fork에서).
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	//SPT 초기화
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
