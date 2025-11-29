/* vm.c: 가상 메모리 객체를 위한 일반 인터페이스. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* 각 서브시스템의 초기화 코드를 호출해 가상 메모리 서브시스템을 초기화한다. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* 위쪽 코드는 수정하지 않는다. */
	/* TODO: 여기에 코드를 작성한다. */
}

/* 페이지 타입을 반환한다.
 * 페이지가 초기화된 뒤 어떤 타입이 되는지 알고 싶을 때 유용하다.
 * 이미 전부 구현돼 있다. */
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

/* 보조 함수들 */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
static unsigned page_hash(const struct hash_elem *e, void *aux UNUSED);
static bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);



/*MOD1 키를 해싱할 함수*/

static unsigned
page_hash(const struct hash_elem *e, void *aux UNUSED) {
    const struct page *p = hash_entry(e, struct page, spt_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

/*MOD1 정렬 함수*/
static bool
page_less(const struct hash_elem *a,
          const struct hash_elem *b,
          void *aux UNUSED) {
    const struct page *pa = hash_entry(a, struct page, spt_elem);
    const struct page *pb = hash_entry(b, struct page, spt_elem);
    return pa->va < pb->va;
}

/* 초기화 정보가 있는 지연 페이지 객체를 생성한다.
 * 새 페이지를 만들고 싶다면 직접 만들지 말고 이 함수나 `vm_alloc_page`를 거친다. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* upage가 이미 다른 페이지에 점유돼 있는지 확인한다. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: 페이지를 만들고 VM 타입에 맞는 초기화기를 찾아 uninit_new로
		 * TODO: "미초기화" 페이지를 구성한다. 호출 이후 필요한 필드를 채운다. */

		/* TODO: spt에 페이지를 삽입한다. */
	}
err:
	return false;
}

/* SPT에서 VA를 찾아 페이지를 반환한다. 실패하면 NULL을 돌려준다. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct hash_elem *elem;
	struct page page_tmp;
	void *aligned_va;

	if (spt == NULL || va == NULL)
		return NULL;

	aligned_va = pg_round_down (va);
	page_tmp.va = aligned_va;
	elem = hash_find (&spt->pages, &page_tmp.spt_elem);
	return elem != NULL ? hash_entry (elem, struct page, spt_elem) : NULL;
}

/*MOD1*/
/* 검증 후 페이지를 SPT에 삽입한다. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	if (!spt || !page || !page->va){
		return false;
	}

	/*현재 페이지 주소를 페이지 시작점으로 내림.*/
	page->va = pg_round_down(page->va);	

	/*해시 테이블에 새 항목을 넣음*/
	return hash_insert (&spt->pages, &page->spt_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	/*MOD1 
	해시에서 page가 꽂혀있던 엔트리를 제거
	실제 페이지 메모리는 따로 해제*/
	if(!spt || !page){
		return;
	}
	hash_delete(&spt->pages, &page->spt_elem);
	vm_dealloc_page (page);
}

/* 축출 대상이 될 프레임을 고른다. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: 축출 정책은 자유롭게 정한다. */

	return victim;
}

/* 한 페이지를 축출하고 해당 프레임을 반환한다.
 * 실패하면 NULL을 반환한다. */
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: 희생 프레임을 스왑 아웃하고 축출된 프레임을 반환한다. */

	return NULL;
}

/* palloc()으로 프레임을 얻는다. 만약 가용 페이지가 없다면 하나를 축출해 반환한다.
 * 항상 유효한 주소를 반환해야 하며, 사용자 풀 메모리가 가득 차면 프레임을 축출해
 * 빈 공간을 마련한다. */
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: 이 함수를 완성한다. */

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* 스택을 성장시킨다. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* 쓰기 보호된 페이지에서의 폴트를 처리한다. */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* 성공 시 true를 반환한다. */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: 폴트가 유효한지 검사한다. */
	/* TODO: 필요한 코드를 작성한다. */

	return vm_do_claim_page (page);
}

/* 페이지를 해제한다.
 * 이 함수는 수정하지 않는다. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* 해당 VA에 할당된 페이지를 클레임한다. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: 이 함수를 완성한다. */

	return vm_do_claim_page (page);
}vm_do_c;

/* PAGE를 클레임하고 MMU 설정을 한다. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* 연결 관계를 설정한다. */
	frame->page = page;
	page->frame = frame;

	/* TODO: 페이지의 VA와 프레임의 PA를 매핑하는 PTE를 삽입한다. */

	return swap_in (page, frame->kva);
}

/* MOD1 */
/* 새로운 보조 페이지 테이블을 초기화한다. */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	/* page_hash/page_less: page 안의 va만 보고 해시값을 계산하고 순서를 정하는 함수*/
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* src의 보조 페이지 테이블을 dst로 복사한다. */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* 보조 페이지 테이블이 들고 있는 자원을 해제한다. */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: 스레드가 보유한 모든 supplemental_page_table을 파괴하고
	 * TODO: 수정된 내용을 스토리지로 기록한다. */
}
