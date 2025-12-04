/* vm.c: 가상 메모리 객체를 위한 일반 인터페이스.
 * MOD1: 보조 페이지 테이블/페이지 생성
 * MOD2: 프레임/매핑
 * MOD5: 폴트 처리/스택 성장
 * MOD6: SPT 복사/정리
 * MOD7: 스왑/추가 훅(TODO 포함) */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <stdio.h>
#include <string.h>

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
static void spt_destructor (struct hash_elem *e, void *aux UNUSED);

/* lazy load 시 사용한 파일 정보 구조체(process.c와 동일) */
struct file_load_aux {
	struct file *file;
	off_t offset;
	size_t read_bytes;
	size_t zero_bytes;
	bool writable;
};



/* MOD1: SPT 해시 함수 */
/*sturct pagd의 va를 키로 해시값을 계산*/

static unsigned
page_hash(const struct hash_elem *e, void *aux UNUSED) {
    const struct page *p = hash_entry(e, struct page, spt_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

/* MOD1: SPT 정렬 함수 */
/*두 struct page의 va를 비교해 정렬 기준을 정함*/
static bool
page_less(const struct hash_elem *a,
          const struct hash_elem *b,
          void *aux UNUSED) {
    const struct page *pa = hash_entry(a, struct page, spt_elem);
    const struct page *pb = hash_entry(b, struct page, spt_elem);
    return pa->va < pb->va;
}

/* MOD1: 지연 페이지 예약 */
/* 초기화 정보가 있는 지연 페이지 객체를 생성한다.
 * 새 페이지를 만들고 싶다면 직접 만들지 말고 이 함수나 `vm_alloc_page`를 거친다. */
/*type: ANOD/FILE.. upage: VA init: lazy 콜백 aux: 콜백용 데이터*/
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT);
	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* upage가 이미 다른 페이지에 점유돼 있는지 확인한다. */
	upage = pg_round_down(upage);
	if(spt_find_page(spt, upage)) {
		return false;
	}
	//struct page 메타데이터를 malloc 
	struct page *page = malloc(sizeof(struct page));
	if(page == NULL) {
		return false;
	}

	/* 초기화 함수 하나를 담아두는 변수
	익명 페이지면 page_init = anon_initializer
	파일 페이지면 page_init = file_backed_initializer*/
	bool (*page_init)(struct page *, enum vm_type, void *kva) = NULL;
	switch (VM_TYPE(type)) {
		case VM_ANON:
			page_init = anon_initializer;
			break;
		case VM_FILE:
			page_init = file_backed_initializer;
			break;
		default:
			free(page);
			return false;
	}
	
	/* 페이지를 만들고 VM 타입에 맞는 초기화기를 찾아 uninit_new로
	* "미초기화" 페이지를 구성한다. 호출 이후 필요한 필드를 채운다. */
	uninit_new(page, upage, init, type, aux, page_init);
	page->writable = writable;
	/* spt에 페이지를 해시에 삽입한다. */
	if(!spt_insert_page(spt, page)) {
		vm_dealloc_page(page);
		return false;
	}
	return true;
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

/* MOD1: SPT 삽입/삭제 */
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

/* MOD2: 프레임 할당 */
/* palloc()으로 프레임을 얻는다. 만약 가용 페이지가 없다면 하나를 축출해 반환한다.
 * kva와 frame을 일단 연결만 해 둔다. */
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	
	/*user pool에서 물리 페이지, 4kb 사용자 풀 페이지를 받아옴*/
	void *kva = palloc_get_page (PAL_USER);
	
	/*todo 프레임 대체 로직 추가*/
	if(kva == NULL) {
		PANIC("todo");
	}

	/*
	frame은 kva 물리 페이지를 관리하기 위한 메타데이터
	프레임 메타 할당 실패 시 페이지 반환
	*/
	frame = malloc(sizeof(*frame));
	if(frame == NULL) {
		palloc_free_page(kva);
		PANIC("todo");
	}

	/*
	frame->kva: 방금 할당한 실제 메모리의 커널 가상주소
	frame->page: 어느 가상 페이지(struct page)가 이 프레임을 쓰는지 연결
	*/
	frame->kva = kva;
	frame->page = NULL;
	return frame;
}

/* MOD5: 스택을 성장시킨다. */
static void
vm_stack_growth (void *addr) {
	void *stack_bottom = pg_round_down (addr);
	/* 스택 페이지를 바로 할당하고 클레임 */
	if (vm_alloc_page (VM_ANON | VM_MARKER_0, stack_bottom, true))
		vm_claim_page (stack_bottom);
}

/* 쓰기 보호된 페이지에서의 폴트를 처리한다. */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* MOD5: 폴트 처리 */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;

	/* 잘못된 접근이면 실패 */
	if (addr == NULL || is_kernel_vaddr (addr))
		return false;

	/* not-present가 아니고 쓰기 보호라면 처리 */
	if (!not_present)
		return vm_handle_wp (page);

	/* 페이지 조회 */
	page = spt_find_page (spt, addr);
	if (page == NULL) {
		/* 스택 자동 성장 조건: 사용자 스택 포인터 근처인지 확인 */
		void *rsp = (void *) (user ? f->rsp : thread_current ()->tf.rsp);

		//폴트가 난 주소는 rsp-8일 경우 USER_STACK~ rsp 사이가 스택으로 할당된 공간
		if (addr >= rsp - 8 && addr < (void *) USER_STACK) {
			vm_stack_growth (addr);
			page = spt_find_page (spt, addr);
		}
		if (page == NULL)
			return false;
	}

	return vm_do_claim_page (page);
}

/* 페이지를 해제한다.
 * 이 함수는 수정하지 않는다. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* MOD2: VA로 페이지 클레임 */
/* 주어진 VA에 대해 SPT에서 page를 찾아서 있으면 vm_do_claim_page로 넘김 */
bool
vm_claim_page (void *va) {
	struct page *page = spt_find_page (&thread_current ()->spt, va);
	if (page == NULL) {
		return false;
	}
	return vm_do_claim_page (page);
}

/* MOD2: 페이지 클레임 후 매핑/로드 */
/* 프레임 확보, 프레임<->페이지 링크, VA와 kva를 PML4에 매핑, swap_in호출해서 UNINIT이면 타입전환+lazyload, ANON이나 FILE이면 각자 */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* 연결 관계를 설정한다. */
	frame->page = page;
	page->frame = frame;

	/* 페이지의 VA와 프레임의 PA를 매핑하는 PTE를 삽입한다. */
	if(!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
		frame->page = NULL;
		page->frame = NULL;
		palloc_free_page (frame->kva);
		free (frame);
		return false;
	}

	return swap_in (page, frame->kva);
}

/* MOD1: SPT 초기화 */
/* 새로운 보조 페이지 테이블을 초기화한다. */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	/* page_hash/page_less: page 안의 va만 보고 해시값을 계산하고 순서를 정하는 함수*/
	hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* src의 보조 페이지 테이블을 dst로 복사한다. */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct hash_iterator it;
	const char *fail_stage = NULL;
	void *fail_va = NULL;
	enum vm_type fail_type = 0;

	//이터레이터로 초기화한 뒤 
	hash_first (&it, &src->pages);
	//다음 요소가 있을 때까지 반복 (해시의 버킷을 순회)
	while (hash_next (&it)) {
		//hash next로 현재 요소를 얻고 page로 반환
		struct page *src_page = hash_entry (hash_cur (&it), struct page, spt_elem);

		//페이지가 UNINIT인지 확인, lazy페이지이면 프레임이 없으므로 처리 방식이 달라짐
		bool is_uninit = src_page->operations->type == VM_UNINIT;

		//VM_UNINIT이면 실제 타입을 얻음 아니면 그대로 타입을 반환
		enum vm_type type = is_uninit ? VM_TYPE (src_page->uninit.type)
									  : page_get_type (src_page);
		void *va = src_page->va;
		bool writable = src_page->writable;
		
		//디버깅 위한 값
		fail_va = va;
		fail_type = type;

		//UNINIT이라(lazy 상태)면 초기화 정보도 복사
		if (is_uninit) {
			struct uninit_page *uninit = &src_page->uninit;
			void *aux = uninit->aux;
			bool aux_copied = false;

			/* 파일 포인터-오프셋이 들어 있는 구조체라 부모와 공유하면 안됨 */
			/* 부모가 파일 기반(VM_FILE)이고 로딩 정보(aux)가 있을 때*/
			if (VM_TYPE (uninit->type) == VM_FILE && uninit->aux != NULL) {
				//부모의 파일 정보
				struct file_load_aux *src_aux = uninit->aux;
				
				//자식을 위한 파일 로딩 정보를 위한 메모리 할당
				struct file_load_aux *dst_aux = malloc (sizeof *dst_aux);
				if (dst_aux == NULL) {
					fail_stage = "aux alloc";
					goto fail;
				}
				
				//부모의 파일 로딩 정보를 자식으로 복사
				memcpy (dst_aux, src_aux, sizeof *dst_aux);
				
				//앞으로 사용할 aux포인터를 자식의 것으로 변경
				aux = dst_aux;
				aux_copied = true;
			}

			/* 자식에게도 부모와 똑같은 UNINIT 페이지 생성*/
			if (!vm_alloc_page_with_initializer (uninit->type, va, writable,
						uninit->init, aux)) {
				if (aux_copied)
					free (aux);
				fail_stage = "uninit alloc";
				goto fail;
			}
			/* 메모리할당 + 매핑 + swapin */
			if (!vm_claim_page (va)) {
				fail_stage = "uninit claim";
				goto fail;
			}
		} else {
			//자식 SPT에 페이지 할당
			if (!vm_alloc_page (type, va, writable)) {
				fail_stage = "alloc";
				goto fail;
			}

			//페이지에 프레임 할당, 물리 메모리와 매핑 설정
			if (!vm_claim_page (va)) {
				fail_stage = "claim";
				goto fail;
			}

			//자식 SPT에서 방금 만든 페이지 찾아옴 부모 페이지도 실제 프레임 가졌는지 확인
			struct page *dst_page = spt_find_page (dst, va);
			if (dst_page == NULL || src_page->frame == NULL) {
				fail_stage = "find dst/frame";
				goto fail;
			}

			//부모 페이지의 내용(kva 물리프레임)을 자식 페이지로 복사
			memcpy (dst_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
	}

	return true;

fail:
	printf ("[spt_copy] fail va=%p type=%d stage=%s\n",
			fail_va, fail_type, fail_stage ? fail_stage : "unknown");
	supplemental_page_table_kill (dst);
	return false;
}

/* MOD6: SPT 자원 해제 */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	if (spt == NULL)
		return;

	hash_clear (&spt->pages, spt_destructor);
}

static void
spt_destructor (struct hash_elem *e, void *aux UNUSED) {
	struct page *page = hash_entry (e, struct page, spt_elem);

	/* UNINIT의 lazy aux가 남아 있다면 해제 */
	if (page->operations->type == VM_UNINIT) {
		struct uninit_page *uninit = &page->uninit;
		if (VM_TYPE (uninit->type) == VM_FILE && uninit->aux != NULL)
			free (uninit->aux);
	}

	vm_dealloc_page (page);
}
	