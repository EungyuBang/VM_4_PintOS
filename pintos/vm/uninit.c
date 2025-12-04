/* uninit.c: 미초기화 페이지 구현체.
 *
 * 모든 페이지는 미초기화 상태로 태어난다. 첫 페이지 폴트가 발생하면
 * 핸들러 체인이 uninit_initialize(page->operations.swap_in)를 호출한다.
 * uninit_initialize 함수는 페이지 객체를 초기화해 anon/file/page_cache 등의
 * 구체 페이지 객체로 변환하고, vm_alloc_page_with_initializer에서 전달된
 * 초기화 콜백을 호출한다.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* 이 구조체는 수정하지 않는다. */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* 이 함수는 수정하지 않는다. */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* 아직 프레임이 없음 */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* 첫 폴트 시 페이지를 초기화한다. */
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* page_initialize가 값을 덮어쓸 수 있으니 먼저 꺼낸다. */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* TODO: 필요하다면 이 함수를 수정한다. */
	return uninit->page_initializer (page, uninit->type, kva) &&
		(init ? init (page, aux) : true);
}

/* uninit_page가 들고 있는 자원을 해제한다. 대부분의 페이지가 다른 타입으로
 * 변환되지만, 실행 중 한 번도 참조되지 않아 프로세스 종료 시까지 남아 있는
 * 미초기화 페이지가 있을 수도 있다.
 * PAGE 메모리 자체는 호출자가 해제한다. */
static void
uninit_destroy (struct page *page) {
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* 현재 단계에서는 lazy file aux를 따로 해제하지 않는다.
	   첫 접근 시 lazy_load_segment가 이미 정리하므로 중복 해제를 막는다. */
}
