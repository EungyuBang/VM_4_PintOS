/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* Initalize the page on first fault */
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* TODO: You may need to fix this function. */
	return uninit->page_initializer (page, uninit->type, kva) &&
		(init ? init (page, aux) : true);
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy (struct page *page) {
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* TODO: Fill this function.
	 * TODO: If you don't have anything to do, just return. */

	// 1. 페이지의 실제 VM 타입이 VM_ANON인 경우 처리
    // VM_UNINIT 페이지는 내부적으로 VM_ANON, VM_FILE 등의 타입을 가집니다.
    // uninit.type이 실제 타입입니다.
    enum vm_type type = uninit->type;

	// 현재는 VM_ANON 페이지의 지연 로딩 정보만 처리
    if (VM_TYPE(type) == VM_ANON) {
        // VM_ANON 페이지의 경우, aux는 주로 fork 과정에서 할당된
        // Swapped out 정보나 특정 초기화 인자를 담고 있습니다.
        // 현재 Pintos의 VM_ANON 구현에서는 aux가 동적 할당된 경우가 많으므로 해제합니다.
        
        // aux가 NULL이 아닌 경우에만 해제 (malloc 또는 calloc으로 할당된 경우)
        if (uninit->aux != NULL) {
            free(uninit->aux);
            uninit->aux = NULL; // 해제 후 NULL로 설정
        }
    }
}
