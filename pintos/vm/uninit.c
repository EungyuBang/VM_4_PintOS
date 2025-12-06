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
#include "userprog/process.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize, // swap_in 함수 포인터가 uninit_initialize 를 가리킴
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void
uninit_new (struct page *page, void *va, vm_initializer *init, enum vm_type type, void *aux, bool (*initializer)(struct page *, enum vm_type, void *)) 
{
	ASSERT (page != NULL);

	*page = (struct page) {
		.operations = &uninit_ops, // 페이지의 operation을 uninit_ops 로 설정한다
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init, // type : file -> lazy_load_segment or type : anon -> NULL
			.type = type, // type : VM_FILE or tpye : VM_ANON
			.aux = aux, // type : file -> lazy_load_info , type : anon -> NULL
			.page_initializer = initializer, // type : file -> file_backed_initializer or type : anon -> anon_initializer
		}
	};
}

/* Initalize the page on first fault */
// 11주차 VM_UNINIT 페이지의 첫 페이지 폴트 시 실행된다. , swap-in 에서 uninit-initialize 를 호출하여 실제 페이지를 로드
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	vm_initializer *init = uninit->init; // type : file -> init -> lazy_load_segment 함수 or type : anon -> init -> NULL
	void *aux = uninit->aux; // type : file -> aux -> lazy_load_info 구조체 or type : anon -> aux -> NULL

	/* TODO: You may need to fix this function. */
	// uninit -> page_initializer (anon_initializer or file_backed_initializer 가 담겨 있음)
	// type : file -> file_backed_initializer (page, VM_FILE, kva) && (lazy_laod_segment) ? lazy_load_segment(page, aux) : true
	// type : anon -> anon_initializer (page, VM_ANON, kva) && (NULL ? NULl : true)
	return uninit->page_initializer (page, uninit->type, kva) && (init ? init (page, aux) : true);
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
}

// static void uninit_destroy (struct page *page) {
//   struct uninit_page *uninit = &page->uninit;
//   struct lazy_load_info *aux = (struct lazy_load_info *) uninit->aux;
    
//   if (aux != NULL) {
//     if (aux->file != NULL) {
//       file_close(aux->file); // 
//     }
//    free(aux);
//   }
// }
