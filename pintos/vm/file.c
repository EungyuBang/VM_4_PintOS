/* file.c: Implementation of memory backed file object (mmaped object).
 * MOD3: 파일 페이지 초기화
 * MOD7: 파일 페이지 스왑 구현 */

#include "vm/vm.h"
#include "threads/mmu.h"
#include <string.h>

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	/* MOD6: 기본 메타 초기화. 실제 값은 lazy loader(aux)에서 채운다. */
	struct file_page *fp = &page->file;
	fp->file = NULL;
	fp->offset = 0;
	fp->read_bytes = 0;
	fp->zero_bytes = 0;
	fp->writable = page->writable;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *fp = &page->file;

	if (fp->file == NULL)
		return false;

	file_seek (fp->file, fp->offset);
	int read = file_read (fp->file, kva, fp->read_bytes);
	if (read != (int) fp->read_bytes)
		return false;
	memset ((uint8_t *) kva + fp->read_bytes, 0, fp->zero_bytes);
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *fp = &page->file;

	/* 더티면 파일에 반영, 아니면 버림 */
	if (pml4_is_dirty (thread_current ()->pml4, page->va)) {
		file_seek (fp->file, fp->offset);
		file_write (fp->file, page->frame->kva, fp->read_bytes);
		pml4_set_dirty (thread_current ()->pml4, page->va, false);
	}
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
