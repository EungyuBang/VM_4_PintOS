#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
	/*MOD7*/
	/* 파일 매핑 정보를 유지할 필드를 정의한다. */
	struct file *file;		//매핑 대상 파일
	off_t offset;			//파일 내 시작 오프셋
	size_t read_bytes;		//이 페이지에서 읽을 바이트 수
	size_t zero_bytes;		//나머지 0으로 채울 바이트 수
	bool writable;			//쓰기 가능 여부
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
