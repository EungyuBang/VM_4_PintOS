#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;
typedef int mapid_t;

struct mmap_desc {
  mapid_t id;				//고유 매핑 ID
  void *addr;				//매핑 시작 가상 주소
  size_t length;			//요청한 전체 길이(바이트)
  size_t page_cnt;			//길이를 PGSIZE 단위로 나눈 값
  struct file *file;		//매핑과 연결된 파일 객체
  off_t offset;				//파일 안에서 매핑이 시작된 위치
  struct list_elem elem;	//쓰레드의 mmap_list에 이 descriptor를 넣기 위한 리스트 노드
};

struct file_page {
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
