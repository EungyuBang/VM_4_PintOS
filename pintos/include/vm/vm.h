#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "lib/kernel/hash.h"
#include "threads/palloc.h"

enum vm_type {
	/* 아직 초기화되지 않은 페이지 */
	VM_UNINIT = 0,
	/* 파일과 연관되지 않은 페이지, 즉 익명 페이지 */
	VM_ANON = 1,
	/* 파일과 연관된 페이지 */
	VM_FILE = 2,
	/* 페이지 캐시가 올라오는 페이지 (project 4에서 사용) */
	VM_PAGE_CACHE = 3,

	/* 상태를 저장하는 비트 플래그 */

	/* 보조 정보를 담는 비트 플래그. int 범위 안이라면 더 추가해도 된다. */
	VM_MARKER_0 = (1 << 3),
	VM_MARKER_1 = (1 << 4),

	/* 이 값을 초과하지 않도록 주의한다. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

/* 페이지를 표현하는 구조체.
 * 부모 클래스 비슷한 형태이며, 자식 클래스로 uninit_page, file_page,
 * anon_page, page cache(project4)가 존재한다.
 * 아래에 미리 정의된 멤버는 삭제/수정하면 안 된다. */
struct page {
	const struct page_operations *operations;
	void *va;              /* 유저 공간 기준 주소 */
	struct frame *frame;   /* 이 페이지를 가리키는 프레임 */
	bool writable; /* MOD1 */

	/* 구현체가 확장해 쓰는 공간 */
	struct hash_elem spt_elem; /* SPT 조회용 해시 테이블 요소 */

	/* 타입별 데이터는 아래 공용체에 묶인다.
	 * 각 함수는 현재 활성화된 공용체를 알아서 판단한다. */
	union {
		struct uninit_page uninit;
		struct anon_page anon;
		struct file_page file;
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
};

/* 프레임을 표현하는 구조체 */
struct frame {
	void *kva;
	struct page *page;
};

/* 페이지 연산 테이블.
 * C에서 인터페이스를 흉내 내기 위한 한 가지 방법이다.
 * 메서드 테이블을 구조체 멤버에 넣어두고 필요할 때 호출한다. */
struct page_operations {
	bool (*swap_in) (struct page *, void *);
	bool (*swap_out) (struct page *);
	void (*destroy) (struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in ((page), v)
#define swap_out(page) (page)->operations->swap_out (page)
#define destroy(page) \
	if ((page)->operations->destroy) (page)->operations->destroy (page)

/* 현재 프로세스의 메모리 공간을 표현한다.
 * 특정 설계를 강제하지 않으니 원하는 방식으로 구현해도 된다. */
/* TODO(vm): 보조 페이지 테이블에 필요한 자료구조를 정의한다. */
struct supplemental_page_table {
	/*TODO 필요할때마다 추가*/
	struct hash pages;
};

#include "threads/thread.h"
void supplemental_page_table_init (struct supplemental_page_table *spt);
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src);
void supplemental_page_table_kill (struct supplemental_page_table *spt);
struct page *spt_find_page (struct supplemental_page_table *spt,
		void *va);
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);
void spt_remove_page (struct supplemental_page_table *spt, struct page *page);

void vm_init (void);
bool vm_try_handle_fault (struct intr_frame *f, void *addr, bool user,
		bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage,
		bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page (struct page *page);
bool vm_claim_page (void *va);
enum vm_type page_get_type (struct page *page);

#endif  /* VM_VM_H */
