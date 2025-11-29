/* anon.c: 디스크 이미지에 묶이지 않은 페이지(익명 페이지)의 구현체. */

#include "vm/vm.h"
#include "devices/disk.h"

/* 아래 줄은 수정하지 않는다. */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* 이 구조체는 수정하지 않는다. */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* 익명 페이지용 데이터를 초기화한다. */
void
vm_anon_init (void) {
	/* TODO: swap_disk를 설정한다. */
	swap_disk = NULL;
}

/* 파일 매핑을 초기화한다. */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* 핸들러를 설정한다. */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* 스왑 디스크에서 데이터를 읽어 페이지를 스왑 인한다. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
}

/* 스왑 디스크에 데이터를 써서 페이지를 스왑 아웃한다. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* 익명 페이지를 파괴한다. PAGE 자체는 호출자가 해제한다. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
