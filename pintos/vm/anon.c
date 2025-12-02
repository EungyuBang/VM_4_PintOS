/* anon.c: 디스크 이미지에 묶이지 않은 페이지(익명 페이지)의 구현체.
 * MOD3: 익명 페이지 초기화
 * MOD7: 익명 페이지 스왑/파괴 */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"
#include "threads/mmu.h"
#include <stdlib.h>

/* MOD6 전역 스왑 상태 */
static struct disk *swap_disk;		//스왑용 디스크 핸들
static struct bitmap *swap_bitmap;	//스왑 슬롯 사용 여부 관리 비트맵
static struct lock swap_lock;		//스왑 I/O 보호용 락
static size_t swap_slots;			//스왑 슬롯 개수

/* 아래 줄은 수정하지 않는다. */
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

/* MOD6*/
/* 익명 페이지용 데이터를 초기화한다. */
void
vm_anon_init (void) {
	/*MOD6: 스왑 디스크 및 슬롯/비트맵 초기화 */
	swap_disk = disk_get (1, 1);
	ASSERT (swap_disk != NULL);

	/*슬롯 개수 = 디스크 섹터 수 / (페이지당 섹터 수)*/
	size_t sectors_per_page = PGSIZE / DISK_SECTOR_SIZE;
	swap_slots = disk_size (swap_disk) / sectors_per_page;

	/*슬롯 관리 비트맵 생성*/
	swap_bitmap = bitmap_create (swap_slots);
	ASSERT (swap_bitmap != NULL);
	bitmap_set_all (swap_bitmap, false);
	
	lock_init (&swap_lock);
}

/* 파일 매핑을 초기화한다. */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* 핸들러를 설정한다. */
	page->operations = &anon_ops;

	/* MOD6: 스왑 슬롯 초기화 */
	page->anon.slot = BITMAP_ERROR;
	return true;
}

/* 스왑 디스크에서 데이터를 읽어 페이지를 스왑 인한다. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	if (anon_page->slot == BITMAP_ERROR)
		return false;

	lock_acquire (&swap_lock);
	for (size_t i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
		disk_read (swap_disk, anon_page->slot * (PGSIZE / DISK_SECTOR_SIZE) + i,
				(char *) kva + i * DISK_SECTOR_SIZE);
	}
	bitmap_reset (swap_bitmap, anon_page->slot);
	anon_page->slot = BITMAP_ERROR;
	lock_release (&swap_lock);
	return true;
}

/* 스왑 디스크에 데이터를 써서 페이지를 스왑 아웃한다. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	size_t slot_idx;

	//스왑 비트맵에서 빈 슬롯을 잡아 slot_idx를 기록
	lock_acquire (&swap_lock);
	slot_idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
	lock_release (&swap_lock);

	if (slot_idx == BITMAP_ERROR)
		return false;

	//해당 슬롯 위치에 프레임 내용을 항상 스왑 디스크에 쓴다.
	for (size_t i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++) {
		disk_write (swap_disk, slot_idx * (PGSIZE / DISK_SECTOR_SIZE) + i,
				(char *) page->frame->kva + i * DISK_SECTOR_SIZE);
	}

    //페이지가 이제 스왑 디스크에 있음을 표시한다.
	anon_page->slot = slot_idx;

	//페이지와 연결된 물리 프레임을 해제한다.
	pml4_clear_page (thread_current ()->pml4, page->va);
	page->frame->page = NULL;
	palloc_free_page (page->frame->kva);
	free (page->frame);
	page->frame = NULL;
	return true;
}

/* MOD7: 익명 페이지를 파괴한다. PAGE 자체는 호출자가 해제한다. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if (anon_page->slot != BITMAP_ERROR) {
		lock_acquire (&swap_lock);
		bitmap_reset (swap_bitmap, anon_page->slot);
		lock_release (&swap_lock);
		anon_page->slot = BITMAP_ERROR;
	}
}
