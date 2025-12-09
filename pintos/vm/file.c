#include "vm/vm.h"
#include "threads/mmu.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include <round.h>
#include <string.h>

extern struct lock filesys_lock;

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static bool mmap_lazy_load (struct page *page, void *aux);
static struct mmap_desc *mmap_find_desc (struct thread *t, void *addr);

static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

void
vm_file_init (void) {
}

bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
    page->operations = &file_ops;

    struct file_page *fp = &page->file;
    fp->file = NULL;
    fp->offset = 0;
    fp->read_bytes = 0;
    fp->zero_bytes = 0;
    fp->writable = page->writable;
    return true;
}

static bool
file_backed_swap_in (struct page *page, void *kva) {
    struct file_page *fp = &page->file;

    if (fp->file == NULL)
        return false;

    lock_acquire (&filesys_lock);
    file_seek (fp->file, fp->offset);
    int read = file_read (fp->file, kva, fp->read_bytes);
    lock_release (&filesys_lock);
    if (read != (int) fp->read_bytes)
        return false;
    memset ((uint8_t *) kva + fp->read_bytes, 0, fp->zero_bytes);
    return true;
}

static bool
file_backed_swap_out (struct page *page) {
    struct file_page *fp = &page->file;

    if (pml4_is_dirty (thread_current ()->pml4, page->va)) {
        lock_acquire (&filesys_lock);
        file_seek (fp->file, fp->offset);
        file_write (fp->file, page->frame->kva, fp->read_bytes);
        lock_release (&filesys_lock);
        pml4_set_dirty (thread_current ()->pml4, page->va, false);
    }
    return true;
}

static void
file_backed_destroy (struct page *page) {
    struct file_page *fp = &page->file;

    if (page->frame != NULL) {
        struct thread *curr = thread_current ();
        bool dirty = pml4_is_dirty (curr->pml4, page->va);

        if (dirty && fp->file != NULL && fp->writable && fp->read_bytes > 0) {
            lock_acquire (&filesys_lock);
            file_seek (fp->file, fp->offset);
            file_write (fp->file, page->frame->kva, fp->read_bytes);
            lock_release (&filesys_lock);
            pml4_set_dirty (curr->pml4, page->va, false);
        }

        pml4_clear_page (curr->pml4, page->va);
        page->frame->page = NULL;
        palloc_free_page (page->frame->kva);
        free (page->frame);
        page->frame = NULL;
    }
}

//이 페이지의 어느 위치에서 몇 바이트 읽고 나머지는 0으로 채울지
struct mmap_page_aux {
    struct file *file;
    off_t offset;
    size_t read_bytes;
    size_t zero_bytes;
};


static bool
mmap_lazy_load (struct page *page, void *aux) {
	//페이지마다 만든 aux를 받아옴
    struct mmap_page_aux *info = aux;

	//struct page의 file_page 멤버 채우기
    page->file.file = info->file;
    page->file.offset = info->offset;
    page->file.read_bytes = info->read_bytes;
    page->file.zero_bytes = info->zero_bytes;
    page->file.writable = page->writable;

	//파일에서 실제로 읽을 내용이 있다면 락 찾고 file_seek으로 위치 잡고 file_read로 kva에 데이터를 채움
    if (info->read_bytes > 0) {
        lock_acquire (&filesys_lock);
        file_seek (info->file, info->offset);
        int read = file_read (info->file, page->frame->kva, info->read_bytes);
        lock_release (&filesys_lock);
        if (read != (int) info->read_bytes) {
            free (info);
            return false;
        }
    }
	//페이지의 나머지 공간을 0으로 채워 zero-padding 만족
    memset ((uint8_t *) page->frame->kva + info->read_bytes, 0, info->zero_bytes);
    free (info);
    return true;
}

void *
do_mmap (void *addr, size_t length, int writable,
        struct file *file, off_t offset) {

	//시스콜 외에 내부 경로 호출 가능성 존재
    if (addr == NULL || length == 0 || pg_ofs (addr) != 0 || file == NULL ||
            offset % PGSIZE != 0)
        return NULL;

    struct thread *cur = thread_current ();
    struct supplemental_page_table *spt = &cur->spt;

    if (!is_user_vaddr (addr))
        return NULL;
    uint64_t end_addr = (uint64_t) addr + length;
    if (end_addr < (uint64_t) addr || end_addr == 0)
        return NULL;
    if (!is_user_vaddr ((void *) (end_addr - 1)))
        return NULL;

	
    lock_acquire (&filesys_lock);
    off_t file_len = file_length (file);
    lock_release (&filesys_lock);

	//file_len offset 유효한지
    if (file_len <= 0 || offset < 0 || offset >= file_len)
        return NULL;

	//이미 등록된 페이지가 있는지 확인
	//만약 어느 페이지라도 SPT에 존재한다면 다른 매핑이나 스택/코드와 겹친다는 뜻
    size_t page_cnt = DIV_ROUND_UP (length, PGSIZE);
    for (size_t i = 0; i < page_cnt; i++) {
        void *page_addr = (uint8_t *) addr + i * PGSIZE;
        if (spt_find_page (spt, page_addr) != NULL)
            return NULL;
    }

	//요청한 offset부터 파일 끝까지 남아있는 바이트 수
    size_t file_avail = file_len - offset;

	//매핑 길이가 파일 남은 길이보다 길 수 있으니 실제로 읽을 바이트 수, 나머지는 zeropadding
    size_t read_bytes_left = file_avail < length ? file_avail : length;

	//각 페이지가 읽기 시작할 파일 위치를 추적
    size_t cur_offset = offset;

	//i번째 페이지 정보를 계산하고 mmap_page_aux 구조체에 담음
    for (size_t i = 0; i < page_cnt; i++) {
		//페이지 주소
        void *page_addr = (uint8_t *) addr + i * PGSIZE;

        size_t page_read_bytes = read_bytes_left >= PGSIZE ? PGSIZE : read_bytes_left;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

		//lazy load위한 구조체 할당 및 초기화
        struct mmap_page_aux *info = malloc (sizeof *info);
        if (info == NULL)
            goto fail;
        info->file = file;
        info->offset = cur_offset;
        info->read_bytes = page_read_bytes;
        info->zero_bytes = page_zero_bytes;

		//해당 VA가 처음 접근될 때 실제 파일 데이터를 프레임에 채움
        if (!vm_alloc_page_with_initializer (VM_FILE, page_addr, writable,
                    mmap_lazy_load, info)) {
            free (info);
            goto fail;
        }

		//다음 페이지를 위해 오프셋과 남은 읽기 바이트 수 갱신
        if (page_read_bytes > 0)
            cur_offset += page_read_bytes;
        if (read_bytes_left > page_read_bytes)
            read_bytes_left -= page_read_bytes;
        else
            read_bytes_left = 0;
    }

	//mmap_desc를 만들어 쓰레드의 mmap_list에 저장함
    struct mmap_desc *desc = malloc (sizeof *desc);
    if (desc == NULL)
        goto fail;
    desc->addr = addr;								//mmap이 시작된 가상 주소
    desc->length = length;							//전체 매핑 길이
    desc->page_cnt = page_cnt;						//페이지 수
    desc->file = file;								//이 매핑이 참조하는 file
    desc->offset = offset;							//파일 내에서 매핑이 시작된 위치
    desc->id = cur->next_mapid++;					//고유 매핑 ID
    list_push_back (&cur->mmap_list, &desc->elem);	//쓰레드의 mmap_list에 추가
    return addr;

fail:
    for (size_t i = 0; i < page_cnt; i++) {
        void *page_addr = (uint8_t *) addr + i * PGSIZE;
        struct page *page = spt_find_page (spt, page_addr);
        if (page != NULL)
            spt_remove_page (spt, page);
    }
    return NULL;
}

void
do_munmap (void *addr) {
    struct thread *cur = thread_current ();
    struct mmap_desc *desc = mmap_find_desc (cur, addr);
    if (desc == NULL)
        return;

    for (size_t i = 0; i < desc->page_cnt; i++) {
        void *page_addr = (uint8_t *) desc->addr + i * PGSIZE;
        struct page *page = spt_find_page (&cur->spt, page_addr);
        if (page == NULL)
            continue;
        spt_remove_page (&cur->spt, page);
    }

    list_remove (&desc->elem);
    lock_acquire (&filesys_lock);
    file_close (desc->file);
    lock_release (&filesys_lock);
    free (desc);
}

//시작 주소가 addr인 매핑을 찾음
static struct mmap_desc *
mmap_find_desc (struct thread *t, void *addr) {
    struct list_elem *e;
    for (e = list_begin (&t->mmap_list); e != list_end (&t->mmap_list);
            e = list_next (e)) {
        struct mmap_desc *desc = list_entry (e, struct mmap_desc, elem);
        if (desc->addr == addr)
            return desc;
    }
    return NULL;
}
