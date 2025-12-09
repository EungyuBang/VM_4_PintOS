/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "include/lib/stdio.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static void do_munmap_range (void *start_addr, void *end_addr);

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

bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page_info = (struct file_page *)page->uninit.aux;
    struct file_page *file_page = &page->file;

    // aux 정보를 page->file로 복사
    *file_page = *file_page_info;

    if (VM_IS_WRITABLE(type)) { 
        file_page->writable = true;
    } else {
        file_page->writable = false;
    }
    
    return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
    struct file_page *file_page = &page->file;

    lock_acquire(&filesys_lock);
    off_t read_count = file_read_at(file_page->file, kva, file_page->page_read_bytes, file_page->offset);
    lock_release(&filesys_lock);

    // ⚠️ 파일 끝이 아닐 경우, 요청한 바이트 수만큼 정확히 읽었는지 확인
    if (read_count != (off_t)file_page->page_read_bytes) {
        // 파일 읽기 실패 (혹은 부분 읽기 시도가 있었다면)
        return false;
    }

    memset((uint8_t *)kva + file_page->page_read_bytes, 0, file_page->zero_bytes);
    
    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
    struct file_page *file_page = &page->file;
    struct thread *curr = thread_current();
    
    // 페이지가 프레임을 가지고 있고, 더티 상태인지 확인
    if (page->frame == NULL || !pml4_is_dirty(curr->pml4, page->va)) {
        // 프레임이 없거나 더티하지 않으면 스왑 아웃할 필요가 없습니다.
        return true; 
    }

    // 1. 파일에 내용을 씁니다.
    // file_write_at(파일, 물리 주소, 읽은 바이트 수, 파일 오프셋)
    off_t written = file_write_at(file_page->file, page->frame->kva, 
                                  file_page->page_read_bytes, file_page->offset);

    // 2. PML4에서 더티 비트를 제거하고, 페이지를 clean 상태로 표시
    pml4_set_dirty(curr->pml4, page->va, false);

    // 3. 페이지와 프레임 연결 해제 (프레임은 축출 로직에서 재활용)
    page->frame->page = NULL; 
    page->frame = NULL;

    // TODO: 페이지를 SWAPPED 상태로 표시 (스왑 테이블 구현 시)

    return written == (off_t)file_page->page_read_bytes;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
    struct frame *frame = page->frame; 
    struct thread *curr = thread_current(); // 현재 스레드 정보 사용

    /** Project 3-Memory Mapped Files */
    // 1. dirty 상태인 경우 파일에 내용을 씁니다.
    if (frame && pml4_is_dirty(curr->pml4, page->va)) {
        lock_acquire(&filesys_lock); 
        file_write_at(file_page->file, frame->kva, file_page->page_read_bytes, file_page->offset);
        lock_release(&filesys_lock); 
    }
    
    // 2. PML4에서 매핑 제거 및 프레임 해제
    if (frame) {
        pml4_clear_page(curr->pml4, page->va);
        page->frame = NULL; 
        vm_free_frame(frame); 
    }
}

/* Do the mmap */
void 
*vm_mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
    if (!addr || pg_round_down(addr) != addr || is_kernel_vaddr(addr) || is_kernel_vaddr(addr + length))
        return NULL;

    if (offset != pg_round_down(offset) || offset % PGSIZE != 0)
        return NULL;

    if (spt_find_page(&thread_current()->spt, addr))
        return NULL;

	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
        return NULL;
    }

	for (void *va = addr; va < addr + length; va += PGSIZE) {
        if (spt_find_page(&thread_current()->spt, va)) {
            return NULL;
        }
    }

    struct file *file = process_get_file(fd);

	if (file == NULL)
        return NULL;

    if (file_length(file) == 0 || (long)length <= 0)
        return NULL;

    return do_mmap(addr, length, writable, file, offset);
}

/* file.c의 do_munmap 함수 수정 */

void
do_munmap (void *addr) {
    struct thread *curr = thread_current();
    struct page *page;
    struct file *mfile_to_close = NULL; 

    lock_acquire(&filesys_lock);

    // 1. 첫 페이지를 찾아 mfile 포인터 확보 (mmap 매핑의 시작점으로 가정)
    page = spt_find_page(&curr->spt, addr);
    if (page) {
        if (page->operations->type == VM_FILE) {
             mfile_to_close = page->file.file;
        } else if (page->operations->type == VM_UNINIT && VM_TYPE(page->uninit.type) == VM_FILE) {
             // UNINIT 페이지일 경우, aux에서 mfile 포인터를 가져옵니다.
             // [수정] vm_load_arg 대신 file_page 구조체로 캐스팅
             struct file_page *aux = (struct file_page *)page->uninit.aux;
             if (aux != NULL) {
                 mfile_to_close = aux->file;
             }
        }
    }
    
    // 2. 페이지 정리 루프: SPT에서 제거하며 정리
    while ((page = spt_find_page(&curr->spt, addr))) {
        spt_remove_page(&curr->spt, page); 

        addr += PGSIZE;
    }
    
    // 3. 파일 닫기 (이 매핑의 끝을 표시)
    if (mfile_to_close) {
        file_close(mfile_to_close); 
    }

    lock_release(&filesys_lock);
}
/* file.c의 do_mmap 함수 수정 */

void *
do_mmap (void *addr, size_t length, int writable,
        struct file *file, off_t offset) {
            
    // 1. 파일 시스템 락 획득 및 파일 포인터 독립성 확보
    lock_acquire(&filesys_lock);
    struct file *mfile = file_reopen(file);
    if (mfile == NULL) {
        lock_release(&filesys_lock);
        return NULL;
    }
    
    void *ori_addr = addr;
    
    size_t file_left = file_length(mfile) - offset; 
    size_t total_read_bytes = (length < file_left) ? length : file_left;
    size_t total_zero_bytes = length - total_read_bytes;
    
    size_t current_read_bytes = total_read_bytes;
    size_t current_zero_bytes = total_zero_bytes;
    
    // 유효성 검사 (생략)
    ASSERT((total_read_bytes + total_zero_bytes) % PGSIZE == 0 || length == 0);
    ASSERT(pg_ofs(addr) == 0);
    ASSERT(offset % PGSIZE == 0);

    // 2. 페이지 단위로 SPT 항목 생성
    struct file_page *aux;
    while (current_read_bytes > 0 || current_zero_bytes > 0) {
        size_t page_read_bytes = current_read_bytes < PGSIZE ? current_read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes; 
        
        // aux 구조체 할당
        aux = (struct file_page *)calloc(1, sizeof(struct file_page));
        if (!aux)
            goto err;

        // aux 구조체에 Lazy Loading 정보 저장 (file_page 멤버 이름 사용)
        aux->file = mfile;
        aux->offset = offset; 
        aux->page_read_bytes = page_read_bytes; 
        aux->zero_bytes = page_zero_bytes;
        aux->writable = writable; 

        // SPT에 UNINIT VM_FILE 페이지 항목 등록
        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, aux)) {
            goto err;
        }

        // 다음 페이지로 이동 및 카운터 업데이트
        current_read_bytes -= page_read_bytes;
        current_zero_bytes -= page_zero_bytes;
        addr += PGSIZE;
        offset += page_read_bytes;
    }
    
    lock_release(&filesys_lock);
    return ori_addr;

err:
    do_munmap_range(ori_addr, addr); 

    if (aux != NULL) {
        if (addr == ori_addr) { 
             // SPT에 아무것도 삽입되지 않고 바로 실패한 경우:
             file_close(mfile); 
        }

        // aux 메모리 해제
        free(aux);         
    }

    lock_release(&filesys_lock);
    
    return NULL;
}

static void
do_munmap_range (void *start_addr, void *end_addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    void *curr_addr = start_addr;

    while (curr_addr < end_addr) {
        struct page *page = spt_find_page(spt, curr_addr);
        if (page) {
            spt_remove_page(spt, page); // spt_remove_page가 destroy + free를 호출함
        }
        curr_addr += PGSIZE;
    }
}