#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"  // power_off() 함수를 위해 추가
#include "threads/palloc.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "lib/string.h"


void syscall_entry(void);
void syscall_handler(struct intr_frame *);
struct lock filesys_lock;
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */
#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */
void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);
    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
    lock_init(&filesys_lock);
}

/* 유저 메모리 검증 함수들 -> 유저 프로그램에서 잘못된 접근을 했을 때, 사용자 프로그램만 다운시키고 OS는 유지되게 해주는 함수들 */
/* 단일 주소가 유효한 유저 주소인지 검사 */
void
check_address(void *addr) {
    struct thread *cur_thread = thread_current();

    // 1. NULL이거나, 2. 커널 영역 주소일 때
    if (addr == NULL || !is_user_vaddr(addr)) {
        exit_with_status(-1);
    }

    // 매핑되지 않은 주소일 때 (pml4_get_page가 NULL 반환)
    if (pml4_get_page(cur_thread->pml4, addr) == NULL) {
        exit_with_status(-1);
    }
}

/* 버퍼 전체가 유효한지 검사 */
void
check_buffer(void *buffer, size_t size) {
    if (size == 0) return;
    
    check_address(buffer);
    check_address(buffer + size - 1);
}

/* 유저 문자열을 커널 공간으로 안전하게 복사 -> TOCTOU 상황 고려 */
// 반복문 중 게속 주소를 검사하는 이유는 문자열이 두 페이지에 걸쳐서 존재할 수 있기때문.
char *
copy_user_string(const char *ustr) {
    // 1. 시작 주소부터 check_address로 검사
    check_address(ustr); 
    
    char *kstr = palloc_get_page(0);
    if (kstr == NULL) {
        exit_with_status(-1); 
    }
    
    int i;
    for (i = 0; i < PGSIZE; i++) {
        // 2. 루프를 돌며 다음 주소도 check_address로 검사
        check_address(ustr + i);
        
        // 3. '검사 후' 안전하게 읽기
        kstr[i] = ustr[i];
        
        if (kstr[i] == '\0') {
            return kstr; // 성공!
        }
    }
    
    // PGSIZE까지 \0가 안나옴 (문자열이 너무 김)
    palloc_free_page(kstr);
    exit_with_status(-1);
}

/* 종료 코드와 함께 프로세스 종료 */
void
exit_with_status(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

/* The main system call interface */
/* userprog/syscall.c */

/* The main system call interface */
void
syscall_handler (struct intr_frame *f)
{
  /* 시스템 콜 번호는 rax 레지스터에 저장됨 */
  int syscall_num = f->R.rax;
  switch (syscall_num)
  {
    case SYS_HALT:    /* Halt the operating system. */
      sys_halt(f);
      break;
    case SYS_EXIT:    /* Terminate this process. */
      sys_exit(f);
      break;
    case SYS_FORK:    /* Clone current process. */
      sys_fork(f);
      break;
    case SYS_EXEC:    /* Switch current process. */
      sys_exec(f);
      break;
    case SYS_WAIT:    /* Wait for a child process to die. */
      sys_wait(f);
      break;
    case SYS_CREATE:  /* Create a file. */
      sys_create(f);
      break;
    case SYS_REMOVE:  /* Delete a file. */
      sys_remove(f);
      break;
    case SYS_OPEN:    /* Open a file. */
      sys_open(f);
      break;
    case SYS_FILESIZE:/* Obtain a file's size. */
      sys_filesize(f);
      break;
    case SYS_READ:    /* Read from a file. */
      sys_read(f);
      break;
    case SYS_WRITE:   /* Write to a file. */
      sys_write(f);
      break;
    case SYS_SEEK:    /* Change position in a file. */
      sys_seek(f);
      break;
    case SYS_TELL:    /* Report current position in a file. */
      sys_tell(f);
      break;
    case SYS_CLOSE:   /* Close a file. */
      sys_close(f);
      break;
    default:
      /* 미구현 시스템 콜 */
      printf("Unimplemented system call: %d\n", syscall_num);
      thread_exit();
      break;
  }
}



void sys_halt(struct intr_frame *f)
{
	// 핀토스 종료
	power_off();
}

void sys_exit(struct intr_frame *f)
{
	struct thread *cur_thread = thread_current();
  int status = f->R.rdi;  // 첫 번째 인자
	// 현재 쓰레드(자식)의 상태 저장 -> 이후에 부모 쓰레드가 확인함
	cur_thread->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}



void sys_fork(struct intr_frame *f) 
{
  const char *name = (const char *)f->R.rdi;
  check_address(name);
  
  f->R.rax = process_fork(name, f);
}



void
sys_exec(struct intr_frame *f)
{
    const char *u_cmd = (const char *)f->R.rdi;

    char *k_cmd = copy_user_string(u_cmd);
    if (k_cmd == NULL) {
        exit_with_status(-1); 
        return;
    }

    int ret = process_exec(k_cmd);

    /* process_exec가 리턴했다는 건 load 실패를 의미함 (-1) */
    if (ret == -1) {
        exit_with_status(-1); 
        return;
    }
    // 성공 시 절대 여기로 오지 않음
    NOT_REACHED();
}


void sys_wait (struct intr_frame *f) 
{
  // 1. 첫 번째 인자(rdi)에서 기다릴 'child_tid'를 읽어옴.
  tid_t child_tid = (tid_t)f->R.rdi;
  
  // 2. wait 함수를 호출.
  int status = process_wait(child_tid); 
  
  // 3. 자식의 종료 코드(status)를 반환값 레지스터(rax)에 저장.
  f->R.rax = status;
}

void sys_create(struct intr_frame *f) 
{
    const char *file = (const char *)f->R.rdi;
    unsigned initial_size = (unsigned)f->R.rsi;
    
    check_address(file);

    // filesys_create 호출 
    lock_acquire(&filesys_lock);
    f->R.rax = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
}

void sys_remove(struct intr_frame *f) 
{
    const char *file = (const char *)f->R.rdi;
    check_address(file);
    
    lock_acquire(&filesys_lock);
    f->R.rax = filesys_remove(file);
    lock_release(&filesys_lock);
}

void sys_open(struct intr_frame *f) 
{
  const char *file_name = (const char *)f->R.rdi;

  check_address(file_name);

  char *k_filename = copy_user_string(file_name);
  if(k_filename == NULL) {
    f->R.rax = -1;
    return;
  }
  struct thread *cur_thread = thread_current();

  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(k_filename);
  lock_release(&filesys_lock);

  palloc_free_page(k_filename);

  if(file == NULL) {
    f->R.rax = -1;
    return;
  }

  int fd = -1;
  // 각 프로세스의 fd 테이블 순회하면서 NULL 이면 해당 fd 배정
  for(int i = 2 ; i < FDT_LIMIT ; i++) {
    if(cur_thread->fd_table[i] == NULL) {
      fd = i;
      cur_thread->fd_table[i] = file;
      break;
    }
  }
  // 반목문을 다 돌았는데도 -1? -> 테이블이 꽉 차서 배정받지 못한 경우 -> 파일 닫아줘야 함
  if(fd == -1) {
    lock_acquire(&filesys_lock);
    file_close(file);
    lock_release(&filesys_lock);
    f->R.rax = -1;
    return;
  }

  f->R.rax = fd;
}

void sys_filesize(struct intr_frame *f) 
{
  int fd = f->R.rdi;
  struct thread *cur_thread = thread_current();
  
  if(fd < 2 || fd >= FDT_LIMIT || cur_thread->fd_table[fd] == NULL) {
    f->R.rax = -1;
    return;
  }
  struct file *file = cur_thread -> fd_table[fd];

  lock_acquire(&filesys_lock);
  off_t size = file_length(file);
  lock_release(&filesys_lock);

  f->R.rax = size;
}

void sys_read(struct intr_frame *f) 
{
  int fd = f->R.rdi;
  void *buffer = (void *)f->R.rsi;
  unsigned size = f->R.rdx;

  // if(size == 0) {
  //   f->R.rax = 0;
  //   return;
  // }

  check_buffer(buffer, size);
  // fd=0 -> 표준입력 : 키보드 입력
  if(fd == 0)
  {
    // 사이즈 만큼 반복
    for(unsigned i = 0; i < size; i++) {
      // 키보드 입력 한 글자 가져와서 버퍼에 담기
      ((uint8_t *)buffer)[i] = input_getc();
   }
   // read 함수의 리턴값은 실제로 읽은 바이트 수여야 하므로 size 반환
   f->R.rax = size;
   return;
  }
  // fd=1 -> 표준 출력 -> 여기는 read 시스템 콜
  if(fd == 1) 
  {
    f->R.rax = -1;
    return;
  }

  struct thread *cur_thread = thread_current();
  if(fd < 0 || fd >= FDT_LIMIT || cur_thread->fd_table[fd] == NULL)
  {
    f->R.rax = -1;
    return;
  }

  struct file *file = cur_thread->fd_table[fd];

  lock_acquire(&filesys_lock);
  int ret = file_read(file, buffer, size);
  lock_release(&filesys_lock);

  f->R.rax = ret;
}

void sys_write(struct intr_frame *f)
{
	// write 콜도 표준 규약에 따라 인자를 받는다
  int fd = f->R.rdi;                      // 1번 인자 : rdi -> fd (파일 디스크립터)
  const void *buffer = (void *)f->R.rsi;  // 2번 인자 : buffer (출력할 문자의 주소)
  unsigned size = f->R.rdx;               // 3번 인자 : size (출력할 문자의 길이)

  // if(size == 0) {
  //   f->R.rax = 0;
  //   return;
  // }

	check_buffer(buffer, size);							// 사용자가 넘겨준 buffer 주소를 읽어도 되는지 확인

  struct thread *cur_thread = thread_current();
  
  if(fd == 0) 
  {
    f->R.rax = -1;
    return;
  }

  if(fd < 0 || fd >= FDT_LIMIT || cur_thread->fd_table[fd] == NULL)
  {
    f->R.rax = -1;
    return;
  }

  if (fd == 1)
  {                          
  	putbuf(buffer, size);  // 버퍼를 콘솔에 출력
    f->R.rax = size;       
    return;
  }

  // 분기처리 완료 -> 파일 쓰기 처리
  struct file *file = cur_thread->fd_table[fd];
  lock_acquire(&filesys_lock);
  int ret = file_write(file, buffer, size);
  lock_release(&filesys_lock);

  f->R.rax = ret;
}

// 해당 fd의 파일 오프셋을 position 으로 이동
void sys_seek(struct intr_frame *f) 
{
  int fd = f->R.rdi;
  unsigned position = f->R.rsi;
  
  struct thread *cur_thread = thread_current();
  if (fd < 2 || fd >= FDT_LIMIT || cur_thread->fd_table[fd] == NULL) {
    return;
  }
  struct file *file = cur_thread->fd_table[fd];

  lock_acquire(&filesys_lock);
  file_seek(file, position);
  lock_release(&filesys_lock);
}

// 해당 fd 파일의 오프셋을 반환
void sys_tell(struct intr_frame *f) 
{
  int fd = f->R.rdi;

  struct thread *cur_thread = thread_current();
  if(fd < 2 || fd >= FDT_LIMIT || cur_thread->fd_table[fd]== NULL) {
    f->R.rax = -1;
    return;
  }
  struct file *file = cur_thread->fd_table[fd];

  lock_acquire(&filesys_lock);
  int ret = file_tell(file);
  lock_release(&filesys_lock);

  f->R.rax = ret;
}

void sys_close(struct intr_frame *f) 
{
  int fd = f->R.rdi;

  struct thread *cur_thread = thread_current();

  if(fd < 2 || fd >= FDT_LIMIT || cur_thread->fd_table[fd] == NULL) {
    return;
  }

  struct file *file = cur_thread->fd_table[fd];

  cur_thread->fd_table[fd] = NULL;

  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
}
