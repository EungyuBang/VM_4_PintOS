#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "lib/string.h"
#ifdef VM
#include "vm/vm.h"
#endif


struct fork_struct {
	struct thread *parent;
	struct intr_frame parent_if;
	bool fork_success;
	struct semaphore fork_sema;
};

// static struct semaphore temporary;
static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
extern struct lock filesys_lock;

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *cur_thread = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
// filename 은 'programname args ~' 이런식
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	// fn_copy = 'programname args ~'
	strlcpy (fn_copy, file_name, PGSIZE);

	// file_name 파싱 하는 부분 'programname args' -> 'programname' 됨
	char *ptr;
	strtok_r(file_name, " ", &ptr);

	/* Create a new thread to execute FILE_NAME. */
	// 프로그램을 실행할 자식 쓰레드를 하나 만들고 , 그 쓰레드는 바로 initd 실행 (fn_copy를 인자로 받아서 -> fn_copy에는 programname args 다 들어있음)
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
	// 초기화 하고
	process_init ();
	// 여기서 process_exec 실행 -> 자기 자신(쓰레드) 를 사용자 프로그램으로 변환
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
/* Clone current thread to new thread.*/
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	struct thread *parent_thread = thread_current();


	struct fork_struct *fork_struct = malloc(sizeof(struct fork_struct));
	if(fork_struct == NULL) {
		return TID_ERROR;
	}

	// fork_struct 에 자식에게 넘길 부모의 현재 상태 저장
	fork_struct->parent = parent_thread;
	memcpy(&fork_struct->parent_if, if_, sizeof(struct intr_frame));
	sema_init(&fork_struct->fork_sema, 0);
	fork_struct->fork_success = false;

	// 이후 자식 만들고 부모 상태 저장된 구조체 넘기고 
	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, fork_struct);
	// 자식의 리턴값이 TID_ERROR 면 구조체 free 후 오류 반환
	if(tid == TID_ERROR) {
		free(fork_struct);
		return TID_ERROR;
	}
	// 여기서 sleep
	sema_down(&fork_struct->fork_sema);

	if(!fork_struct->fork_success) {
		free(fork_struct);
		return TID_ERROR;
	}

	free(fork_struct);
	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* userprog/process.c */

static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current ();
    struct thread *parent = (struct thread *) aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. 커널 영역 주소라면 복사할 필요 없음 (그대로 리턴) */
    if (is_kernel_vaddr(va)) {
        return true;
    }

    /* 2. 부모의 페이지 테이블에서 해당 가상주소(va)의 물리 주소를 가져옴 */
    parent_page = pml4_get_page (parent->pml4, va);
    if (parent_page == NULL) {
        return false; 
    }

    /* 3. 자식을 위한 새 페이지(PAL_USER) 할당 */
    newpage = palloc_get_page (PAL_USER); 
    if (newpage == NULL) {
        return false; // 메모리 부족
    }

    /* 4. 내용 복사 (Deep Copy) */
    // 부모 페이지 내용을 자식 페이지로 그대로 복사
    memcpy(newpage, parent_page, PGSIZE);

    /* 5. 쓰기 권한 확인 */
    writable = is_writable(pte);

    /* 6. 자식의 페이지 테이블에 매핑 */
    if (!pml4_set_page (current->pml4, va, newpage, writable)) {
        /* 매핑 실패 시 할당받은 페이지 해제 */
        palloc_free_page (newpage);
        return false;
    }

    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
// 인자로 부모값 가진 포크 구조체 넘어옴 
__do_fork (void *aux) {
	// 부모의 정보를 가진 fork_struct를 aux 로 받아서 parent_data 로 
	struct fork_struct *parent_data = aux;
	struct thread *parent = parent_data->parent;
	// 현재 쓰레드의 주체는 자식 쓰레드
	struct thread *child = thread_current();
		
	bool succ = true;
	// 자식이 사용할 인터럽트 프레임
	struct intr_frame if_;

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	/* 1. Read the cpu context to local stack. */
	// 1. 인터럽트 프레임 복제
	memcpy(&if_, &parent_data->parent_if, sizeof(struct intr_frame));
	// 포크된 자식의 리턴값은 0
	if_.R.rax = 0;

	/* 2. Duplicate PT (2. pml4 복제) */
	child->pml4 = pml4_create();
	if (child->pml4 == NULL) {
		succ = false;
		goto error;
	}
	// 새 주소 공간 활성화
	process_activate (child);
#ifdef VM
	supplemental_page_table_init (&child->spt);
	if (!supplemental_page_table_copy (&child->spt, &parent->spt)) {
		printf ("[fork] spt copy failed (parent=%s tid=%d)\n",
				parent->name, parent->tid);
		goto error;
	}
#else
// 부모의 pml4 를 처음부터 끝까지 훑으면서, 유효한 페이지가 나올 때마다 duplicate_pte 함수 실행
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	// 3. FD 도 복제
	for(int i = 2 ; i < FDT_LIMIT ; i++) {
		struct file *file = parent->fd_table[i];
		if(file != NULL) {
			child->fd_table[i] = file_duplicate(file);
		}
	}

	// 10주차 rox
	// 부모가 현재 실행중인 파일이 있다면
	if (parent->running_file != NULL) {
		// 자식의 실행중인 파일에도 복사
    child->running_file = file_duplicate(parent->running_file);
		// 자식의 실행중인 파일도 deny_write 상태 유지 !
    file_deny_write(child->running_file);
	}

	// 유저 모드로 전환전, 포크 성공 유무 저장
	parent_data->fork_success = true;
	// 부모 깨우기
	sema_up(&parent_data->fork_sema);

	/* Finally, switch to the newly created process. */
	// 자식은 유저모드로
	if (succ)
		do_iret (&if_);
error:
	parent_data->fork_success = false;
	sema_up(&parent_data->fork_sema);
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
  // f_name은 "program_name args..." 형태의 '명령어 전체' 문자열.
	// 새로 실행할 파일의 이름임 
  // char *file_name = f_name;
	char *file_name = palloc_get_page(PAL_ZERO);
	if(file_name == NULL) {
		return -1;
	}
	strlcpy(file_name, f_name, PGSIZE);
	palloc_free_page(f_name);
  bool success;

	struct thread *cur_thread = thread_current();
	
  if (cur_thread->running_file != NULL) {
      lock_acquire(&filesys_lock);
			// 다른 파일로 변경 전, 부모와 같이 참조하고 있는 파일 닫아줌
      file_close(cur_thread->running_file);
      lock_release(&filesys_lock);
      cur_thread->running_file = NULL;
  }
  /* 1. 유저 모드 진입을 위한 '임시' CPU 레지스터(intr_frame)를 설정. */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG;
  _if.cs = SEL_UCSEG;
  _if.eflags = FLAG_IF | FLAG_MBS; // 인터럽트 활성화

  /* 2. 현재 컨텍스트(메모리 공간, pml4)를 정리(파괴)하여
   * 새 유저 프로세스로 '변신'할 준비를 함. */
  process_cleanup ();

  /* 3. load() 함수를 호출하여 새 프로그램을 메모리에 적재. */
  success = load (file_name, &_if);

  /* 4. f_name은 process_create_initd에서 할당(palloc)한 복사본이므로,
   * 로드가 끝났으니 해당 메모리 페이지를 해제. */
  palloc_free_page (file_name);
  if (!success)
    return -1; // 로드 실패 (예: 파일 없음, 메모리 부족 등)

  /* 5. do_iret()을 호출하여 유저 모드로 전환.
   * CPU 레지스터가 _if에 설정된 값(rip, rsp 등)으로 갱신되며,
   * 유저 프로그램의 진입점(rip)에서 실행을 시작.
   * 이 함수는 커널로 돌아오지 않음. */
  do_iret (&_if);
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
// 10주차 부모가 자식 실행 기다려야 함.
// 부모가 init.c 에서 자식의 tid 들고 이 함수로 옴 
int
process_wait (tid_t child_tid UNUSED) {
	// 현재 쓰레드의 주체는 부모 쓰레드
	struct thread *parent = thread_current();
	struct list_elem *e;
	struct thread *search_child = NULL;

	// 부모의 child_list 순회하면서 자식 찾기
	for(e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e)) {
		struct thread *t = list_entry(e, struct thread, child_elem) ;
		if(t ->tid == child_tid) {
			search_child = t;
			break;
		}
	}

	if(search_child == NULL) {
		return -1 ;
	}

	// 두번 wait 방지
	lock_acquire(&filesys_lock);
	if(search_child->waited){
		lock_release(&filesys_lock);
		return -1;
	}
	search_child->waited = true;
	lock_release(&filesys_lock);
	
	// 부모는 자식의 개인 세마포어를 기다리면서 sleep
	sema_down(&search_child->wait_sema);
	
	// 깨어난뒤 -> 자식이 exit_status에 저장해둔 종료 코드 읽음
	int status = search_child->exit_status;
	// 부모 child_list에 꽂아둔 chile_elem 삭제
	list_remove(&search_child->child_elem);

	// 부모가 일어난 뒤, 자식에게 죽어도 된다는 신호 주기
	sema_up(&search_child->exit_sema);

	return status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	// 현재 쓰레드의 주체는 자식 쓰레드
	struct thread *cur_thread = thread_current ();

#ifdef VM
	while(!list_empty(&cur_thread->mmap_list)) {
		struct mmap_desc *desc = list_entry(list_front(&cur_thread->mmap_list), struct mmap_desc, elem);
		do_munmap((void *)desc->addr);
	}
#endif
	// 📌 수정 부분
	// 쓰레드 죽기 전에, 파일 디스크립터 정리
	 if(cur_thread->fd_table != NULL) {
		// lock_acquire(&filesys_lock);
		bool lock_held = lock_held_by_current_thread(&filesys_lock);

		if(!lock_held) lock_acquire(&filesys_lock);
		// 반복문으로 해제하는 이유 -> 해당 쓰레드가 열었던 모든 파일을 닫아야 하기 때문에
		for(int fd= 2; fd < FDT_LIMIT; fd++) {
			if(cur_thread->fd_table[fd] != NULL) {
				file_close(cur_thread->fd_table[fd]);
				cur_thread->fd_table[fd] = NULL;
			}
		}
		// lock_release(&filesys_lock);
		if(!lock_held) lock_release(&filesys_lock);
		palloc_free_page(cur_thread->fd_table);
		cur_thread->fd_table = NULL;
	 }
	
	// 📌 수정 부분
	// 10주차 rox
	 if (cur_thread->running_file != NULL) {
			bool lock_held = lock_held_by_current_thread(&filesys_lock);
      if (!lock_held) lock_acquire(&filesys_lock);  
      file_close(cur_thread->running_file);
      if (!lock_held) lock_release(&filesys_lock);  
      cur_thread->running_file = NULL;
    } 
	
	// 부모가 죽기 전 자식 탐색 -> 부모가 먼저 죽는 경우
	// 부팅 쓰레드는 여기를 오지 않지만, 부팅 쓰레드를 제외하고, 부모 자식의 관계가 있을 수 있어서 exit시 자식 탐색 후 다 깨워줌
	 struct list_elem *e = list_begin(&cur_thread->child_list);
	 while(e != list_end(&cur_thread->child_list)) {
		struct thread *child = list_entry(e, struct thread , child_elem);
		e = list_next(e);

		// 부모 죽을 거니까 NULL
		child->parent = NULL;

		// 대기중인 자식 다 풀어줌
		sema_up(&child->exit_sema);

		list_remove(&child->child_elem);
	 }


	 // 자식이 죽기전 부모가 있다면 -> 자식이 먼저 죽는 경우
	 if(cur_thread->parent != NULL) {
		sema_up(&cur_thread->wait_sema); // 부모 깨우기
		sema_down(&cur_thread->exit_sema); // 부모가 처리할 때까지 대기 -> 이후 깨어나면 밑에 process_cleanup 만나서 즉사 
	 }

	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

// 로드 함수에서 file_name (cmd_line) 넘기면 스택에 밀어넣는 부분
bool
arg_load_stack(char *cmdline, struct intr_frame *if_) {
	// 성공 실패 반환
	bool success = false;

	char *token, *save_ptr;
	int argc = 0;
	char *argv[64]; // 최대 64개의 인자를 처리한다고 가정

	// 1. 커맨드 라인 파싱
	for (token = strtok_r(cmdline, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
		argv[argc++] = token;
	}

	// 2. 인자 문자열들을 스택에 역순으로 Push
	for (int i = argc - 1; i >= 0; i--) {
		int len = strlen(argv[i]);
		// 인자들의 각 바이트 수만큼 스택 증가(증가니까 - , + NULL 생각!)
		if_->rsp -= (len + 1); // 널 종결 문자 포함
		memcpy((void *)if_->rsp, argv[i], len + 1); // arvg[i]에 있는 데이터 스택에 넣고
		argv[i] = (char *)if_->rsp; // 배열 해당 자리엔 그 데이터 주소 넣기 
	}
	// 3. 스택 포인터를 8바이트로 정렬
	// 포인터 공간만 만들고 초기화 x -> 어차피 안씀 (아래에서 실제 데이터 접근할땐 주소로 뛰니까)
	while(if_->rsp % 8 != 0) 
		if_->rsp--; 

	// 4. argv 포인터(문자열 주소)들을 스택에 Push
	// argv[argc]에 해당하는 널 포인터 sentinel 삽입
	if_->rsp -= 8;
	memset((void *)if_->rsp, 0, sizeof(char *));

	// 인자들의 주소를 역순으로 삽입
	for (int i = argc - 1; i >= 0; i--) {
		// 삽입되니 스택의 최상단 주소 8씩 감소 (8씩 증가)
		if_->rsp -= 8;
		memcpy((void *)if_->rsp, &argv[i], sizeof(char *));
	}

	// 5. main(argc, argv)를 위한 레지스터 설정
	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp;

	// 6. 가짜 반환 주소 Push
	if_->rsp -= 8;
	memset((void *)if_->rsp, 0, sizeof(void *));

	success = true;
	return success;
 }


/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
// 유저가 실행을 요청한 프로그램을 하드 디스크에서 찾아서 메모리에 적재(load) 하는 단계
/* Loads an ELF executable from the file system into the current process's memory.
 * 
 * file_name: 실행할 유저 프로그램의 파일 이름
 * if_:       유저 프로그램이 시작될 때의 레지스터 상태를 저장하는 intr_frame
 */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();   // 현재 스레드 (실행할 프로세스)
	struct ELF ehdr;                        // ELF 헤더 구조체
	struct file *file = NULL;               // 실행 파일 포인터
	off_t file_ofs;                         // 파일 오프셋
	bool success = false;                   // 성공 여부
	int i;

	char *cmd = palloc_get_page(0);
	if(cmd == NULL) {
		return false;
	}
	strlcpy(cmd, file_name, PGSIZE);

	char *save_ptr;
	char *program_name = strtok_r(cmd, " ", &save_ptr);
	if(program_name == NULL) {
		palloc_free_page(cmd);
		return false;
	}

	/* 1️⃣ 페이지 테이블 생성 및 활성화 */
	t->pml4 = pml4_create ();               // 새 pml4(페이지 테이블) 생성
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());   // 새 페이지 테이블 활성화

	/* 2️⃣ 실행 파일 열기 */
	file = filesys_open (program_name);        // 파일 시스템에서 실행 파일 탐색 및 오픈
	if (file == NULL) {
		printf ("load: %s: open failed\n", program_name);
		goto done;
	}

	/* 3️⃣ ELF 헤더 읽고 검증 */
	// 실행 파일이 올바른 ELF 포맷인지 확인
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)   // ELF 매직 넘버 확인
			|| ehdr.e_type != 2                           // 실행 파일 타입
			|| ehdr.e_machine != 0x3E                     // x86-64 아키텍처
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)   // 프로그램 헤더 크기 확인
			|| ehdr.e_phnum > 1024) {                     // 프로그램 헤더 개수 유효성
		printf ("load: %s: error loading executable\n", program_name);
		goto done;
	}

	/* 4️⃣ 프로그램 헤더를 순회하며 세그먼트 로드 */
	file_ofs = ehdr.e_phoff;                 // 프로그램 헤더 오프셋부터 읽기 시작
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		// 파일 범위 검증
		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);          // 해당 프로그램 헤더 위치로 이동

		// 프로그램 헤더 읽기
		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;

		// 세그먼트 타입에 따라 처리
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* 무시 가능한 세그먼트 */
				break;

			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				/* 지원하지 않는 타입 → 실패 처리 */
				goto done;

			case PT_LOAD: {
				/* 로드 가능한 세그먼트 → 메모리에 적재 */
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;  // 쓰기 가능 여부
					uint64_t file_page = phdr.p_offset & ~PGMASK; // 파일 오프셋 페이지 단위
					uint64_t mem_page  = phdr.p_vaddr & ~PGMASK;  // 가상주소 페이지 단위
					uint64_t page_offset = phdr.p_vaddr & PGMASK; // 페이지 내 오프셋
					uint32_t read_bytes, zero_bytes;

					if (phdr.p_filesz > 0) {
						/* 일부는 파일에서 읽고, 나머지는 0으로 채움 (BSS 등) */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
										- read_bytes);
					} else {
						/* 완전히 0으로 채워지는 세그먼트 */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}

					/* 파일에서 메모리로 세그먼트 로드 */
					if (!load_segment (file, file_page, (void *) mem_page, read_bytes, zero_bytes, writable))
						goto done;
				} else
					goto done;
				break;
			}
		}
	}

	/* 5️⃣ 유저 스택 설정 */
	if (!setup_stack (if_))

		goto done;

	/* 6️⃣ 실행 시작 주소 설정 */
	if_->rip = ehdr.e_entry;   // ELF 진입점 (main 함수 시작 주소)

	/* TODO: 인자 전달 구현 (argument passing) */
	// - 프로젝트 2에서 argv, argc 스택에 적재하는 부분 구현 예정
	success = arg_load_stack(file_name, if_);

done:
    /* 1. 로딩 성공 시 처리 */
		// 10주차 rox
    if (success) {
        t->running_file = file; // 스레드 구조체에 저장
        file_deny_write(file);  // 쓰기 방지 설정     
    } 
    /* 2. 로딩 실패 시 처리 */
    else {
        if (file != NULL) {
            file_close(file); // 실패했으니 닫아줌
        }
    }

    palloc_free_page(cmd);
    return success;
}



/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * MOD4: ELF 로딩 지연(lazy_load_segment/load_segment/setup_stack)
 * MOD5: 폴트 처리/스택 성장 훅(vm_try_handle_fault에서 호출) */

/* MOD4: lazy load 시 파일 정보를 전달하기 위한 구조체 */
struct file_load_aux {
	struct file *file;
	off_t offset;
	size_t read_bytes;
	size_t zero_bytes;
	bool writable;
};

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* MOD4: aux에 담긴 파일/오프셋 정보를 이용해 실제 내용을 채운다. */
	struct file_load_aux *info = aux;
	struct file *file = info->file;
	off_t offset = info->offset;
	size_t read_bytes = info->read_bytes;
	size_t zero_bytes = info->zero_bytes;

	/* 파일 페이지 메타 채우기 */
	page->file.file = file;
	page->file.offset = offset;
	page->file.read_bytes = read_bytes;
	page->file.zero_bytes = zero_bytes;
	page->file.writable = info->writable;
	page->writable = info->writable;

	/* 파일에서 읽어오기 */
	file_seek (file, offset);
	if (file_read (file, page->frame->kva, read_bytes) != (int) read_bytes)
		return false;

	/* 나머지는 0으로 채움 */
	memset ((uint8_t *) page->frame->kva + read_bytes, 0, zero_bytes);

	free (info);
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* MOD4: lazy_load_segment에 넘길 파일 정보 구성 */
		struct file_load_aux *aux = malloc (sizeof *aux);
		if (aux == NULL)
			return false;
		aux->file = file;
		aux->offset = ofs;
		aux->read_bytes = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		aux->writable = writable;

		if (!vm_alloc_page_with_initializer (VM_FILE, upage,
					writable, lazy_load_segment, aux)) {
			free (aux);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;

	//한 페이지 공간을 예약할 VA를 정함
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);
    
	/* MOD4: 스택 페이지를 즉시 할당하고 클레임 */
    //UNINIT 페이지 객체를 만들고 SPT에 등록만 함(프레임 없음)
	success = vm_alloc_page (VM_ANON | VM_MARKER_0, stack_bottom, true);
	if (success)
		success = vm_claim_page (stack_bottom);
	if (success)
		if_->rsp = USER_STACK;

	return success;
}
#endif /* VM */
