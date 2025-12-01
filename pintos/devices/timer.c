#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/list.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* 자고 있는 thread 관리해줄 list (linked list) */
static struct list sleep_list;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
	// 9주차 : 잠자고 있는 쓰레드들 관리할 리스트 초기화 해준다
	list_init(&sleep_list);
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	int64_t t = ticks;
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

// 9주차 alarm-priority - sleep_list에 넣을때 비교하는 헬퍼 함수
static bool
comapare_tick(const struct list_elem *a , const struct list_elem *b, void *aux UNUSED)
{
	const struct thread *ta = list_entry(a, struct thread, elem);
	const struct thread *tb = list_entry(b, struct thread, elem);

	return ta->wakeup_tick < tb->wakeup_tick;
}

// 9주차 구현 - alarm
/* Suspends execution for approximately TICKS timer ticks. */
/* 문제점 : while 문이라서 이미 자고 있는 쓰레드 계속 방문함 (자고 있는애 계속 확인할 필요가 없음 -> 그냥 sleep_list에 넣어놓고 -> 깨면 ready_list에 넣어버리면 안 되나?)*/
/* 로직 생각 
	 1. 우선 들어온 ticks 이 0보다 작거나 같으면 돌릴필요 없죠?
	 2. 그게 아니라면 sleep_list (queue? linkedlist?) 에다가 넣어버리면 되겠죠? -> 넣을 때 정렬? 근데 이건 priority 에서 하는거 아닌가? (우선은 정렬 없이 구현)
	 3. sleep_list에서 깨면 다시 쓰레드 ready_list로 넘겨줘야 함 -> 이거 timer_interrupt 에서
	 4. 꺠는걸 어떻게 확인할건데? -> clock interrupt 마다 sleep_list 확인? -> 이거 timer_interrupt 에서
	 5. 근데 핸들러가 interrupt 처리하는 시간보다 ticks 가 더 빠르면 이거 어케함? -> interrupt 잠시 중단...
*/
void
timer_sleep (int64_t ticks) {
	// 원래 코드
	// int64_t start = timer_ticks ();
	// ASSERT (intr_get_level () == INTR_ON);
	// while (timer_elapsed (start) < ticks)
	// // 자는 동안 다른 쓰레드 돌려줘 
	// 	thread_yield ();
	
	// ticks 0 보다 작아? 종료
	if(ticks <= 0) return;
	// 현재 CPU에서 이 코드를 실행하고 있는 쓰레드
	struct thread *cur_thread = thread_current();
	// old_level 변수는 enum intr_level 타입의 값만 담을 수 있음 -> INTR_ON or INTR_OFF
	enum intr_level old_level;

	// intr_disable() -> 1. CPU의 인터럽트를 끔, 2. 인터럽트를 끄기 직전의 상태를 old_level에 담음 
	old_level = intr_disable();
	// 잠든 쓰레드의 일어나는 조건은 현재 틱 + sleep 시 받은 ticks
	cur_thread->wakeup_tick = timer_ticks() + ticks;
	// 깨는데 남은 시간 제일 적게 남은애 제일 앞으로 
	list_insert_ordered(&sleep_list, &cur_thread->elem, comapare_tick, NULL);
	// 쓰레드 막음 
	thread_block();
	// 인터럽트 꺼지기 직전 상태로 다시 복귀
	intr_set_level (old_level);
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}
// 9주차 alarm
/* Timer interrupt handler. -> clock에 의해서 cpu가 현재 실행중이던 작업을 잠시 멈추고 오는 곳 */
/* 이 함수에서 구현해야 하는 것 
	 인터럽트가 왔을때, 위애서 만든 sleep_list를 순회하면서 잠에서 깬 쓰레드들 ready_list로 옮겨주는 역할 
*/
/* 로직 생각
	 1. sleep_list의 맨 처음 요소 가져온다
	 2. 반복문 시작 (끝이 아닐 때 까지)
	 3. 반복문 돌면서 wakeup_tick 이 현재 tick 보다 작거나 같으면 -> 깨워야 하는 쓰레드 !
	 4. 현재 쓰레드 다음 쓰레드 저장하고 현재 쓰레드 삭제
	 5. 아니라면 다음순회 준비 
*/
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;
	
	// sleep_list 비어있지 않을때까지 순회
	while (!list_empty(&sleep_list)) {
		// sleep_list의 맨 처음 elem 잡아서 now_e에 담고 
		struct list_elem *now_e = list_begin(&sleep_list);
		// 현재 element로 thread 주소 잡기
		struct thread *t = list_entry(now_e, struct thread, elem);
		if(t->wakeup_tick <= ticks) {
			list_pop_front(&sleep_list);
			thread_unblock(t);
		} else {
			break;
		}
	}
	thread_tick();
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}
