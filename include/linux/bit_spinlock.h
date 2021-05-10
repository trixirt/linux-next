/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BIT_SPINLOCK_H
#define __LINUX_BIT_SPINLOCK_H

#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/atomic.h>
#include <linux/bug.h>

/*
 *  bit-based spin_lock()
 *
 * Don't use this unless you really need to: spin_lock() and spin_unlock()
 * are significantly faster.
 */
static inline void __raw_bit_spin_lock(int bitnum, unsigned long *addr)
{
	/*
	 * Assuming the lock is uncontended, this never enters
	 * the body of the outer loop. If it is contended, then
	 * within the inner loop a non-atomic test is used to
	 * busywait with less bus contention for a good time to
	 * attempt to acquire the lock bit.
	 */
	preempt_disable();
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	while (unlikely(test_and_set_bit_lock(bitnum, addr))) {
		preempt_enable();
		do {
			cpu_relax();
		} while (test_bit(bitnum, addr));
		preempt_disable();
	}
#endif
	__acquire(bitlock);
}

/*
 * Return true if it was acquired
 */
static inline int __raw_bit_spin_trylock(int bitnum, unsigned long *addr)
{
	preempt_disable();
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	if (unlikely(test_and_set_bit_lock(bitnum, addr))) {
		preempt_enable();
		return 0;
	}
#endif
	__acquire(bitlock);
	return 1;
}

/*
 *  bit-based spin_unlock()
 */
static inline void __raw_bit_spin_unlock(int bitnum, unsigned long *addr)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(!test_bit(bitnum, addr));
#endif
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	clear_bit_unlock(bitnum, addr);
#endif
	preempt_enable();
	__release(bitlock);
}

/*
 *  bit-based spin_unlock()
 *  non-atomic version, which can be used eg. if the bit lock itself is
 *  protecting the rest of the flags in the word.
 */
static inline void ___raw_bit_spin_unlock(int bitnum, unsigned long *addr)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(!test_bit(bitnum, addr));
#endif
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	__clear_bit_unlock(bitnum, addr);
#endif
	preempt_enable();
	__release(bitlock);
}

/*
 * Return true if the lock is held.
 */
static inline int __raw_bit_spin_is_locked(int bitnum, unsigned long *addr)
{
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
	return test_bit(bitnum, addr);
#elif defined CONFIG_PREEMPT_COUNT
	return preempt_count();
#else
	return 1;
#endif
}

typedef struct {
	unsigned long addr;
#if defined(CONFIG_PREEMPT_RT)
	spinlock_t spin_lock;
	unsigned long initialized : 1;
#endif
} bit_spinlock_t;

#if defined(CONFIG_PREEMPT_RT)

static inline void bit_spin_lock_init(int bitnum, bit_spinlock_t *lock)
{
	if (unlikely(!lock->initialize)) {
		spin_lock_init(&lock->spin_lock);
		lock->initialized = 1;
	}
}

static inline int bit_spin_lock(int bitnum, bit_spinlock_t *lock)
{
	bit_spin_lock_init(bitnum, lock);
	return spin_lock(&lock->spin_lock);
}

static inline int bit_spin_trylock(int bitnum, bit_spinlock_t *lock)
{
	bit_spin_lock_init(bitnum, lock);
	return spin_trylock(&lock->spin_lock);
}

static inline void bit_spin_unlock(int bitnum, bit_spinlock_t *lock)
{
	bit_spin_lock_init(bitnum, lock);
	spin_unock(&lock->spin_lock);
}

static inline void __bit_spin_unlock(int bitnum, bit_spinlock_t *lock)
{
	bit_spin_unlock(bitnum, lock);
}

static inline int bit_spin_is_locked(int bitnum, bit_spinlock_t *lock)
{
	bit_spin_lock_init(bitnum, lock);
	return spin_is_locked(&lock->spin_lock);
}

#else

#define bit_spin_lock_init(bitnum, lock)
#define bit_spin_lock(bitnum, lock) __raw_bit_spin_lock((bitnum), &(lock)->addr)
#define bit_spin_trylock(bitnum, lock) __raw_bit_spin_trylock((bitnum), &(lock)->addr)
#define bit_spin_unlock(bitnum, lock) __raw_bit_spin_unlock((bitnum), &(lock)->addr)
#define __bit_spin_unlock(bitnum, lock)	___raw_bit_spin_unlock((bitnum), &(lock)->addr)
#define bit_spin_is_locked(bitnum, lock) __raw_bit_spin_is_locked((bitnum), &(lock)->addr)

#endif /* CONFIG_PREEMPT_RT */

#endif /* __LINUX_BIT_SPINLOCK_H */

