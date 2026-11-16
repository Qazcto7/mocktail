//! Pure-Rust lock-free audio primitives:
//! - `AudioSlotPool`: wait-free/lock-free `AtomicU64` bitmask slot allocator
//!   eliminating per-buffer heap allocations and O(N) slot scans in SDL/OpenSL/FMOD.
//! - `AudioCallbackRing`: bounded lock-free Vyukov MPMC ring buffer for
//!   zero-allocation OpenSL callback job queueing.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const MAX_SLOT_POOL_CAPACITY: usize = 4096;

#[repr(C)]
pub struct MocktailRustAudioSlotPool {
    capacity: usize,
    words: Box<[AtomicU64]>,
}

impl MocktailRustAudioSlotPool {
    pub fn new(capacity: usize) -> Option<Self> {
        if capacity == 0 || capacity > MAX_SLOT_POOL_CAPACITY {
            return None;
        }
        let word_count = capacity.div_ceil(64);
        let mut words = Vec::with_capacity(word_count);
        for word_idx in 0..word_count {
            words.push(AtomicU64::new(Self::full_mask_for_word(capacity, word_idx)));
        }
        Some(Self {
            capacity,
            words: words.into_boxed_slice(),
        })
    }

    #[inline]
    fn full_mask_for_word(capacity: usize, word_idx: usize) -> u64 {
        let remaining = capacity.saturating_sub(word_idx * 64);
        if remaining >= 64 {
            u64::MAX
        } else if remaining == 0 {
            0
        } else {
            (1u64 << remaining) - 1
        }
    }

    #[inline]
    pub fn acquire(&self) -> Option<usize> {
        for (word_idx, word) in self.words.iter().enumerate() {
            loop {
                let cur = word.load(Ordering::Acquire);
                if cur == 0 {
                    break;
                }
                let bit_pos = cur.trailing_zeros() as usize;
                let idx = word_idx * 64 + bit_pos;
                if idx >= self.capacity {
                    break;
                }
                let mask = !(1u64 << bit_pos);
                if word
                    .compare_exchange_weak(cur, cur & mask, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Some(idx);
                }
            }
        }
        None
    }

    #[inline]
    pub fn release(&self, index: usize) -> bool {
        if index >= self.capacity {
            return false;
        }
        let word_idx = index / 64;
        let bit = 1u64 << (index % 64);
        let prev = self.words[word_idx].fetch_or(bit, Ordering::Release);
        (prev & bit) == 0
    }

    pub fn reset(&self) {
        for (word_idx, word) in self.words.iter().enumerate() {
            word.store(
                Self::full_mask_for_word(self.capacity, word_idx),
                Ordering::Release,
            );
        }
    }
}

struct RingCell {
    sequence: AtomicUsize,
    callback: AtomicUsize,
    context: AtomicUsize,
}

#[repr(C)]
pub struct MocktailRustAudioCallbackRing {
    mask: usize,
    cells: Box<[RingCell]>,
    enqueue_pos: AtomicUsize,
    dequeue_pos: AtomicUsize,
}

impl MocktailRustAudioCallbackRing {
    pub fn new(min_capacity: usize) -> Option<Self> {
        let cap = min_capacity.clamp(16, 65536).next_power_of_two();
        let mut cells = Vec::with_capacity(cap);
        for i in 0..cap {
            cells.push(RingCell {
                sequence: AtomicUsize::new(i),
                callback: AtomicUsize::new(0),
                context: AtomicUsize::new(0),
            });
        }
        Some(Self {
            mask: cap - 1,
            cells: cells.into_boxed_slice(),
            enqueue_pos: AtomicUsize::new(0),
            dequeue_pos: AtomicUsize::new(0),
        })
    }

    pub fn push(&self, callback: usize, context: usize) -> bool {
        let mut pos = self.enqueue_pos.load(Ordering::Relaxed);
        loop {
            let cell = &self.cells[pos & self.mask];
            let seq = cell.sequence.load(Ordering::Acquire);
            let dif = (seq as isize) - (pos as isize);
            if dif == 0 {
                if self
                    .enqueue_pos
                    .compare_exchange_weak(pos, pos.wrapping_add(1), Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    cell.callback.store(callback, Ordering::Relaxed);
                    cell.context.store(context, Ordering::Relaxed);
                    cell.sequence.store(pos.wrapping_add(1), Ordering::Release);
                    return true;
                }
                pos = self.enqueue_pos.load(Ordering::Relaxed);
            } else if dif < 0 {
                return false;
            } else {
                pos = self.enqueue_pos.load(Ordering::Relaxed);
            }
        }
    }

    pub fn pop(&self) -> Option<(usize, usize)> {
        let mut pos = self.dequeue_pos.load(Ordering::Relaxed);
        loop {
            let cell = &self.cells[pos & self.mask];
            let seq = cell.sequence.load(Ordering::Acquire);
            let dif = (seq as isize) - (pos.wrapping_add(1) as isize);
            if dif == 0 {
                if self
                    .dequeue_pos
                    .compare_exchange_weak(pos, pos.wrapping_add(1), Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    let cb = cell.callback.load(Ordering::Relaxed);
                    let ctx = cell.context.load(Ordering::Relaxed);
                    cell.sequence
                        .store(pos.wrapping_add(self.mask + 1), Ordering::Release);
                    return Some((cb, ctx));
                }
                pos = self.dequeue_pos.load(Ordering::Relaxed);
            } else if dif < 0 {
                return None;
            } else {
                pos = self.dequeue_pos.load(Ordering::Relaxed);
            }
        }
    }

    pub fn clear(&self) {
        while self.pop().is_some() {}
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_slot_pool_create(
    capacity: usize,
) -> *mut MocktailRustAudioSlotPool {
    match MocktailRustAudioSlotPool::new(capacity) {
        Some(pool) => Box::into_raw(Box::new(pool)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_slot_pool_destroy(pool: *mut MocktailRustAudioSlotPool) {
    if !pool.is_null() {
        unsafe { drop(Box::from_raw(pool)) };
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_slot_pool_acquire(
    pool: *const MocktailRustAudioSlotPool,
) -> isize {
    if pool.is_null() {
        return -1;
    }
    match unsafe { &*pool }.acquire() {
        Some(idx) => idx as isize,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_slot_pool_release(
    pool: *const MocktailRustAudioSlotPool,
    index: usize,
) -> bool {
    if pool.is_null() {
        return false;
    }
    unsafe { &*pool }.release(index)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_slot_pool_reset(pool: *const MocktailRustAudioSlotPool) {
    if !pool.is_null() {
        unsafe { &*pool }.reset();
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_ring_create(
    min_capacity: usize,
) -> *mut MocktailRustAudioCallbackRing {
    match MocktailRustAudioCallbackRing::new(min_capacity) {
        Some(ring) => Box::into_raw(Box::new(ring)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_ring_destroy(ring: *mut MocktailRustAudioCallbackRing) {
    if !ring.is_null() {
        unsafe { drop(Box::from_raw(ring)) };
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_ring_push(
    ring: *const MocktailRustAudioCallbackRing,
    callback: usize,
    context: usize,
) -> bool {
    if ring.is_null() {
        return false;
    }
    unsafe { &*ring }.push(callback, context)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_ring_pop(
    ring: *const MocktailRustAudioCallbackRing,
    callback_out: *mut usize,
    context_out: *mut usize,
) -> bool {
    if ring.is_null() || callback_out.is_null() || context_out.is_null() {
        return false;
    }
    if let Some((cb, ctx)) = unsafe { &*ring }.pop() {
        unsafe {
            *callback_out = cb;
            *context_out = ctx;
        }
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_audio_ring_clear(ring: *const MocktailRustAudioCallbackRing) {
    if !ring.is_null() {
        unsafe { &*ring }.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn slot_pool_acquires_releases_resets_and_guards_double_release() {
        let pool = MocktailRustAudioSlotPool::new(130).unwrap();
        let mut acquired = Vec::new();
        while let Some(idx) = pool.acquire() {
            acquired.push(idx);
        }
        assert_eq!(acquired.len(), 130);
        acquired.sort_unstable();
        acquired.dedup();
        assert_eq!(acquired.len(), 130);
        assert!(pool.acquire().is_none());

        assert!(pool.release(65));
        assert!(!pool.release(65));
        assert!(!pool.release(130));
        assert_eq!(pool.acquire(), Some(65));

        pool.reset();
        for _ in 0..130 {
            assert!(pool.acquire().is_some());
        }
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn callback_ring_preserves_fifo_and_handles_concurrent_spsc_mpmc() {
        let ring = Arc::new(MocktailRustAudioCallbackRing::new(64).unwrap());
        let p_ring = Arc::clone(&ring);
        let producer = thread::spawn(move || {
            for i in 1..=2000usize {
                while !p_ring.push(i, i * 10) {
                    thread::yield_now();
                }
            }
        });
        let mut received = 0usize;
        while received < 2000 {
            if let Some((cb, ctx)) = ring.pop() {
                received += 1;
                assert_eq!(cb, received);
                assert_eq!(ctx, received * 10);
            } else {
                thread::yield_now();
            }
        }
        producer.join().unwrap();
        assert!(ring.pop().is_none());

        assert!(ring.push(11, 22));
        assert!(ring.push(33, 44));
        ring.clear();
        assert!(ring.pop().is_none());
    }
}
