// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

/// Pointer to memory address 1.
/// It means that the descriptor chain is over
#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
const LAST_DESC_PTR: *mut Descriptor = 1 as *mut Descriptor;
const DMA_REALIGN: u32 = 1 << 29;
/// Single EasyDMA scatter-gather job entry.
///
/// This structure maps directly to one hardware “job entry” consumed by the
/// EasyDMA engine when scatter-gather mode is enabled. Each descriptor describes
/// one contiguous memory region to be read from or written to by DMA.
/// `next` must either point to the next `Descriptor` in the chain or be the
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Descriptor {
    /// Start address of the memory region for this DMA job.
    ///
    /// Must be DMA-accessible memory.
    addr: *mut u8,
    /// Pointer to the next descriptor in the scatter-gather job list.
    ///
    /// Should be LAST_DESC_PTR in case of the last descriptor of the chain.
    next: *mut Descriptor,
    /// Length of the memory region in bytes, with `DMA_REALIGN` (bit 29) set.
    /// `DMA_REALIGN` tells the DMA engine to re-align its internal state at the end of this
    /// descriptor before starting the next one.
    sz: u32,
    /// Routes this descriptor to a hardware engine and describes the data role.
    /// Lower bits select the engine (e.g. `DMATAG_BA411 = 1` for AES). Bit 4 marks a
    /// configuration register write; bits [6:5] encode the data type; bits [12:8] encode the
    /// number of trailing padding bytes the engine should ignore (`DMATAG_IGN`).
    dmatag: u32,
}

impl Descriptor {
    fn empty() -> Self {
        Self {
            addr: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            sz: 0,
            dmatag: 0,
        }
    }

    fn new(addr: *mut u8, sz: u32, dmatag: u32) -> Self {
        Self {
            addr,
            next: core::ptr::null_mut(),
            sz,
            dmatag,
        }
    }
}

/// Marker type for a descriptor chain that feeds data into the DMA engine (reads from memory).
pub(crate) struct Input;
/// Marker type for a descriptor chain that receives data from the DMA engine (writes to memory).
pub(crate) struct Output;

/// Fixed-capacity scatter-gather descriptor chain.
///
/// This type owns a small array of `Descriptor`s and tracks how many entries
/// are currently in use.
///
/// Descriptors are linked into a list (with the last terminated by [`LAST_DESC_PTR`])
/// lazily, just before use, in [`first`](DescriptorChain::first). This avoids the
/// struct being self-referential at rest, which would make it unsafe to move after pushing.
///
/// `Direction` is either [`Input`] or [`Output`], distinguishing read-from-memory and
/// write-to-memory chains at the type level.
pub(crate) struct DescriptorChain<'mem, Direction, const N: usize> {
    descs: [Descriptor; N],
    count: usize,
    /// Bytes accumulated since the last realign (`DMA_REALIGN`) descriptor — i.e. the running total
    /// fed by `push_raw`. A realign `push` must bring this to a word boundary before resetting it.
    pending: usize,
    _dir: core::marker::PhantomData<*mut &'mem Direction>,
}

impl<'mem, Direction, const N: usize> DescriptorChain<'mem, Direction, N> {
    /// Creates an empty `DescriptorChain`.
    ///
    /// The chain is initialized with all descriptors zero-filled and contains
    /// no active entries.
    pub(crate) fn new() -> Self {
        Self {
            descs: [Descriptor::empty(); N],
            count: 0,
            pending: 0,
            _dir: core::marker::PhantomData,
        }
    }

    /// Links a new [`Descriptor`] into the chain.
    ///
    /// # Panics
    ///
    /// Panics if the chain is already at full capacity.
    fn push_descriptor(&mut self, desc: Descriptor) {
        assert!(self.count < N);

        let idx = self.count;
        self.descs[idx] = desc;
        self.count += 1;
    }

    /// Sets the `next` pointer of each descriptor to point to the following one,
    /// and terminates the chain with [`LAST_DESC_PTR`].
    ///
    /// Links are set here rather than at push time to avoid the struct being
    /// self-referential at rest (which would make it unsafe to move after pushing).
    fn update_links(&mut self) {
        for i in 1..self.count {
            self.descs[i - 1].next = &mut self.descs[i];
        }
        if self.count > 0 {
            let last = &mut self.descs[self.count - 1];
            last.next = LAST_DESC_PTR;
            // DMATAG_LAST (bit 5) on the final descriptor signals the engine to
            // finalize the operation (produce output / authentication tag).
            // sx_cmdma_finalize_descs() in the Nordic SDK applies this to both
            // the last input and last output descriptor of every DMA operation.
            last.dmatag |= 1 << 5;
        }
    }

    /// Returns an address to the first descriptor in the chain.
    ///
    /// This pointer is intended to be written to the EasyDMA input/output pointer
    /// register to start a scatter-gather transfer.
    fn first(&mut self) -> u32 {
        assert!(self.count > 0);
        self.update_links();
        &self.descs[0] as *const Descriptor as u32
    }

    /// Calls `f` with the address of the first descriptor, holding a `&mut self`
    /// borrow for the duration of the call.
    ///
    /// This guarantees that the descriptor chain remains live and pinned in memory
    /// while `f` is executing, so the pointer passed to hardware stays valid.
    ///
    /// # Safety
    ///
    /// This function is not unsafe to use on its own, but typically used to call
    /// `dma.fetchaddrlsb().write_value(…)` or `dma.fpushaddrlsb().write_value(…)` the argument,
    /// which is an unsafe operation.
    ///
    /// To make that operation safe, `f` must wait until END or ERROR is observed on the relevant
    /// EasyDMA. It must not return **or panic** between starting the DMA operation and observing
    /// its completion.
    pub(crate) fn with_first_pointer(&mut self, f: impl FnOnce(u32)) {
        f(self.first())
    }
}

impl<'mem, const N: usize> DescriptorChain<'mem, Input, N> {
    /// Appends an input (read) buffer to the chain.
    ///
    /// The DMA engine will read from `data` during the transfer.
    ///
    /// # Safety / Correctness requirements
    ///
    /// - `data` must be DMA-accessible memory.
    /// - `data.len()` must be a multiple of 4.
    pub(crate) fn push(&mut self, data: &'mem [u8], dmatag: u32) {
        // Realigning descriptor: the cumulative byte count fed since the last realign point (any
        // preceding `push_raw` bytes plus this descriptor) must land on a word boundary, otherwise
        // the fetcher flushes a partial word and corrupts the stream.
        self.pending += data.len();
        debug_assert!(
            self.pending.is_multiple_of(4),
            "Cumulative bytes at a realign point must be a multiple of the word size"
        );
        self.pending = 0;
        self.push_descriptor(Descriptor::new(
            data.as_ptr() as *mut u8,
            sz(data.len()),
            dmatag,
        ));
    }

    /// Appends an input (read) buffer *without* the `DMA_REALIGN` flag.
    ///
    /// Omitting `DMA_REALIGN` makes the fetcher keep its partial-word accumulator across this
    /// descriptor's boundary, so the descriptor's trailing 1-3 bytes are byte-concatenated with
    /// the *next* descriptor's data instead of being padded out to a 32-bit word boundary. This
    /// mirrors `ADD_RAW_INDESC` in the Nordic SDK (`cmdma.h`), which `sx_hash_feed` uses to stream
    /// arbitrary-length chunks. It is the mechanism for feeding a sub-word field (e.g. the 2-byte
    /// CCM AAD length prefix) in its own descriptor while keeping the byte stream contiguous.
    ///
    /// Unlike [`push`](Self::push), `data.len()` need not be a multiple of 4. Whatever descriptor
    /// follows must bring the cumulative byte count back to a word boundary by the next
    /// `DMA_REALIGN` point.
    ///
    /// Must **not** be used for the last descriptor of a data type (or of the whole chain): without
    /// `DMA_REALIGN` the fetcher never flushes its trailing partial word — it always defers the
    /// sub-word remainder to the next descriptor. A terminal descriptor has no next one, so its
    /// pending bytes would be left unflushed. Use [`push`](Self::push) there instead; it realigns
    /// and flushes (and is also the only variant that can mark trailing padding via `dmatag_ign`).
    pub(crate) fn push_raw(&mut self, data: &'mem [u8], dmatag: u32) {
        // RAW descriptor: no realign, so its (possibly sub-word) bytes accumulate into `pending` for
        // a later realigning `push` to bring back to a word boundary.
        self.pending += data.len();
        self.push_descriptor(Descriptor::new(
            data.as_ptr() as *mut u8,
            data.len() as u32,
            dmatag,
        ));
    }
}

impl<'mem, const N: usize> DescriptorChain<'mem, Output, N> {
    /// Appends an output (write) buffer to the chain.
    ///
    /// The DMA engine will write into `data` during the transfer.
    ///
    /// # Safety / Correctness requirements
    ///
    /// - `data` must be DMA-accessible memory.
    /// - `data.len()` must be a multiple of 4.
    pub(crate) fn push(&mut self, data: &'mem mut [u8], dmatag: u32) {
        // Realigning descriptor: the cumulative byte count fed since the last realign point must land
        // on a word boundary before the fetcher flushes.
        self.pending += data.len();
        debug_assert!(
            self.pending.is_multiple_of(4),
            "cumulative bytes at a realign point must be a multiple of the word size"
        );
        self.pending = 0;
        self.push_descriptor(Descriptor::new(data.as_mut_ptr(), sz(data.len()), dmatag));
    }
}

/// Encodes `n` ignored trailing bytes into a dmatag (bits [12:8]).
/// The engine will process the full buffer but treat the last `n` bytes as zero-padding.
pub(crate) const fn dmatag_ign(n: usize) -> u32 {
    (n as u32) << 8
}

/// ORs in the `DMA_REALIGN` constant.
///
/// Note: `n` need NOT be a multiple of the word size. A realign descriptor may complete a partial
/// word left by preceding RAW (`push_raw`) descriptors; what matters is that the *cumulative* byte
/// count is word-aligned at the realign point, not that this single descriptor's length is. The
/// engine handles the sub-word completion via `DMA_REALIGN`.
#[inline]
const fn sz(n: usize) -> u32 {
    n as u32 | DMA_REALIGN
}
