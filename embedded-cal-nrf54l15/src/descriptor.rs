// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

/// Pointer to memory address 1.
/// It means that the descriptor chain is over
#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
const LAST_DESC_PTR: *mut Descriptor = 1 as *mut Descriptor;
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
        self.push_descriptor(Descriptor::new(
            data.as_ptr() as *mut u8,
            sz(data.len()),
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
    pub(crate) fn push(&mut self, data: &'mem mut [u8], dmatag: u32) {
        self.push_descriptor(Descriptor::new(data.as_mut_ptr(), sz(data.len()), dmatag));
    }
}

/// Encodes `n` ignored trailing bytes into a dmatag (bits [12:8]).
/// The engine will process the full buffer but treat the last `n` bytes as zero-padding.
pub(crate) const fn dmatag_ign(n: usize) -> u32 {
    (n as u32) << 8
}

/// Asserts that size is a multiple of 4, and ORs in the DMA_REALIGN constant.
#[inline]
const fn sz(n: usize) -> u32 {
    const DMA_REALIGN: usize = 0x2000_0000;
    debug_assert!(
        n.is_multiple_of(4),
        "Sizes passed through this function need to be in multiples of the word size"
    );
    (n | DMA_REALIGN) as u32
}
