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
    // FIXME: Improve documentation, explain the magic number 0x2000_0000
    /// Length, in bytes, of the memory region described by `addr`.
    sz: u32,
    // FIXME: Improve documentation, enum all possible tags.
    /// DMA attribute / tag field.
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

/// Fixed-capacity scatter-gather descriptor chain.
///
/// This type owns a small array of `Descriptor`s and tracks how many entries
/// are currently in use.
///
/// DescriptorChain also make sure they are linked like a linked-list
/// and the last Descriptor.next is always LAST_DESC_PTR
pub(crate) struct DescriptorChain<const N: usize> {
    descs: [Descriptor; N],
    count: usize,
}

impl<const N: usize> DescriptorChain<N> {
    /// Creates an empty `DescriptorChain`.
    ///
    /// The chain is initialized with all descriptors zero-filled and contains
    /// no active entries.
    pub(crate) fn new() -> Self {
        Self {
            descs: [Descriptor::empty(); N],
            count: 0,
        }
    }

    /// Appends a descriptor to the end of the chain.
    ///
    /// This method:
    /// - Stores `desc` in the next free slot.
    /// - Updates the `next` pointer of the previous descriptor to point to the
    ///   newly added one.
    /// - Ensures the newly added descriptor’s `next` pointer is set to
    ///   `LAST_DESC_PTR`, marking it as the terminal job entry.
    ///
    /// # Panics
    ///
    /// Panics if the chain is already at full capacity.
    ///
    /// # Safety / Correctness requirements
    ///
    /// - The descriptor and all previously pushed descriptors must remain
    ///   valid and unmodified while a DMA transfer is in progress.
    /// - All descriptors in the chain must describe DMA-accessible memory.
    /// - The chain must not be mutated after being handed to the EasyDMA
    ///   hardware until the END or ERROR event is observed.
    pub(crate) fn push(&mut self, addr: *mut u8, sz: u32, dmatag: u32) {
        assert!(self.count < N);
        let desc = Descriptor::new(addr, sz, dmatag);

        let idx = self.count;
        self.descs[idx] = desc;
        self.count += 1;

        // update links
        if idx > 0 {
            let prev = idx - 1;
            self.descs[prev].next = &mut self.descs[idx];
        }

        self.descs[idx].next = LAST_DESC_PTR;
    }

    /// Returns an address to the first descriptor in the chain.
    ///
    /// This pointer is intended to be written to the EasyDMA input/output pointer
    /// register to start a scatter-gather transfer.
    pub(crate) fn first(&mut self) -> u32 {
        &mut self.descs[0] as *mut Descriptor as u32
    }
}
