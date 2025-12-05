#[allow(
    clippy::manual_dangling_ptr,
    reason = "nRF54L15 uses 1 as last-descriptor sentinel"
)]
pub const LAST_DESC_PTR: *mut Descriptor = 1 as *mut Descriptor;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Descriptor {
    pub addr: *mut u8,
    pub next: *mut Descriptor,
    pub sz: u32,
    pub dmatag: u32,
}

impl Descriptor {
    pub fn empty() -> Self {
        Self {
            addr: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            sz: 0,
            dmatag: 0,
        }
    }
}

pub struct DescriptorChain {
    descs: [Descriptor; 4],
    count: usize,
}

impl DescriptorChain {
    pub fn new() -> Self {
        Self {
            descs: [Descriptor::empty(); 4],
            count: 0,
        }
    }

    pub fn push(&mut self, desc: Descriptor) {
        assert!(self.count < 4);

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

    pub fn first(&mut self) -> *mut Descriptor {
        if self.count == 0 {
            core::ptr::null_mut()
        } else {
            &mut self.descs[0]
        }
    }
}
