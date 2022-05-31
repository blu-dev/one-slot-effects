
// The following code is taken from the WIP skyline rust-rewrite to assist in symbol hooking
// the static modules

#[derive(Debug)]
#[repr(transparent)]
pub struct NxResult(u32);

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum MemoryState {
    Free             = 0x00,
    Io               = 0x01,
    Static           = 0x02,
    Code             = 0x03,
    CodeData         = 0x04,
    Normal           = 0x05,
    Shared           = 0x06,
    Alias            = 0x07,
    AliasCode        = 0x08,
    AliasCodeData    = 0x09,
    Ipc              = 0x0A,
    Stack            = 0x0B,
    ThreadLocal      = 0x0C,
    Transfered       = 0x0D,
    SharedTransfered = 0x0E,
    SharedCode       = 0x0F,
    Inaccessible     = 0x10,
    NonSecureIpc     = 0x11,
    NonDeviceIpc     = 0x12,
    Kernel           = 0x13,
    GeneratedCode    = 0x14,
    CodeOut          = 0x15,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemoryInfo {
    pub base_address: usize,
    pub size: usize,
    pub state: u32,
    pub attribute: u32,
    pub permission: u32,
    pub device_refcount: u32,
    pub ipc_refcount: u32,
    pub padding: u32
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct PageInfo {
    pub flags: u32
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QueryMemoryResult {
    pub mem_info: MemoryInfo,
    pub page_info: PageInfo
}

use std::mem::MaybeUninit;

std::arch::global_asm!(r#"
.macro SVC_BEGIN name
    .section .text.\name, "ax", %progbits
    .global \name
    .type \name, %function
    .align 2
    .cfi_startproc
\name:
.endm

.macro SVC_END
    .cfi_endproc
.endm

SVC_BEGIN svcQueryMemory
    str x1, [sp, #-16]!
    svc 0x6
    ldr x2, [sp], 16
    str w1, [x2]
    ret
SVC_END

SVC_BEGIN svcGetInfo
    str x0, [sp, -16]!
    svc 0x29
    ldr x2, [sp], 16
    str x1, [x2]
    ret
SVC_END
"#);

extern "C" {
    fn svcQueryMemory(mem_info: &mut MemoryInfo, page_info: &mut u32, addr: *mut u8) -> NxResult;
    fn svcGetInfo(out: &mut u64, what: u32) -> NxResult;
}

pub mod svc {
    use super::*;

    #[inline(always)]
    pub extern "C" fn query_memory(address: usize) -> Result<QueryMemoryResult, NxResult> {
        let mut res: NxResult = NxResult(0);
        let mut mem_info: MemoryInfo = unsafe { std::mem::zeroed() };
        let svc_result = unsafe {
            let mut page_info = 0u32;
            res = svcQueryMemory(&mut mem_info, &mut page_info, address as _);
            QueryMemoryResult {
                mem_info: mem_info,
                page_info: PageInfo { flags: page_info }
            }
        };
        match res.0 {
            0 => Ok(svc_result),
            _ => Err(res)
        }
    }

    pub fn get_info(what: u32) -> Result<u64, NxResult> {
        unsafe {
            let mut val = 0u64;
            let res = svcGetInfo(&mut val, what);
            if res.0 == 0 {
                Ok(val)
            } else {
                Err(res)
            }
        }
    }
}