//! Safe Capstone 5 x86-64 FFI wrapper implementing `X86Disassembler`.
//!
//! Layout constants match `<capstone/capstone.h>` and `<capstone/x86.h>` for
//! Capstone 5 on 64-bit targets (`cs_version` major == 5 verified at open time).

use std::ffi::{c_char, c_int, c_uint, CStr};
use std::mem::{offset_of, size_of};

use crate::host_abi_deriver::{Instruction, Operand, OperandKind, X86Disassembler};

const CS_ARCH_X86: c_int = 3;
const CS_MODE_64: c_int = 8;
const CS_OPT_DETAIL: c_int = 2;
const CS_OPT_ON: usize = 3;
const CS_ERR_OK: c_int = 0;

const CS_GRP_JUMP: c_uint = 1;
const CS_GRP_CALL: c_uint = 2;
const CS_GRP_RET: c_uint = 3;

const X86_OP_REG: u32 = 1;
const X86_OP_IMM: u32 = 2;
const X86_OP_MEM: u32 = 3;
const X86_REG_RIP: c_uint = 41;

type Csh = usize;

#[repr(C)]
#[derive(Clone, Copy)]
struct X86OpMem {
    segment: c_uint,
    base: c_uint,
    index: c_uint,
    scale: c_int,
    disp: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
union CsX86OpValue {
    reg: c_uint,
    imm: i64,
    mem: X86OpMem,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CsX86Op {
    type_: u32,
    value: CsX86OpValue,
    size: u8,
    _pad_tail: [u8; 15],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CsX86Encoding {
    modrm_offset: u8,
    disp_offset: u8,
    disp_size: u8,
    imm_offset: u8,
    imm_size: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CsX86 {
    _head: [u8; 64],
    op_count: u8,
    operands: [CsX86Op; 8],
    encoding: CsX86Encoding,
}

#[repr(C)]
struct CsDetail {
    _regs_and_groups: [u8; 96],
    x86: CsX86,
    _other_arch_pad: [u8; 1864 - (96 + size_of::<CsX86>())],
}

#[repr(C)]
struct CsInsn {
    id: c_uint,
    address: u64,
    size: u16,
    bytes: [u8; 24],
    mnemonic: [c_char; 32],
    op_str: [c_char; 160],
    detail: *mut CsDetail,
}

const _: () = {
    assert!(size_of::<X86OpMem>() == 24);
    assert!(size_of::<CsX86Op>() == 48);
    assert!(offset_of!(CsX86Op, value) == 8);
    assert!(offset_of!(CsX86Op, size) == 32);
    assert!(size_of::<CsX86Encoding>() == 5);
    assert!(size_of::<CsX86>() == 464);
    assert!(offset_of!(CsX86, op_count) == 64);
    assert!(offset_of!(CsX86, operands) == 72);
    assert!(offset_of!(CsX86, encoding) == 456);
    assert!(size_of::<CsDetail>() == 1864);
    assert!(offset_of!(CsDetail, x86) == 96);
    assert!(size_of::<CsInsn>() == 248);
    assert!(offset_of!(CsInsn, id) == 0);
    assert!(offset_of!(CsInsn, address) == 8);
    assert!(offset_of!(CsInsn, size) == 16);
    assert!(offset_of!(CsInsn, bytes) == 18);
    assert!(offset_of!(CsInsn, mnemonic) == 42);
    assert!(offset_of!(CsInsn, op_str) == 74);
    assert!(offset_of!(CsInsn, detail) == 240);
};

extern "C" {
    fn cs_version(major: *mut c_int, minor: *mut c_int) -> c_uint;
    fn cs_open(arch: c_int, mode: c_int, handle: *mut Csh) -> c_int;
    fn cs_close(handle: *mut Csh) -> c_int;
    fn cs_option(handle: Csh, type_: c_int, value: usize) -> c_int;
    fn cs_disasm(
        handle: Csh,
        code: *const u8,
        code_size: usize,
        address: u64,
        count: usize,
        insn: *mut *mut CsInsn,
    ) -> usize;
    fn cs_free(insn: *mut CsInsn, count: usize);
    fn cs_reg_name(handle: Csh, reg_id: c_uint) -> *const c_char;
    fn cs_insn_group(handle: Csh, insn: *const CsInsn, group_id: c_uint) -> bool;
}

fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

pub(crate) struct CapstoneX86Disassembler {
    handle: Csh,
}

impl Default for CapstoneX86Disassembler {
    fn default() -> Self {
        Self { handle: 0 }
    }
}

impl Drop for CapstoneX86Disassembler {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                let _ = cs_close(&mut self.handle as *mut Csh);
            }
            self.handle = 0;
        }
    }
}

impl X86Disassembler for CapstoneX86Disassembler {
    fn open(&mut self) -> Result<(), String> {
        if self.handle != 0 {
            return Ok(());
        }
        let mut major: c_int = 0;
        let mut minor: c_int = 0;
        unsafe {
            cs_version(&mut major, &mut minor);
        }
        if major != 5 {
            return Err("cannot open x86-64 disassembler".to_string());
        }
        let mut handle: Csh = 0;
        let open_err = unsafe { cs_open(CS_ARCH_X86, CS_MODE_64, &mut handle) };
        if open_err != CS_ERR_OK
            || handle == 0
            || unsafe { cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) } != CS_ERR_OK
        {
            if handle != 0 {
                unsafe {
                    let _ = cs_close(&mut handle);
                }
            }
            return Err("cannot open x86-64 disassembler".to_string());
        }
        self.handle = handle;
        Ok(())
    }

    fn decode_raw(&self, rva: u64, code: &[u8], count: usize) -> Result<Vec<Instruction>, String> {
        if self.handle == 0 || count == 0 {
            return Err("cannot disassemble instruction".to_string());
        }
        let mut decoded_ptr: *mut CsInsn = std::ptr::null_mut();
        let decoded_count = unsafe {
            cs_disasm(
                self.handle,
                code.as_ptr(),
                code.len(),
                rva,
                count,
                &mut decoded_ptr,
            )
        };
        if decoded_count != count || decoded_ptr.is_null() {
            if !decoded_ptr.is_null() {
                unsafe {
                    cs_free(decoded_ptr, decoded_count);
                }
            }
            return Err("cannot decode normalized instruction signature".to_string());
        }

        struct Guard(*mut CsInsn, usize);
        impl Drop for Guard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { cs_free(self.0, self.1) };
                }
            }
        }
        let _guard = Guard(decoded_ptr, decoded_count);
        let insns = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_count) };

        let mut out = Vec::with_capacity(decoded_count);
        for src in insns {
            if src.size == 0 || src.detail.is_null() {
                return Err("cannot decode normalized instruction signature".to_string());
            }
            let x86 = unsafe { &(*src.detail).x86 };
            let op_count = (x86.op_count as usize).min(x86.operands.len());
            let mut operands = Vec::with_capacity(op_count);
            for src_op in &x86.operands[..op_count] {
                let op = match src_op.type_ {
                    X86_OP_REG => Operand {
                        kind: OperandKind::Reg,
                        reg_name: cstr_to_string(unsafe { cs_reg_name(self.handle, src_op.value.reg) }),
                        seg_name: String::new(),
                        base_name: String::new(),
                        index_name: String::new(),
                        scale: 0,
                        value: 0,
                        size: src_op.size,
                        rip_relative: false,
                    },
                    X86_OP_IMM => Operand {
                        kind: OperandKind::Imm,
                        reg_name: String::new(),
                        seg_name: String::new(),
                        base_name: String::new(),
                        index_name: String::new(),
                        scale: 0,
                        value: unsafe { src_op.value.imm },
                        size: src_op.size,
                        rip_relative: false,
                    },
                    X86_OP_MEM => {
                        let mem = unsafe { src_op.value.mem };
                        Operand {
                            kind: OperandKind::Mem,
                            reg_name: String::new(),
                            seg_name: cstr_to_string(unsafe { cs_reg_name(self.handle, mem.segment) }),
                            base_name: cstr_to_string(unsafe { cs_reg_name(self.handle, mem.base) }),
                            index_name: cstr_to_string(unsafe { cs_reg_name(self.handle, mem.index) }),
                            scale: mem.scale,
                            value: mem.disp,
                            size: src_op.size,
                            rip_relative: mem.base == X86_REG_RIP,
                        }
                    }
                    _ => {
                        return Err("unsupported x86 operand kind in instruction signature".to_string());
                    }
                };
                operands.push(op);
            }

            let control_flow = unsafe {
                cs_insn_group(self.handle, src as *const CsInsn, CS_GRP_CALL)
                    || cs_insn_group(self.handle, src as *const CsInsn, CS_GRP_JUMP)
            };
            let returns = unsafe { cs_insn_group(self.handle, src as *const CsInsn, CS_GRP_RET) };

            out.push(Instruction {
                address: src.address,
                size: src.size,
                mnemonic: cstr_to_string(src.mnemonic.as_ptr()),
                operands,
                imm_offset: x86.encoding.imm_offset,
                imm_size: x86.encoding.imm_size,
                disp_offset: x86.encoding.disp_offset,
                disp_size: x86.encoding.disp_size,
                control_flow,
                returns,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capstone_decodes_x86_64_rip_relative_and_control_flow() {
        let mut disasm = CapstoneX86Disassembler::default();
        disasm.open().expect("capstone 5 x86_64 open should succeed");

        // push rbp; mov rbp, rsp; lea rax, [rip + 0x10]; call +5; ret
        let code: [u8; 17] = [
            0x55,
            0x48, 0x89, 0xe5,
            0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00,
            0xe8, 0x05, 0x00, 0x00, 0x00,
            0xc3,
        ];
        let insns = disasm.decode_raw(0x1000, &code, 5).unwrap();
        assert_eq!(insns.len(), 5);

        assert_eq!(insns[0].mnemonic, "push");
        assert!(!insns[0].control_flow);
        assert!(!insns[0].returns);

        assert_eq!(insns[2].mnemonic, "lea");
        assert_eq!(insns[2].operands[0].kind, OperandKind::Reg);
        assert_eq!(insns[2].operands[0].reg_name, "rax");
        assert_eq!(insns[2].operands[1].kind, OperandKind::Mem);
        assert!(insns[2].operands[1].rip_relative);
        assert_eq!(insns[2].operands[1].base_name, "rip");
        assert_eq!(insns[2].operands[1].value, 0x10);
        assert_eq!(insns[2].disp_offset, 3);
        assert_eq!(insns[2].disp_size, 4);

        assert_eq!(insns[3].mnemonic, "call");
        assert!(insns[3].control_flow);
        assert!(!insns[3].returns);

        assert_eq!(insns[4].mnemonic, "ret");
        assert!(!insns[4].control_flow);
        assert!(insns[4].returns);
    }
}
