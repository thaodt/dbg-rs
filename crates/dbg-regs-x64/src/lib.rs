//! x86_64 register alias mapping for Linux ptrace backends.
//!
//! This crate translates user-facing register names (`rax`, `eax`, `ah`, `rip`, `rflags`, ...)
//! to bit-slices in Linux `user_regs_struct` and applies architecture-correct write behavior.
//!
//! Where these names/semantics come from:
//! - AMD64 architecture manuals (general-purpose registers, `RIP`, and `RFLAGS`).
//! - Linux `struct user_regs_struct` exposed by `ptrace(PTRACE_GETREGS/SETREGS)`.
//! - x86-64 rule: writing a 32-bit GPR alias (for example `eax`) zero-extends the full 64-bit base.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("dbg-regs-x64 currently supports only x86_64 targets");

use dbg_core::{DebugError, RegisterValue};
use nix::libc::user_regs_struct;

/// Canonical 64-bit storage locations in `user_regs_struct`.
///
/// Aliases like `eax`, `ax`, `al`, and `ah` all map to `BaseReg::Rax`
/// with different `(bits, lsb)` slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseReg {
    /// Accumulator register.
    Rax,
    /// Base register.
    Rbx,
    /// Counter register.
    Rcx,
    /// Data register.
    Rdx,
    /// Source index register.
    Rsi,
    /// Destination index register.
    Rdi,
    /// Base pointer.
    Rbp,
    /// Stack pointer.
    Rsp,
    /// Extended general-purpose register 8.
    R8,
    /// Extended general-purpose register 9.
    R9,
    /// Extended general-purpose register 10.
    R10,
    /// Extended general-purpose register 11.
    R11,
    /// Extended general-purpose register 12.
    R12,
    /// Extended general-purpose register 13.
    R13,
    /// Extended general-purpose register 14.
    R14,
    /// Extended general-purpose register 15.
    R15,
    /// Instruction pointer (program counter on x86-64).
    Rip,
    /// Flags register (condition and control flags).
    Rflags,
}

/// Declarative mapping from a textual register name to a bit range in a base register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegisterSpec {
    /// Canonical lowercase alias returned to callers.
    name: &'static str,
    /// Underlying 64-bit storage register in `user_regs_struct`.
    base: BaseReg,
    /// Width of this alias in bits.
    bits: u8,
    /// Least significant bit offset inside `base`.
    lsb: u8,
    /// Whether writing this alias must zero-extend the full 64-bit base register.
    ///
    /// On x86-64 this is true for 32-bit writes like `eax`, `r8d`, etc.
    zero_extend_64: bool,
}

impl RegisterSpec {
    /// `const` constructor used by static lookup tables.
    const fn new(
        name: &'static str,
        base: BaseReg,
        bits: u8,
        lsb: u8,
        zero_extend_64: bool,
    ) -> Self {
        Self {
            name,
            base,
            bits,
            lsb,
            zero_extend_64,
        }
    }
}

const CANONICAL_GPRS: [RegisterSpec; 18] = [
    RegisterSpec::new("rax", BaseReg::Rax, 64, 0, false),
    RegisterSpec::new("rbx", BaseReg::Rbx, 64, 0, false),
    RegisterSpec::new("rcx", BaseReg::Rcx, 64, 0, false),
    RegisterSpec::new("rdx", BaseReg::Rdx, 64, 0, false),
    RegisterSpec::new("rsi", BaseReg::Rsi, 64, 0, false),
    RegisterSpec::new("rdi", BaseReg::Rdi, 64, 0, false),
    RegisterSpec::new("rbp", BaseReg::Rbp, 64, 0, false),
    RegisterSpec::new("rsp", BaseReg::Rsp, 64, 0, false),
    RegisterSpec::new("r8", BaseReg::R8, 64, 0, false),
    RegisterSpec::new("r9", BaseReg::R9, 64, 0, false),
    RegisterSpec::new("r10", BaseReg::R10, 64, 0, false),
    RegisterSpec::new("r11", BaseReg::R11, 64, 0, false),
    RegisterSpec::new("r12", BaseReg::R12, 64, 0, false),
    RegisterSpec::new("r13", BaseReg::R13, 64, 0, false),
    RegisterSpec::new("r14", BaseReg::R14, 64, 0, false),
    RegisterSpec::new("r15", BaseReg::R15, 64, 0, false),
    RegisterSpec::new("rip", BaseReg::Rip, 64, 0, false),
    RegisterSpec::new("rflags", BaseReg::Rflags, 64, 0, false),
];

/// Resolve a register/alias name into a [`RegisterSpec`].
///
/// Accepts case-insensitive inputs by recursively normalizing ASCII uppercase
/// names into lowercase.
fn spec_by_name(name: &str) -> Option<RegisterSpec> {
    let spec = match name {
        // rax family
        "rax" => RegisterSpec::new("rax", BaseReg::Rax, 64, 0, false),
        "eax" => RegisterSpec::new("eax", BaseReg::Rax, 32, 0, true),
        "ax" => RegisterSpec::new("ax", BaseReg::Rax, 16, 0, false),
        "al" => RegisterSpec::new("al", BaseReg::Rax, 8, 0, false),
        "ah" => RegisterSpec::new("ah", BaseReg::Rax, 8, 8, false),
        // rbx family
        "rbx" => RegisterSpec::new("rbx", BaseReg::Rbx, 64, 0, false),
        "ebx" => RegisterSpec::new("ebx", BaseReg::Rbx, 32, 0, true),
        "bx" => RegisterSpec::new("bx", BaseReg::Rbx, 16, 0, false),
        "bl" => RegisterSpec::new("bl", BaseReg::Rbx, 8, 0, false),
        "bh" => RegisterSpec::new("bh", BaseReg::Rbx, 8, 8, false),
        // rcx family
        "rcx" => RegisterSpec::new("rcx", BaseReg::Rcx, 64, 0, false),
        "ecx" => RegisterSpec::new("ecx", BaseReg::Rcx, 32, 0, true),
        "cx" => RegisterSpec::new("cx", BaseReg::Rcx, 16, 0, false),
        "cl" => RegisterSpec::new("cl", BaseReg::Rcx, 8, 0, false),
        "ch" => RegisterSpec::new("ch", BaseReg::Rcx, 8, 8, false),
        // rdx family
        "rdx" => RegisterSpec::new("rdx", BaseReg::Rdx, 64, 0, false),
        "edx" => RegisterSpec::new("edx", BaseReg::Rdx, 32, 0, true),
        "dx" => RegisterSpec::new("dx", BaseReg::Rdx, 16, 0, false),
        "dl" => RegisterSpec::new("dl", BaseReg::Rdx, 8, 0, false),
        "dh" => RegisterSpec::new("dh", BaseReg::Rdx, 8, 8, false),
        // rsi/rdi/rbp/rsp families
        "rsi" => RegisterSpec::new("rsi", BaseReg::Rsi, 64, 0, false),
        "esi" => RegisterSpec::new("esi", BaseReg::Rsi, 32, 0, true),
        "si" => RegisterSpec::new("si", BaseReg::Rsi, 16, 0, false),
        "sil" => RegisterSpec::new("sil", BaseReg::Rsi, 8, 0, false),
        "rdi" => RegisterSpec::new("rdi", BaseReg::Rdi, 64, 0, false),
        "edi" => RegisterSpec::new("edi", BaseReg::Rdi, 32, 0, true),
        "di" => RegisterSpec::new("di", BaseReg::Rdi, 16, 0, false),
        "dil" => RegisterSpec::new("dil", BaseReg::Rdi, 8, 0, false),
        "rbp" => RegisterSpec::new("rbp", BaseReg::Rbp, 64, 0, false),
        "ebp" => RegisterSpec::new("ebp", BaseReg::Rbp, 32, 0, true),
        "bp" => RegisterSpec::new("bp", BaseReg::Rbp, 16, 0, false),
        "bpl" => RegisterSpec::new("bpl", BaseReg::Rbp, 8, 0, false),
        "rsp" => RegisterSpec::new("rsp", BaseReg::Rsp, 64, 0, false),
        "esp" => RegisterSpec::new("esp", BaseReg::Rsp, 32, 0, true),
        "sp" => RegisterSpec::new("sp", BaseReg::Rsp, 16, 0, false),
        "spl" => RegisterSpec::new("spl", BaseReg::Rsp, 8, 0, false),
        // r8-r15
        "r8" => RegisterSpec::new("r8", BaseReg::R8, 64, 0, false),
        "r8d" => RegisterSpec::new("r8d", BaseReg::R8, 32, 0, true),
        "r8w" => RegisterSpec::new("r8w", BaseReg::R8, 16, 0, false),
        "r8b" => RegisterSpec::new("r8b", BaseReg::R8, 8, 0, false),
        "r9" => RegisterSpec::new("r9", BaseReg::R9, 64, 0, false),
        "r9d" => RegisterSpec::new("r9d", BaseReg::R9, 32, 0, true),
        "r9w" => RegisterSpec::new("r9w", BaseReg::R9, 16, 0, false),
        "r9b" => RegisterSpec::new("r9b", BaseReg::R9, 8, 0, false),
        "r10" => RegisterSpec::new("r10", BaseReg::R10, 64, 0, false),
        "r10d" => RegisterSpec::new("r10d", BaseReg::R10, 32, 0, true),
        "r10w" => RegisterSpec::new("r10w", BaseReg::R10, 16, 0, false),
        "r10b" => RegisterSpec::new("r10b", BaseReg::R10, 8, 0, false),
        "r11" => RegisterSpec::new("r11", BaseReg::R11, 64, 0, false),
        "r11d" => RegisterSpec::new("r11d", BaseReg::R11, 32, 0, true),
        "r11w" => RegisterSpec::new("r11w", BaseReg::R11, 16, 0, false),
        "r11b" => RegisterSpec::new("r11b", BaseReg::R11, 8, 0, false),
        "r12" => RegisterSpec::new("r12", BaseReg::R12, 64, 0, false),
        "r12d" => RegisterSpec::new("r12d", BaseReg::R12, 32, 0, true),
        "r12w" => RegisterSpec::new("r12w", BaseReg::R12, 16, 0, false),
        "r12b" => RegisterSpec::new("r12b", BaseReg::R12, 8, 0, false),
        "r13" => RegisterSpec::new("r13", BaseReg::R13, 64, 0, false),
        "r13d" => RegisterSpec::new("r13d", BaseReg::R13, 32, 0, true),
        "r13w" => RegisterSpec::new("r13w", BaseReg::R13, 16, 0, false),
        "r13b" => RegisterSpec::new("r13b", BaseReg::R13, 8, 0, false),
        "r14" => RegisterSpec::new("r14", BaseReg::R14, 64, 0, false),
        "r14d" => RegisterSpec::new("r14d", BaseReg::R14, 32, 0, true),
        "r14w" => RegisterSpec::new("r14w", BaseReg::R14, 16, 0, false),
        "r14b" => RegisterSpec::new("r14b", BaseReg::R14, 8, 0, false),
        "r15" => RegisterSpec::new("r15", BaseReg::R15, 64, 0, false),
        "r15d" => RegisterSpec::new("r15d", BaseReg::R15, 32, 0, true),
        "r15w" => RegisterSpec::new("r15w", BaseReg::R15, 16, 0, false),
        "r15b" => RegisterSpec::new("r15b", BaseReg::R15, 8, 0, false),
        // pc and flags
        "rip" => RegisterSpec::new("rip", BaseReg::Rip, 64, 0, false),
        "rflags" => RegisterSpec::new("rflags", BaseReg::Rflags, 64, 0, false),
        "eflags" => RegisterSpec::new("eflags", BaseReg::Rflags, 32, 0, false),
        _ => {
            if name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
                let lower = name.to_ascii_lowercase();
                return spec_by_name(lower.as_str());
            }
            return None;
        }
    };

    Some(spec)
}

/// Read full 64-bit value of a canonical base register from Linux `user_regs_struct`.
fn base_value(regs: &user_regs_struct, base: BaseReg) -> u64 {
    match base {
        BaseReg::Rax => regs.rax,
        BaseReg::Rbx => regs.rbx,
        BaseReg::Rcx => regs.rcx,
        BaseReg::Rdx => regs.rdx,
        BaseReg::Rsi => regs.rsi,
        BaseReg::Rdi => regs.rdi,
        BaseReg::Rbp => regs.rbp,
        BaseReg::Rsp => regs.rsp,
        BaseReg::R8 => regs.r8,
        BaseReg::R9 => regs.r9,
        BaseReg::R10 => regs.r10,
        BaseReg::R11 => regs.r11,
        BaseReg::R12 => regs.r12,
        BaseReg::R13 => regs.r13,
        BaseReg::R14 => regs.r14,
        BaseReg::R15 => regs.r15,
        BaseReg::Rip => regs.rip,
        BaseReg::Rflags => regs.eflags,
    }
}

/// Write full 64-bit value of a canonical base register into Linux `user_regs_struct`.
fn set_base_value(regs: &mut user_regs_struct, base: BaseReg, value: u64) {
    match base {
        BaseReg::Rax => regs.rax = value,
        BaseReg::Rbx => regs.rbx = value,
        BaseReg::Rcx => regs.rcx = value,
        BaseReg::Rdx => regs.rdx = value,
        BaseReg::Rsi => regs.rsi = value,
        BaseReg::Rdi => regs.rdi = value,
        BaseReg::Rbp => regs.rbp = value,
        BaseReg::Rsp => regs.rsp = value,
        BaseReg::R8 => regs.r8 = value,
        BaseReg::R9 => regs.r9 = value,
        BaseReg::R10 => regs.r10 = value,
        BaseReg::R11 => regs.r11 = value,
        BaseReg::R12 => regs.r12 = value,
        BaseReg::R13 => regs.r13 = value,
        BaseReg::R14 => regs.r14 = value,
        BaseReg::R15 => regs.r15 = value,
        BaseReg::Rip => regs.rip = value,
        BaseReg::Rflags => regs.eflags = value,
    }
}

/// Build a `bits`-wide low-bit mask.
fn bit_mask(bits: u8) -> u64 {
    match bits {
        64 => u64::MAX,
        0 => 0,
        n => (1_u64 << n) - 1,
    }
}

/// Extract `bits` at offset `lsb` from a raw 64-bit base value.
fn extract_value(raw: u64, bits: u8, lsb: u8) -> u64 {
    let mask = bit_mask(bits);
    (raw >> lsb) & mask
}

/// Read one register alias from a Linux `user_regs_struct`.
///
/// Examples:
/// - `read_register(regs, "rax")` -> full 64-bit accumulator.
/// - `read_register(regs, "ah")` -> bits `8..15` of `rax`.
/// - `read_register(regs, "rip")` -> current instruction pointer.
pub fn read_register(regs: &user_regs_struct, name: &str) -> Result<RegisterValue, DebugError> {
    let spec = spec_by_name(name).ok_or_else(|| DebugError::UnknownRegister(name.to_string()))?;
    let raw = base_value(regs, spec.base);
    Ok(RegisterValue {
        name: spec.name,
        bits: spec.bits,
        value: extract_value(raw, spec.bits, spec.lsb),
    })
}

/// Write one register alias in a Linux `user_regs_struct`.
///
/// Semantics follow x86-64 rules:
/// - 64-bit alias write (for example `rax`) replaces the whole base register.
/// - 32-bit alias write with `zero_extend_64=true` (for example `eax`) clears upper 32 bits.
/// - Partial aliases (for example `ah`, `al`, `ax`) update only their bit range.
pub fn write_register(
    regs: &mut user_regs_struct,
    name: &str,
    value: u64,
) -> Result<RegisterValue, DebugError> {
    let spec = spec_by_name(name).ok_or_else(|| DebugError::UnknownRegister(name.to_string()))?;

    let mask = bit_mask(spec.bits);
    let truncated = value & mask;
    let raw = base_value(regs, spec.base);

    let whole_register_write = (spec.zero_extend_64 && spec.bits == 32 && spec.lsb == 0)
        || (spec.bits == 64 && spec.lsb == 0);
    let updated = if whole_register_write {
        truncated
    } else {
        let field_mask = mask << spec.lsb;
        (raw & !field_mask) | (truncated << spec.lsb)
    };

    set_base_value(regs, spec.base, updated);

    Ok(RegisterValue {
        name: spec.name,
        bits: spec.bits,
        value: extract_value(updated, spec.bits, spec.lsb),
    })
}

/// Read the canonical 64-bit GPR set (`rax..r15`, `rip`, `rflags`).
///
/// This intentionally returns canonical base registers only (not every alias).
pub fn read_all_gpr(regs: &user_regs_struct) -> Vec<RegisterValue> {
    let mut out = Vec::with_capacity(CANONICAL_GPRS.len());
    for spec in CANONICAL_GPRS {
        let raw = base_value(regs, spec.base);
        out.push(RegisterValue {
            name: spec.name,
            bits: spec.bits,
            value: raw,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{read_register, write_register};

    fn empty_regs() -> nix::libc::user_regs_struct {
        // SAFETY: all fields are integer scalars, zero is a valid bit pattern.
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn eax_write_zero_extends_rax() {
        let mut regs = empty_regs();
        regs.rax = 0xFFFF_0000_1111_2222;

        write_register(&mut regs, "eax", 0xAABB_CCDD).expect("eax write should work");

        let rax = read_register(&regs, "rax").expect("rax read should work");
        assert_eq!(rax.value, 0x0000_0000_AABB_CCDD);
    }

    #[test]
    fn ah_write_updates_only_high_byte_of_low_word() {
        let mut regs = empty_regs();
        regs.rax = 0x1122_3344_5566_7788;

        write_register(&mut regs, "ah", 0xAB).expect("ah write should work");

        let rax = read_register(&regs, "rax").expect("rax read should work");
        assert_eq!(rax.value, 0x1122_3344_5566_AB88);
    }

    #[test]
    fn read_aliases_match_expected_slices() {
        let mut regs = empty_regs();
        regs.rax = 0x1122_3344_5566_7788;

        assert_eq!(read_register(&regs, "eax").expect("eax").value, 0x5566_7788);
        assert_eq!(read_register(&regs, "ax").expect("ax").value, 0x7788);
        assert_eq!(read_register(&regs, "al").expect("al").value, 0x88);
        assert_eq!(read_register(&regs, "ah").expect("ah").value, 0x77);
    }

    #[test]
    fn unknown_register_fails() {
        let regs = empty_regs();
        let err = read_register(&regs, "totally_fake_reg").expect_err("must fail");
        assert!(err.to_string().contains("unknown register"));
    }
}
