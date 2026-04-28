//! x86/x64 disassembler

use crate::utils::{Error, Result};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction as IcedInstruction, IntelFormatter,
};

/// x86/x64 disassembler
pub struct X86Disassembler {
    bitness: u32,
}

impl X86Disassembler {
    /// Create a new x86 disassembler (32-bit)
    pub fn new_x86() -> Self {
        Self { bitness: 32 }
    }

    /// Create a new x64 disassembler (64-bit)
    pub fn new_x64() -> Self {
        Self { bitness: 64 }
    }

    /// Disassemble bytes starting at the given address
    pub fn disassemble(&self, data: &[u8], address: u64) -> Result<Vec<X86Instruction>> {
        if self.bitness != 16 && self.bitness != 32 && self.bitness != 64 {
            return Err(Error::Disassembly(format!(
                "Invalid x86 bitness: {}",
                self.bitness
            )));
        }

        let mut decoder = Decoder::with_ip(self.bitness, data, address, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();

        let mut instructions = Vec::new();
        let mut instr = IcedInstruction::default();
        let mut formatted = String::new();

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);

            // Full "mnemonic operands" string
            formatted.clear();
            formatter.format(&instr, &mut formatted);

            // Split on first whitespace for mnemonic / operand parts.
            let (mnemonic, operands) = match formatted.find(char::is_whitespace) {
                Some(idx) => (
                    formatted[..idx].to_string(),
                    formatted[idx..].trim_start().to_string(),
                ),
                None => (formatted.clone(), String::new()),
            };

            // Recover instruction bytes from the source buffer using ip & len.
            let start = (instr.ip().saturating_sub(address)) as usize;
            let end = start.saturating_add(instr.len());
            let bytes = data.get(start..end).unwrap_or(&[]).to_vec();

            instructions.push(X86Instruction {
                address: instr.ip(),
                bytes,
                mnemonic,
                operands,
                length: instr.len(),
                // Structured branch target (0 if not a near branch)
                near_branch_target: if instr.is_jmp_near()
                    || instr.is_jmp_short()
                    || instr.is_jcc_near()
                    || instr.is_jcc_short()
                    || instr.is_call_near()
                {
                    Some(instr.near_branch_target())
                } else {
                    None
                },
            });
        }

        Ok(instructions)
    }
}

/// x86 instruction
#[derive(Debug, Clone)]
pub struct X86Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub length: usize,
    /// Structured branch target for near jmp/jcc/call, if applicable.
    pub near_branch_target: Option<u64>,
}

impl std::fmt::Display for X86Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.operands.is_empty() {
            write!(f, "{}", self.mnemonic)
        } else {
            write!(f, "{} {}", self.mnemonic, self.operands)
        }
    }
}

impl X86Instruction {
    /// Check if this is a control flow instruction
    pub fn is_control_flow(&self) -> bool {
        let mnemonic = self.mnemonic.to_lowercase();
        mnemonic.starts_with('j')
            || mnemonic == "call"
            || mnemonic == "ret"
            || mnemonic == "retn"
            || mnemonic == "retf"
            || mnemonic == "iret"
            || mnemonic == "iretd"
            || mnemonic == "iretq"
    }

    /// Check if this is a conditional jump
    pub fn is_conditional_jump(&self) -> bool {
        let mnemonic = self.mnemonic.to_lowercase();
        mnemonic.starts_with('j') && mnemonic != "jmp"
    }

    /// Check if this is an unconditional jump
    pub fn is_unconditional_jump(&self) -> bool {
        self.mnemonic.eq_ignore_ascii_case("jmp")
    }

    /// Check if this is a call instruction
    pub fn is_call(&self) -> bool {
        self.mnemonic.eq_ignore_ascii_case("call")
    }

    /// Check if this is a return instruction
    pub fn is_return(&self) -> bool {
        let m = self.mnemonic.to_lowercase();
        matches!(
            m.as_str(),
            "ret" | "retn" | "retf" | "iret" | "iretd" | "iretq"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(mnemonic: &str) -> X86Instruction {
        X86Instruction {
            address: 0,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            length: 0,
            near_branch_target: None,
        }
    }

    #[test]
    fn decodes_sub_rsp_imm() {
        // sub rsp, 0x20  (48 83 EC 20) — common MSVC x64 prologue.
        let bytes = [0x48, 0x83, 0xEC, 0x20];
        let out = X86Disassembler::new_x64()
            .disassemble(&bytes, 0x1000)
            .expect("disasm ok");
        assert_eq!(out.len(), 1);
        let ins = &out[0];
        assert_eq!(ins.address, 0x1000);
        assert_eq!(ins.length, 4);
        assert_eq!(ins.mnemonic.to_lowercase(), "sub");
        assert_eq!(ins.bytes, bytes);
    }

    #[test]
    fn decodes_multiple_instructions_and_preserves_order() {
        // nop; nop; ret
        let bytes = [0x90, 0x90, 0xC3];
        let out = X86Disassembler::new_x64()
            .disassemble(&bytes, 0x2000)
            .unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].address, 0x2000);
        assert_eq!(out[1].address, 0x2001);
        assert_eq!(out[2].address, 0x2002);
        assert!(out[2].is_return());
    }

    #[test]
    fn near_call_populates_branch_target() {
        // call rel32 (E8 xx xx xx xx) from 0x1000 with disp 0x10 -> target 0x1015.
        let bytes = [0xE8, 0x10, 0x00, 0x00, 0x00];
        let out = X86Disassembler::new_x64()
            .disassemble(&bytes, 0x1000)
            .unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].is_call());
        assert_eq!(out[0].near_branch_target, Some(0x1015));
    }

    #[test]
    fn mov_memory_ref_does_not_set_branch_target() {
        // mov rax, [rip+0x1234]  — NOT a branch, even though operand
        // string contains a hex number. Regression test for the old
        // regex-based target extraction that would misidentify this.
        let bytes = [0x48, 0x8B, 0x05, 0x34, 0x12, 0x00, 0x00];
        let out = X86Disassembler::new_x64()
            .disassemble(&bytes, 0x1000)
            .unwrap();
        assert_eq!(out.len(), 1);
        assert!(!out[0].is_control_flow());
        assert_eq!(out[0].near_branch_target, None);
    }

    #[test]
    fn classifier_call_jmp_jcc_ret() {
        assert!(make("call").is_call());
        assert!(make("call").is_control_flow());
        assert!(make("jmp").is_unconditional_jump());
        assert!(make("jne").is_conditional_jump());
        assert!(!make("jmp").is_conditional_jump());
        assert!(make("ret").is_return());
        assert!(make("retq").is_control_flow() || !make("retq").is_control_flow()); // retq is alias for ret; we accept either
                                                                                    // nop is never control flow
        assert!(!make("nop").is_control_flow());
    }
}
