//! Type inference for variables and expressions

use crate::disasm::Instruction;
use std::collections::HashMap;

/// Type information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeInfo {
    /// Void type
    Void,
    /// Boolean
    Bool,
    /// 8-bit signed integer
    I8,
    /// 8-bit unsigned integer
    U8,
    /// 16-bit signed integer
    I16,
    /// 16-bit unsigned integer
    U16,
    /// 32-bit signed integer
    I32,
    /// 32-bit unsigned integer
    U32,
    /// 64-bit signed integer
    I64,
    /// 64-bit unsigned integer
    U64,
    /// Pointer
    Pointer(Box<TypeInfo>),
    /// Array
    Array(Box<TypeInfo>, usize),
    /// Function pointer
    FunctionPointer {
        params: Vec<TypeInfo>,
        return_type: Box<TypeInfo>,
    },
    /// Unknown
    Unknown,
}

impl TypeInfo {
    /// Get the C type name
    pub fn to_c_type(&self) -> &'static str {
        match self {
            TypeInfo::Void => "void",
            TypeInfo::Bool => "bool",
            TypeInfo::I8 => "int8_t",
            TypeInfo::U8 => "uint8_t",
            TypeInfo::I16 => "int16_t",
            TypeInfo::U16 => "uint16_t",
            TypeInfo::I32 => "int32_t",
            TypeInfo::U32 => "uint32_t",
            TypeInfo::I64 => "int64_t",
            TypeInfo::U64 => "uint64_t",
            TypeInfo::Pointer(inner) => match inner.as_ref() {
                TypeInfo::Void => "void*",
                TypeInfo::I8 => "char*",
                TypeInfo::U8 => "unsigned char*",
                _ => "void*", // Conservative default
            },
            TypeInfo::Array(inner, _size) => match inner.as_ref() {
                TypeInfo::I8 => "char[]",
                TypeInfo::U8 => "unsigned char[]",
                _ => "void[]",
            },
            TypeInfo::FunctionPointer { .. } => "void(*)()",
            TypeInfo::Unknown => "void*",
        }
    }

    /// Check if this is an integer type
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            TypeInfo::I8
                | TypeInfo::U8
                | TypeInfo::I16
                | TypeInfo::U16
                | TypeInfo::I32
                | TypeInfo::U32
                | TypeInfo::I64
                | TypeInfo::U64
        )
    }

    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        matches!(self, TypeInfo::Pointer(_) | TypeInfo::Unknown)
    }

    /// Get the size in bytes
    pub fn size(&self) -> usize {
        match self {
            TypeInfo::Void => 0,
            TypeInfo::Bool => 1,
            TypeInfo::I8 | TypeInfo::U8 => 1,
            TypeInfo::I16 | TypeInfo::U16 => 2,
            TypeInfo::I32 | TypeInfo::U32 => 4,
            TypeInfo::I64 | TypeInfo::U64 => 8,
            TypeInfo::Pointer(_) => 8, // Assume 64-bit
            TypeInfo::Array(inner, size) => inner.size() * size,
            TypeInfo::FunctionPointer { .. } => 8,
            TypeInfo::Unknown => 8,
        }
    }
}

/// Type inference engine
pub struct TypeInference {
    /// Known types for registers/variables
    known_types: HashMap<String, TypeInfo>,
}

impl TypeInference {
    /// Create a new type inference engine
    pub fn new() -> Self {
        Self {
            known_types: HashMap::new(),
        }
    }

    /// Infer type from instruction
    pub fn infer_from_instruction(&mut self, instr: &Instruction) -> TypeInfo {
        match instr {
            Instruction::X86(x86_instr) => self.infer_from_x86(x86_instr),
            Instruction::Arm(arm_instr) => self.infer_from_arm(arm_instr),
        }
    }

    /// Infer type from x86 instruction
    fn infer_from_x86(&mut self, instr: &crate::disasm::X86Instruction) -> TypeInfo {
        let mnemonic = instr.mnemonic.to_lowercase();

        // MOV instructions with immediate values
        if mnemonic == "mov" {
            if let Some(value) = self.parse_immediate(&instr.operands) {
                return self.infer_from_immediate(value);
            }
        }

        // Pointer operations
        if mnemonic.contains("lea") || mnemonic.contains("ptr") {
            return TypeInfo::Pointer(Box::new(TypeInfo::Void));
        }

        TypeInfo::Unknown
    }

    /// Infer type from ARM instruction
    fn infer_from_arm(&mut self, instr: &crate::disasm::ArmInstruction) -> TypeInfo {
        let mnemonic = instr.mnemonic.to_lowercase();

        // MOV instructions with immediate values
        if mnemonic == "mov" || mnemonic == "movz" || mnemonic == "movk" {
            if let Some(value) = self.parse_immediate(&instr.operands) {
                return self.infer_from_immediate(value);
            }
        }

        // Load instructions
        if mnemonic.starts_with("ldr") {
            return TypeInfo::Pointer(Box::new(TypeInfo::Void));
        }

        TypeInfo::Unknown
    }

    /// Infer type from immediate value
    fn infer_from_immediate(&self, value: u64) -> TypeInfo {
        if value <= 0xFF {
            TypeInfo::U8
        } else if value <= 0xFFFF {
            TypeInfo::U16
        } else if value <= 0xFFFFFFFF {
            TypeInfo::U32
        } else {
            TypeInfo::U64
        }
    }

    /// Parse immediate value from operand string
    fn parse_immediate(&self, operands: &str) -> Option<u64> {
        // Look for hex addresses like 0x1234
        let re = regex::Regex::new(r"0[xX]([0-9A-Fa-f]+)").ok()?;
        if let Some(caps) = re.captures(operands) {
            let hex = caps.get(1)?.as_str();
            u64::from_str_radix(hex, 16).ok()
        } else {
            // Try to parse decimal
            operands.trim().parse().ok()
        }
    }

    /// Set a known type for a variable
    pub fn set_type(&mut self, name: String, type_info: TypeInfo) {
        self.known_types.insert(name, type_info);
    }

    /// Get the type for a variable
    pub fn get_type(&self, name: &str) -> Option<&TypeInfo> {
        self.known_types.get(name)
    }
}

impl Default for TypeInference {
    fn default() -> Self {
        Self::new()
    }
}
