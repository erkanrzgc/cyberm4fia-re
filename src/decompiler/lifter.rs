//! Bridge from disassembly-level `FunctionInfo` to AST-level `ast::Function`.
//!
//! This is the *minimum honest lift*. We produce a well-typed `ast::Function`
//! whose body is one `InlineAsm` statement per input instruction. No
//! structuring, no type recovery, no parameter inference — those belong to
//! later passes. The point is to have a single well-defined seam between
//! `analysis::FunctionInfo` (what we discovered) and `decompiler::CGenerator`
//! (what we emit), so downstream passes can iterate on the AST rather than on
//! raw instruction lists.

use crate::analysis::{FunctionInfo, TypeInfo};
use crate::decompiler::ast::{Function, Statement};
use crate::decompiler::c_syntax::{sanitize_c_identifier, unique_c_identifier};
use crate::disasm::control_flow::Instruction;
use std::collections::BTreeSet;

/// Lift a single detected function into an AST function.
///
/// The body preserves original instruction order and addresses. The return
/// type defaults to `void` and the parameter list is empty — signatures are
/// reconstructed by later analysis passes once calling-convention recovery
/// lands.
pub fn lift_function(info: &FunctionInfo) -> Function {
    let fallback = format!("sub_{:X}", info.address);
    lift_function_with_name(info, sanitize_c_identifier(&info.name, &fallback))
}

/// Lift a slice of detected functions.
pub fn lift_functions(infos: &[FunctionInfo]) -> Vec<Function> {
    let mut used_names = BTreeSet::new();

    infos
        .iter()
        .map(|info| {
            let fallback = format!("sub_{:X}", info.address);
            let unique_name = unique_c_identifier(&info.name, &fallback, &mut used_names);
            lift_function_with_name(info, unique_name)
        })
        .collect()
}

fn lift_function_with_name(info: &FunctionInfo, name: String) -> Function {
    let body: Vec<Statement> = info
        .instructions
        .iter()
        .map(instruction_to_statement)
        .collect();

    Function {
        name,
        return_type: TypeInfo::Void,
        parameters: Vec::new(),
        body,
        is_variadic: false,
    }
}

fn instruction_to_statement(instr: &Instruction) -> Statement {
    let (address, disasm) = match instr {
        Instruction::X86(x) => (x.address, x.to_string()),
        Instruction::Arm(a) => (a.address, a.to_string()),
    };
    Statement::InlineAsm { address, disasm }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::X86Instruction;

    fn x86_instr(address: u64, mnemonic: &str, operands: &str) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length: 1,
            near_branch_target: None,
        })
    }

    #[test]
    fn lifted_function_preserves_name_and_instruction_order() {
        let info = FunctionInfo {
            name: "my_func".to_string(),
            address: 0x1000,
            size: 3,
            instructions: vec![
                x86_instr(0x1000, "push", "rbp"),
                x86_instr(0x1001, "mov", "rbp, rsp"),
                x86_instr(0x1004, "ret", ""),
            ],
            is_import: false,
            is_export: false,
        };

        let func = lift_function(&info);
        assert_eq!(func.name, "my_func");
        assert_eq!(func.return_type, TypeInfo::Void);
        assert!(func.parameters.is_empty());
        assert_eq!(func.body.len(), 3);

        // Body order matches instruction order, and each carries its address.
        let addrs: Vec<u64> = func
            .body
            .iter()
            .filter_map(|s| match s {
                Statement::InlineAsm { address, .. } => Some(*address),
                _ => None,
            })
            .collect();
        assert_eq!(addrs, vec![0x1000, 0x1001, 0x1004]);
    }

    #[test]
    fn inline_asm_payload_includes_operands_when_present() {
        let info = FunctionInfo {
            name: "f".to_string(),
            address: 0x2000,
            size: 1,
            instructions: vec![x86_instr(0x2000, "mov", "rax, 1")],
            is_import: false,
            is_export: false,
        };

        let func = lift_function(&info);
        match &func.body[0] {
            Statement::InlineAsm { address, disasm } => {
                assert_eq!(*address, 0x2000);
                assert_eq!(disasm, "mov rax, 1");
            }
            other => panic!("expected InlineAsm, got {:?}", other),
        }
    }

    #[test]
    fn lift_function_sanitizes_invalid_c_identifier_names() {
        let info = FunctionInfo {
            name: "kernel32.dll!CreateFileW".to_string(),
            address: 0x4000,
            size: 0,
            instructions: vec![],
            is_import: false,
            is_export: true,
        };

        let func = lift_function(&info);
        assert_eq!(func.name, "kernel32_dll_CreateFileW");
    }

    #[test]
    fn lift_function_uses_address_fallback_for_empty_sanitized_name() {
        let info = FunctionInfo {
            name: "!!!".to_string(),
            address: 0x4010,
            size: 0,
            instructions: vec![],
            is_import: false,
            is_export: false,
        };

        let func = lift_function(&info);
        assert_eq!(func.name, "sub_4010");
    }

    #[test]
    fn lift_function_avoids_keywords_and_leading_digits() {
        let keyword = FunctionInfo {
            name: "return".to_string(),
            address: 0x5000,
            size: 0,
            instructions: vec![],
            is_import: false,
            is_export: false,
        };
        let leading_digit = FunctionInfo {
            name: "123abc".to_string(),
            address: 0x5001,
            size: 0,
            instructions: vec![],
            is_import: false,
            is_export: false,
        };

        assert_eq!(lift_function(&keyword).name, "return_");
        assert_eq!(lift_function(&leading_digit).name, "sub_5001_123abc");
    }

    #[test]
    fn lift_functions_uniquifies_sanitized_name_collisions() {
        let infos = vec![
            FunctionInfo {
                name: "foo-bar".to_string(),
                address: 0x6000,
                size: 0,
                instructions: vec![],
                is_import: false,
                is_export: false,
            },
            FunctionInfo {
                name: "foo_bar".to_string(),
                address: 0x6001,
                size: 0,
                instructions: vec![],
                is_import: false,
                is_export: false,
            },
            FunctionInfo {
                name: "foo bar".to_string(),
                address: 0x6002,
                size: 0,
                instructions: vec![],
                is_import: false,
                is_export: false,
            },
        ];

        let funcs = lift_functions(&infos);
        assert_eq!(
            funcs.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            vec!["foo_bar", "foo_bar_2", "foo_bar_3"]
        );
    }

    #[test]
    fn empty_instruction_list_produces_empty_body() {
        let info = FunctionInfo {
            name: "empty".to_string(),
            address: 0x3000,
            size: 0,
            instructions: vec![],
            is_import: false,
            is_export: false,
        };

        let func = lift_function(&info);
        assert!(func.body.is_empty());
    }

    #[test]
    fn lift_functions_preserves_order() {
        let infos = vec![
            FunctionInfo {
                name: "a".to_string(),
                address: 0x1000,
                size: 0,
                instructions: vec![],
                is_import: false,
                is_export: false,
            },
            FunctionInfo {
                name: "b".to_string(),
                address: 0x2000,
                size: 0,
                instructions: vec![],
                is_import: false,
                is_export: false,
            },
        ];
        let funcs = lift_functions(&infos);
        assert_eq!(
            funcs.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }
}
