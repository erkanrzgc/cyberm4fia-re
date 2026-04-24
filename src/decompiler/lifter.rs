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
use crate::disasm::control_flow::Instruction;

/// Lift a single detected function into an AST function.
///
/// The body preserves original instruction order and addresses. The return
/// type defaults to `void` and the parameter list is empty — signatures are
/// reconstructed by later analysis passes once calling-convention recovery
/// lands.
pub fn lift_function(info: &FunctionInfo) -> Function {
    let body: Vec<Statement> = info
        .instructions
        .iter()
        .map(instruction_to_statement)
        .collect();

    Function {
        name: info.name.clone(),
        return_type: TypeInfo::Void,
        parameters: Vec::new(),
        body,
        is_variadic: false,
    }
}

/// Lift a slice of detected functions.
pub fn lift_functions(infos: &[FunctionInfo]) -> Vec<Function> {
    infos.iter().map(lift_function).collect()
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
