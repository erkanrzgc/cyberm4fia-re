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
use crate::binary::parser::ImportAddressInfo;
use crate::decompiler::ast::{Expression, Function, Statement};
use crate::decompiler::c_syntax::{sanitize_c_identifier, unique_c_identifier};
use crate::disasm::control_flow::Instruction;
use std::collections::BTreeSet;
use std::collections::HashMap;

/// C declaration metadata for one imported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFunctionDeclaration {
    pub library: String,
    pub function: String,
    pub address: u64,
    pub ordinal: Option<u16>,
    pub c_name: String,
}

/// Lift a single detected function into an AST function.
///
/// The body preserves original instruction order and addresses. The return
/// type defaults to `void` and the parameter list is empty — signatures are
/// reconstructed by later analysis passes once calling-convention recovery
/// lands.
pub fn lift_function(info: &FunctionInfo) -> Function {
    let fallback = format!("sub_{:X}", info.address);
    lift_function_with_name(
        info,
        sanitize_c_identifier(&info.name, &fallback),
        &HashMap::new(),
    )
}

/// Lift a slice of detected functions.
pub fn lift_functions(infos: &[FunctionInfo]) -> Vec<Function> {
    lift_functions_with_imports(infos, &[])
}

/// Lift detected functions and resolve known import-address call targets.
pub fn lift_functions_with_imports(
    infos: &[FunctionInfo],
    imports: &[ImportAddressInfo],
) -> Vec<Function> {
    let mut used_names = BTreeSet::new();
    let mut resolved_names = Vec::with_capacity(infos.len());

    for info in infos {
        let fallback = format!("sub_{:X}", info.address);
        let unique_name = unique_c_identifier(&info.name, &fallback, &mut used_names);
        resolved_names.push((info.address, unique_name));
    }

    let mut call_targets: HashMap<u64, String> = resolved_names.iter().cloned().collect();
    call_targets.extend(import_call_targets(imports));

    infos
        .iter()
        .zip(resolved_names)
        .map(|(info, (_, unique_name))| lift_function_with_name(info, unique_name, &call_targets))
        .collect()
}

/// Build C-safe import declarations in the same naming scheme used by the lifter.
pub fn import_function_declarations(
    imports: &[ImportAddressInfo],
) -> Vec<ImportFunctionDeclaration> {
    let mut used_names = BTreeSet::new();
    imports
        .iter()
        .map(|import| {
            let fallback = format!("import_{:X}", import.address);
            ImportFunctionDeclaration {
                library: import.library.clone(),
                function: import.function.clone(),
                address: import.address,
                ordinal: import.ordinal,
                c_name: unique_c_identifier(&import.function, &fallback, &mut used_names),
            }
        })
        .collect()
}

fn import_call_targets(imports: &[ImportAddressInfo]) -> HashMap<u64, String> {
    import_function_declarations(imports)
        .into_iter()
        .map(|declaration| (declaration.address, declaration.c_name))
        .collect()
}

fn lift_function_with_name(
    info: &FunctionInfo,
    name: String,
    call_targets: &HashMap<u64, String>,
) -> Function {
    let body: Vec<Statement> = info
        .instructions
        .iter()
        .map(|instruction| instruction_to_statement(instruction, call_targets))
        .collect();

    Function {
        name,
        return_type: TypeInfo::Void,
        parameters: Vec::new(),
        body,
        is_variadic: false,
    }
}

fn instruction_to_statement(instr: &Instruction, call_targets: &HashMap<u64, String>) -> Statement {
    if let Some(function) = call_target_name(instr, call_targets) {
        return Statement::Expression(Expression::FunctionCall {
            function,
            arguments: Vec::new(),
        });
    }

    let (address, disasm) = match instr {
        Instruction::X86(x) => (x.address, x.to_string()),
        Instruction::Arm(a) => (a.address, a.to_string()),
    };
    Statement::InlineAsm { address, disasm }
}

fn call_target_name(instr: &Instruction, call_targets: &HashMap<u64, String>) -> Option<String> {
    match instr {
        Instruction::X86(x) if x.is_call() => {
            if let Some(target) = x.near_branch_target {
                if let Some(name) = call_targets.get(&target) {
                    return Some(name.clone());
                }
            }

            let target = referenced_memory_address(x.address, x.length, &x.operands)?;
            call_targets.get(&target).cloned()
        }
        _ => None,
    }
}

fn referenced_memory_address(address: u64, length: usize, operands: &str) -> Option<u64> {
    if !operands.contains('[') || !operands.contains(']') {
        return None;
    }

    let lower = operands.to_ascii_lowercase();
    let first_hex = collect_hex_addresses(operands).into_iter().next()?;

    if lower.contains("rip+") || lower.contains("rip +") {
        Some(address.wrapping_add(length as u64).wrapping_add(first_hex))
    } else if lower.contains("rip-") || lower.contains("rip -") {
        Some(address.wrapping_add(length as u64).wrapping_sub(first_hex))
    } else {
        Some(first_hex)
    }
}

fn collect_hex_addresses(text: &str) -> Vec<u64> {
    text.split(|ch: char| {
        !(ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X' || ch == 'h' || ch == 'H')
    })
    .filter_map(parse_hex_token)
    .collect()
}

fn parse_hex_token(token: &str) -> Option<u64> {
    if token.len() < 2 {
        return None;
    }

    let stripped = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .or_else(|| token.strip_suffix('h'))
        .or_else(|| token.strip_suffix('H'))?;

    if stripped.is_empty() || !stripped.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }

    u64::from_str_radix(stripped, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::parser::ImportAddressInfo;
    use crate::disasm::X86Instruction;

    fn x86_instr(address: u64, mnemonic: &str, operands: &str) -> Instruction {
        x86_instr_with_len(address, mnemonic, operands, 1)
    }

    fn x86_instr_with_len(
        address: u64,
        mnemonic: &str,
        operands: &str,
        length: usize,
    ) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: vec![0x90; length],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length,
            near_branch_target: None,
        })
    }

    fn import_address(library: &str, function: &str, address: u64) -> ImportAddressInfo {
        ImportAddressInfo {
            library: library.to_string(),
            function: function.to_string(),
            address,
            ordinal: None,
        }
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

    #[test]
    fn lift_functions_turns_direct_x86_calls_into_function_call_statements() {
        let caller = FunctionInfo {
            name: "sub_1000".to_string(),
            address: 0x1000,
            size: 5,
            instructions: vec![Instruction::X86(X86Instruction {
                address: 0x1000,
                bytes: vec![0xE8, 0, 0, 0, 0],
                mnemonic: "call".to_string(),
                operands: "2000h".to_string(),
                length: 5,
                near_branch_target: Some(0x2000),
            })],
            is_import: false,
            is_export: false,
        };
        let callee = FunctionInfo {
            name: "sub_2000".to_string(),
            address: 0x2000,
            size: 1,
            instructions: vec![x86_instr(0x2000, "ret", "")],
            is_import: false,
            is_export: false,
        };

        let funcs = lift_functions(&[caller, callee]);

        assert!(matches!(
            &funcs[0].body[0],
            Statement::Expression(crate::decompiler::ast::Expression::FunctionCall {
                function,
                arguments
            }) if function == "sub_2000" && arguments.is_empty()
        ));
    }

    #[test]
    fn lift_functions_turns_indirect_iat_calls_into_import_calls() {
        let caller = FunctionInfo {
            name: "sub_1000".to_string(),
            address: 0x1000,
            size: 6,
            instructions: vec![x86_instr(0x1000, "call", "qword ptr [3000h]")],
            is_import: false,
            is_export: false,
        };
        let imports = vec![import_address("kernel32.dll", "CreateFileW", 0x3000)];

        let funcs = lift_functions_with_imports(&[caller], &imports);

        assert!(matches!(
            &funcs[0].body[0],
            Statement::Expression(crate::decompiler::ast::Expression::FunctionCall {
                function,
                arguments
            }) if function == "CreateFileW" && arguments.is_empty()
        ));
    }

    #[test]
    fn lift_functions_turns_rip_relative_iat_calls_into_import_calls() {
        let caller = FunctionInfo {
            name: "sub_1000".to_string(),
            address: 0x1000,
            size: 6,
            instructions: vec![x86_instr_with_len(
                0x1000,
                "call",
                "qword ptr [rip+1FFAh]",
                6,
            )],
            is_import: false,
            is_export: false,
        };
        let imports = vec![import_address("kernel32.dll", "GetProcAddress", 0x3000)];

        let funcs = lift_functions_with_imports(&[caller], &imports);

        assert!(matches!(
            &funcs[0].body[0],
            Statement::Expression(crate::decompiler::ast::Expression::FunctionCall {
                function,
                arguments
            }) if function == "GetProcAddress" && arguments.is_empty()
        ));
    }

    #[test]
    fn import_function_declarations_sanitize_and_deduplicate_names() {
        let imports = vec![
            import_address("kernel32.dll", "CreateFileW", 0x3000),
            import_address("custom.dll", "CreateFileW", 0x3010),
            import_address("odd.dll", "123 bad-name", 0x3020),
        ];

        let declarations = import_function_declarations(&imports);

        assert_eq!(
            declarations
                .iter()
                .map(|decl| decl.c_name.as_str())
                .collect::<Vec<_>>(),
            vec!["CreateFileW", "CreateFileW_2", "import_3020_123_bad_name"]
        );
    }
}
