//! Conservative function signature recovery.

use crate::analysis::{FunctionInfo, TypeInfo};
use crate::decompiler::ast::{Expression, Function, Parameter, Statement};
use crate::disasm::control_flow::Instruction;
use std::collections::BTreeSet;

/// Recover simple ABI-level function signatures and return values in place.
pub fn recover_function_signatures(
    functions: &mut [Function],
    infos: &[FunctionInfo],
    format: &str,
    architecture: &str,
) {
    for (function, info) in functions.iter_mut().zip(infos.iter()) {
        if function.parameters.is_empty() {
            function.parameters = infer_parameters(info, format, architecture);
        }
        recover_rax_return(function);
    }
}

fn infer_parameters(info: &FunctionInfo, format: &str, architecture: &str) -> Vec<Parameter> {
    let Some(arg_registers) = argument_registers(format, architecture) else {
        return Vec::new();
    };

    let mut written = BTreeSet::new();
    let mut used = BTreeSet::new();

    for instruction in info.instructions.iter().take(32) {
        if instruction.is_call() || instruction.is_return() {
            break;
        }
        let Some((mnemonic, operands)) = x86_parts(instruction) else {
            continue;
        };
        let operands = split_operands(operands);
        let dest = operands.first().copied();

        for register in read_registers(&mnemonic, &operands) {
            if arg_registers.contains(&register.as_str()) && !written.contains(&register) {
                used.insert(register);
            }
        }

        if writes_destination(&mnemonic) {
            if let Some(dest) = dest.and_then(register_in_operand) {
                written.insert(dest);
            }
        }
    }

    arg_registers
        .iter()
        .filter(|register| used.contains(**register))
        .map(|register| Parameter {
            name: (*register).to_string(),
            type_info: TypeInfo::U64,
        })
        .collect()
}

fn argument_registers(format: &str, architecture: &str) -> Option<&'static [&'static str]> {
    match (format, architecture) {
        ("PE/EXE", "x64") => Some(&["rcx", "rdx", "r8", "r9"]),
        (_, "x64") => Some(&["rdi", "rsi", "rdx", "rcx", "r8", "r9"]),
        _ => None,
    }
}

fn x86_parts(instruction: &Instruction) -> Option<(String, &str)> {
    let Instruction::X86(instruction) = instruction else {
        return None;
    };
    Some((
        instruction.mnemonic.to_ascii_lowercase(),
        instruction.operands.as_str(),
    ))
}

fn split_operands(operands: &str) -> Vec<&str> {
    operands
        .split(',')
        .map(str::trim)
        .filter(|operand| !operand.is_empty())
        .collect()
}

fn read_registers(mnemonic: &str, operands: &[&str]) -> Vec<String> {
    if mnemonic == "xor" && operands.len() == 2 && operands[0].eq_ignore_ascii_case(operands[1]) {
        return Vec::new();
    }

    let read_operands: &[&str] = match mnemonic {
        "mov" | "movzx" | "movsxd" | "lea" if operands.len() >= 2 => &operands[1..],
        "cmp" | "test" => operands,
        "add" | "sub" | "and" | "or" | "xor" | "imul" => operands,
        _ => operands,
    };

    read_operands
        .iter()
        .filter_map(|operand| register_in_operand(operand))
        .collect()
}

fn writes_destination(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov" | "movzx" | "movsxd" | "lea" | "xor" | "add" | "sub" | "and" | "or" | "imul"
    )
}

fn register_in_operand(operand: &str) -> Option<String> {
    let cleaned = operand
        .trim()
        .trim_start_matches("byte ptr ")
        .trim_start_matches("word ptr ")
        .trim_start_matches("dword ptr ")
        .trim_start_matches("qword ptr ");
    let token = cleaned
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .find(|part| !part.is_empty())?;
    canonical_register(token)
}

fn canonical_register(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let canonical = match lower.as_str() {
        "al" | "ah" | "ax" | "eax" | "rax" => "rax",
        "bl" | "bh" | "bx" | "ebx" | "rbx" => "rbx",
        "cl" | "ch" | "cx" | "ecx" | "rcx" => "rcx",
        "dl" | "dh" | "dx" | "edx" | "rdx" => "rdx",
        "sil" | "si" | "esi" | "rsi" => "rsi",
        "dil" | "di" | "edi" | "rdi" => "rdi",
        "r8b" | "r8w" | "r8d" | "r8" => "r8",
        "r9b" | "r9w" | "r9d" | "r9" => "r9",
        _ => return None,
    };
    Some(canonical.to_string())
}

fn recover_rax_return(function: &mut Function) {
    for idx in 1..function.body.len() {
        if !matches!(function.body[idx], Statement::Return(None)) {
            continue;
        }
        if previous_statement_assigns_rax(&function.body[idx - 1]) {
            function.return_type = TypeInfo::U64;
            function.body[idx] = Statement::Return(Some(Expression::Variable("rax".to_string())));
        }
    }
}

fn previous_statement_assigns_rax(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::Expression(Expression::Assignment { target, .. })
            if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
    )
}
