//! Conservative AST structuring pass.
//!
//! The lifter intentionally starts with one `InlineAsm` statement per
//! instruction. This pass upgrades only instructions whose semantics are
//! unambiguous while preserving every other address-anchored placeholder for
//! later, richer control-flow structuring.

use crate::analysis::TypeInfo;
use crate::decompiler::ast::{BinaryOperator, Expression, Function, Statement};
use crate::disasm::{ControlFlowGraph, EdgeType};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Structure all functions in place.
pub fn structure_functions(functions: &mut [Function]) {
    for function in functions {
        structure_function(function);
    }
}

/// Structure all functions with CFG context.
pub fn structure_functions_with_cfg(functions: &mut [Function], cfg: &ControlFlowGraph) {
    for function in functions {
        structure_function_with_cfg(function, cfg);
    }
}

/// Structure a single function in place.
pub fn structure_function(function: &mut Function) {
    for statement in &mut function.body {
        structure_statement(statement);
    }
}

/// Structure a single function with CFG context.
pub fn structure_function_with_cfg(function: &mut Function, cfg: &ControlFlowGraph) {
    let original_indices = address_to_statement_index(function);
    structure_function(function);
    structure_terminal_if_else(function, cfg, &original_indices);
    insert_pseudo_register_declarations(function);
}

fn structure_statement(statement: &mut Statement) {
    match statement {
        Statement::InlineAsm { disasm, .. } if is_void_return(disasm) => {
            *statement = Statement::Return(None);
        }
        Statement::InlineAsm { disasm, .. } => {
            if let Some(assignment) = simple_assignment(disasm) {
                *statement = assignment;
            }
        }
        Statement::Block(statements) => {
            for nested in statements {
                structure_statement(nested);
            }
        }
        Statement::If {
            then_block,
            else_block,
            ..
        } => {
            for nested in then_block {
                structure_statement(nested);
            }
            if let Some(else_block) = else_block {
                for nested in else_block {
                    structure_statement(nested);
                }
            }
        }
        Statement::While { body, .. } | Statement::For { body, .. } => {
            for nested in body {
                structure_statement(nested);
            }
        }
        _ => {}
    }
}

fn is_void_return(disasm: &str) -> bool {
    let mnemonic = disasm
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    matches!(
        mnemonic.as_str(),
        "ret" | "retn" | "retf" | "iret" | "iretd" | "iretq" | "eret"
    )
}

fn simple_assignment(disasm: &str) -> Option<Statement> {
    let (mnemonic, operands) = split_instruction(disasm)?;
    let (target, value) = split_operands(&operands)?;

    let target_expr = assignment_target_expression(&target)?;
    let value_expr = match mnemonic.as_str() {
        "mov" | "movzx" | "movsxd" => operand_expression(&value)?,
        "xor" if target.eq_ignore_ascii_case(&value) => Expression::IntegerLiteral(0),
        _ => return None,
    };

    Some(Statement::Expression(Expression::Assignment {
        target: Box::new(target_expr),
        value: Box::new(value_expr),
    }))
}

fn structure_terminal_if_else(
    function: &mut Function,
    cfg: &ControlFlowGraph,
    address_to_index: &HashMap<u64, usize>,
) {
    let mut rewrites = Vec::new();

    for node in cfg.graph().node_indices() {
        let Some(block) = cfg.graph().node_weight(node) else {
            continue;
        };
        let Some(last) = block.instructions.last() else {
            continue;
        };
        if !last.is_conditional_jump() {
            continue;
        }

        let Some((true_node, false_node)) = branch_successors(cfg, node) else {
            continue;
        };
        let Some(true_block) = cfg.graph().node_weight(true_node) else {
            continue;
        };
        let Some(false_block) = cfg.graph().node_weight(false_node) else {
            continue;
        };
        let Some(branch_index) = address_to_index.get(&last.address()).copied() else {
            continue;
        };
        let head_range = (branch_index, branch_index);
        let Some(true_range) = block_range(true_block, address_to_index) else {
            continue;
        };
        let Some(false_range) = block_range(false_block, address_to_index) else {
            continue;
        };

        if block_ends_in_return(true_block) && block_ends_in_return(false_block) {
            if let Some(rewrite) =
                terminal_if_else_rewrite(function, head_range, true_range, false_range)
            {
                rewrites.push(rewrite);
            }
            continue;
        }

        if let Some(rewrite) = diamond_if_else_rewrite(
            function,
            cfg,
            head_range,
            true_node,
            true_range,
            false_node,
            false_range,
        ) {
            rewrites.push(rewrite);
        }
    }

    rewrites.sort_by_key(|rewrite| rewrite.start);
    let mut occupied = HashSet::new();
    let mut selected = Vec::new();
    for rewrite in rewrites {
        if (rewrite.start..=rewrite.end).any(|idx| occupied.contains(&idx)) {
            continue;
        }
        for idx in rewrite.start..=rewrite.end {
            occupied.insert(idx);
        }
        selected.push(rewrite);
    }

    for rewrite in selected.into_iter().rev() {
        function.body.splice(
            rewrite.start..=rewrite.end,
            std::iter::once(rewrite.statement),
        );
    }
}

struct IfRewrite {
    start: usize,
    end: usize,
    statement: Statement,
}

fn terminal_if_else_rewrite(
    function: &Function,
    head_range: (usize, usize),
    true_range: (usize, usize),
    false_range: (usize, usize),
) -> Option<IfRewrite> {
    let covered = covered_indices(&[head_range, true_range, false_range]);
    let start = *covered.iter().min().unwrap_or(&0);
    let end = *covered.iter().max().unwrap_or(&0);
    if !range_is_contiguous(start, end, &covered) {
        return None;
    }

    let condition = branch_condition(function, head_range.0)?;
    let then_block = function.body[true_range.0..=true_range.1].to_vec();
    let else_block = function.body[false_range.0..=false_range.1].to_vec();

    Some(IfRewrite {
        start,
        end,
        statement: Statement::If {
            condition,
            then_block,
            else_block: Some(else_block),
        },
    })
}

fn diamond_if_else_rewrite(
    function: &Function,
    cfg: &ControlFlowGraph,
    head_range: (usize, usize),
    true_node: NodeIndex,
    true_range: (usize, usize),
    false_node: NodeIndex,
    false_range: (usize, usize),
) -> Option<IfRewrite> {
    let true_exit = arm_exit(cfg, true_node, true_range)?;
    let false_exit = arm_exit(cfg, false_node, false_range)?;
    if true_exit.join != false_exit.join {
        return None;
    }

    let covered = covered_indices(&[head_range, true_exit.covered, false_exit.covered]);
    let start = *covered.iter().min().unwrap_or(&0);
    let end = *covered.iter().max().unwrap_or(&0);
    if !range_is_contiguous(start, end, &covered) {
        return None;
    }

    let condition = branch_condition(function, head_range.0)?;
    let then_block = payload_statements(function, true_exit.payload);
    let else_block = payload_statements(function, false_exit.payload);

    Some(IfRewrite {
        start,
        end,
        statement: Statement::If {
            condition,
            then_block,
            else_block: Some(else_block),
        },
    })
}

struct ArmExit {
    join: NodeIndex,
    covered: (usize, usize),
    payload: Option<(usize, usize)>,
}

fn address_to_statement_index(function: &Function) -> HashMap<u64, usize> {
    function
        .body
        .iter()
        .enumerate()
        .filter_map(|(idx, statement)| match statement {
            Statement::InlineAsm { address, .. } => Some((*address, idx)),
            _ => None,
        })
        .collect()
}

fn branch_successors(cfg: &ControlFlowGraph, node: NodeIndex) -> Option<(NodeIndex, NodeIndex)> {
    let mut true_node = None;
    let mut false_node = None;

    for edge in cfg.graph().edges(node) {
        match edge.weight() {
            EdgeType::BranchTrue => true_node = Some(edge.target()),
            EdgeType::BranchFalse => false_node = Some(edge.target()),
            _ => {}
        }
    }

    Some((true_node?, false_node?))
}

fn arm_exit(
    cfg: &ControlFlowGraph,
    node: NodeIndex,
    full_range: (usize, usize),
) -> Option<ArmExit> {
    if let Some(join) = successor_by_edge(cfg, node, EdgeType::Unconditional) {
        let payload = if full_range.0 < full_range.1 {
            Some((full_range.0, full_range.1 - 1))
        } else {
            None
        };
        return Some(ArmExit {
            join,
            covered: full_range,
            payload,
        });
    }

    let join = successor_by_edge(cfg, node, EdgeType::FallThrough)?;
    Some(ArmExit {
        join,
        covered: full_range,
        payload: Some(full_range),
    })
}

fn successor_by_edge(
    cfg: &ControlFlowGraph,
    node: NodeIndex,
    edge_type: EdgeType,
) -> Option<NodeIndex> {
    cfg.graph()
        .edges(node)
        .find(|edge| *edge.weight() == edge_type)
        .map(|edge| edge.target())
}

fn block_ends_in_return(block: &crate::disasm::BasicBlock) -> bool {
    block
        .instructions
        .last()
        .map(|instruction| instruction.is_return())
        .unwrap_or(false)
}

fn block_range(
    block: &crate::disasm::BasicBlock,
    address_to_index: &HashMap<u64, usize>,
) -> Option<(usize, usize)> {
    let first = block.instructions.first()?.address();
    let last = block.instructions.last()?.address();
    Some((
        *address_to_index.get(&first)?,
        *address_to_index.get(&last)?,
    ))
}

fn covered_indices(ranges: &[(usize, usize)]) -> HashSet<usize> {
    let mut covered = HashSet::new();
    for (start, end) in ranges {
        for idx in *start..=*end {
            covered.insert(idx);
        }
    }
    covered
}

fn range_is_contiguous(start: usize, end: usize, covered: &HashSet<usize>) -> bool {
    (start..=end).all(|idx| covered.contains(&idx))
}

fn branch_condition(function: &Function, branch_index: usize) -> Option<Expression> {
    let Statement::InlineAsm { address, disasm } = function.body.get(branch_index)? else {
        return None;
    };

    if let Some(recovered) = recovered_condition(function, branch_index, disasm) {
        return Some(recovered);
    }

    Some(Expression::Unknown(format!(
        "/* condition: 0x{:X} {} */ 1",
        address,
        sanitize_comment(disasm)
    )))
}

fn payload_statements(function: &Function, payload: Option<(usize, usize)>) -> Vec<Statement> {
    payload
        .map(|(start, end)| function.body[start..=end].to_vec())
        .unwrap_or_default()
}

fn recovered_condition(
    function: &Function,
    branch_index: usize,
    branch_disasm: &str,
) -> Option<Expression> {
    let setup_index = branch_index.checked_sub(1)?;
    let Statement::InlineAsm {
        disasm: setup_disasm,
        ..
    } = function.body.get(setup_index)?
    else {
        return None;
    };

    let (setup_mnemonic, setup_operands) = split_instruction(setup_disasm)?;
    let (branch_mnemonic, _) = split_instruction(branch_disasm)?;
    match setup_mnemonic.as_str() {
        "cmp" => recover_cmp_condition(
            setup_disasm,
            &setup_operands,
            branch_disasm,
            &branch_mnemonic,
        ),
        "test" => recover_test_condition(
            setup_disasm,
            &setup_operands,
            branch_disasm,
            &branch_mnemonic,
        ),
        _ => None,
    }
}

fn recover_cmp_condition(
    setup_disasm: &str,
    operands: &str,
    branch_disasm: &str,
    branch_mnemonic: &str,
) -> Option<Expression> {
    let (left, right) = split_operands(operands)?;
    let op = cmp_operator_for_branch(branch_mnemonic)?;
    let expression_text = format!("{} {} {}", left, op.symbol(), right);

    let Some(left_expr) = operand_expression(&left) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };
    let Some(right_expr) = operand_expression(&right) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };

    Some(Expression::BinaryOperation {
        op,
        left: Box::new(left_expr),
        right: Box::new(right_expr),
    })
}

fn recover_test_condition(
    setup_disasm: &str,
    operands: &str,
    branch_disasm: &str,
    branch_mnemonic: &str,
) -> Option<Expression> {
    let (left, right) = split_operands(operands)?;
    let compares_equal_zero = branch_is_zero(branch_mnemonic)?;
    let op = if compares_equal_zero {
        BinaryOperator::Equal
    } else {
        BinaryOperator::NotEqual
    };

    if left.eq_ignore_ascii_case(&right) {
        let expression_text = format!("{} {} 0", left, op.symbol());
        let Some(left_expr) = operand_expression(&left) else {
            return Some(comment_condition(
                &expression_text,
                setup_disasm,
                branch_disasm,
            ));
        };
        return Some(Expression::BinaryOperation {
            op,
            left: Box::new(left_expr),
            right: Box::new(Expression::IntegerLiteral(0)),
        });
    }

    let expression_text = format!("({} & {}) {} 0", left, right, op.symbol());
    let Some(left_expr) = operand_expression(&left) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };
    let Some(right_expr) = operand_expression(&right) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };

    Some(Expression::BinaryOperation {
        op,
        left: Box::new(Expression::BinaryOperation {
            op: BinaryOperator::BitwiseAnd,
            left: Box::new(left_expr),
            right: Box::new(right_expr),
        }),
        right: Box::new(Expression::IntegerLiteral(0)),
    })
}

fn operand_expression(operand: &str) -> Option<Expression> {
    let normalized = operand.trim();
    if is_register_name(normalized) {
        return Some(Expression::Variable(canonicalize_register_name(normalized)));
    }
    if let Some(name) = stack_variable_name(normalized) {
        return Some(Expression::Variable(name));
    }

    parse_integer_literal(normalized).map(Expression::IntegerLiteral)
}

fn assignment_target_expression(operand: &str) -> Option<Expression> {
    let normalized = operand.trim();
    if is_register_name(normalized) {
        return Some(Expression::Variable(canonicalize_register_name(normalized)));
    }
    stack_variable_name(normalized).map(Expression::Variable)
}

fn stack_variable_name(operand: &str) -> Option<String> {
    let memory = normalize_memory_operand(operand)?;
    let compact = memory.replace(' ', "");

    for base in ["rbp", "ebp"] {
        if let Some(rest) = compact.strip_prefix(base) {
            return stack_name_from_offset(rest, "local", "arg");
        }
    }

    for base in ["rsp", "esp"] {
        if let Some(rest) = compact.strip_prefix(base) {
            return stack_name_from_offset(rest, "stack_m", "stack");
        }
    }

    None
}

fn normalize_memory_operand(operand: &str) -> Option<String> {
    let mut normalized = operand.trim().to_ascii_lowercase();
    for prefix in [
        "byte ptr ",
        "word ptr ",
        "dword ptr ",
        "qword ptr ",
        "tword ptr ",
        "oword ptr ",
        "xmmword ptr ",
        "ymmword ptr ",
        "zmmword ptr ",
    ] {
        if let Some(rest) = normalized.strip_prefix(prefix) {
            normalized = rest.trim().to_string();
            break;
        }
    }

    let inner = normalized
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))?;
    Some(inner.to_string())
}

fn stack_name_from_offset(
    rest: &str,
    negative_prefix: &str,
    positive_prefix: &str,
) -> Option<String> {
    let (prefix, offset) = if let Some(offset) = rest.strip_prefix('-') {
        (negative_prefix, offset)
    } else if let Some(offset) = rest.strip_prefix('+') {
        (positive_prefix, offset)
    } else {
        return None;
    };

    let component = normalized_offset_component(offset)?;
    Some(format!("{}_{}", prefix, component))
}

fn normalized_offset_component(offset: &str) -> Option<String> {
    let trimmed = offset.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_hex_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let without_hex_suffix = without_hex_prefix
        .strip_suffix('h')
        .or_else(|| without_hex_prefix.strip_suffix('H'))
        .unwrap_or(without_hex_prefix);

    let component = without_hex_suffix.trim_start_matches('0');
    if component.is_empty() {
        Some("0".to_string())
    } else if component.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(component.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_integer_literal(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    let unsigned = trimmed.strip_prefix('-').unwrap_or(trimmed);
    let parsed = if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = unsigned
        .strip_suffix('h')
        .or_else(|| unsigned.strip_suffix('H'))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        unsigned.parse::<i64>().ok()?
    };

    if trimmed.starts_with('-') {
        Some(-parsed)
    } else {
        Some(parsed)
    }
}

fn split_instruction(disasm: &str) -> Option<(String, String)> {
    let trimmed = disasm.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    let operands = parts.next().unwrap_or("").trim().to_string();
    Some((mnemonic, operands))
}

fn split_operands(operands: &str) -> Option<(String, String)> {
    let mut parts = operands.splitn(2, ',');
    let left = parts.next()?.trim();
    let right = parts.next()?.trim();
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left.to_string(), right.to_string()))
}

fn cmp_operator_for_branch(branch_mnemonic: &str) -> Option<BinaryOperator> {
    match branch_mnemonic {
        "je" | "jz" => Some(BinaryOperator::Equal),
        "jne" | "jnz" => Some(BinaryOperator::NotEqual),
        "jl" | "jnge" | "jb" | "jnae" | "jc" => Some(BinaryOperator::LessThan),
        "jle" | "jng" | "jbe" | "jna" => Some(BinaryOperator::LessThanOrEqual),
        "jg" | "jnle" | "ja" | "jnbe" => Some(BinaryOperator::GreaterThan),
        "jge" | "jnl" | "jae" | "jnb" | "jnc" => Some(BinaryOperator::GreaterThanOrEqual),
        _ => None,
    }
}

fn branch_is_zero(branch_mnemonic: &str) -> Option<bool> {
    match branch_mnemonic {
        "je" | "jz" => Some(true),
        "jne" | "jnz" => Some(false),
        _ => None,
    }
}

fn sanitize_comment(value: &str) -> String {
    value.replace("*/", "* /")
}

fn comment_condition(expression: &str, setup_disasm: &str, branch_disasm: &str) -> Expression {
    Expression::Unknown(format!(
        "/* condition: {} (from {}; {}) */ 1",
        sanitize_comment(expression),
        sanitize_comment(setup_disasm),
        sanitize_comment(branch_disasm)
    ))
}

fn insert_pseudo_register_declarations(function: &mut Function) {
    let existing: HashSet<String> = function
        .body
        .iter()
        .filter_map(|statement| match statement {
            Statement::VariableDeclaration { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    let mut registers = BTreeSet::new();
    for statement in &function.body {
        collect_pseudo_registers_from_statement(statement, &mut registers);
    }
    let declarations: Vec<Statement> = registers
        .into_iter()
        .filter(|name| !existing.contains(name))
        .map(|name| Statement::VariableDeclaration {
            name,
            type_info: TypeInfo::U64,
            init: None,
        })
        .collect();

    if !declarations.is_empty() {
        function.body.splice(0..0, declarations);
    }
}

fn collect_pseudo_registers_from_statement(
    statement: &Statement,
    registers: &mut BTreeSet<String>,
) {
    match statement {
        Statement::Expression(expr) | Statement::Return(Some(expr)) => {
            collect_pseudo_registers_from_expression(expr, registers);
        }
        Statement::If {
            condition,
            then_block,
            else_block,
        } => {
            collect_pseudo_registers_from_expression(condition, registers);
            for nested in then_block {
                collect_pseudo_registers_from_statement(nested, registers);
            }
            if let Some(else_block) = else_block {
                for nested in else_block {
                    collect_pseudo_registers_from_statement(nested, registers);
                }
            }
        }
        Statement::While { condition, body } => {
            collect_pseudo_registers_from_expression(condition, registers);
            for nested in body {
                collect_pseudo_registers_from_statement(nested, registers);
            }
        }
        Statement::For {
            init,
            condition,
            update,
            body,
        } => {
            if let Some(init) = init {
                collect_pseudo_registers_from_statement(init, registers);
            }
            if let Some(condition) = condition {
                collect_pseudo_registers_from_expression(condition, registers);
            }
            if let Some(update) = update {
                collect_pseudo_registers_from_expression(update, registers);
            }
            for nested in body {
                collect_pseudo_registers_from_statement(nested, registers);
            }
        }
        Statement::VariableDeclaration {
            init: Some(init), ..
        } => {
            collect_pseudo_registers_from_expression(init, registers);
        }
        Statement::VariableDeclaration { init: None, .. } => {}
        Statement::Block(statements) => {
            for nested in statements {
                collect_pseudo_registers_from_statement(nested, registers);
            }
        }
        _ => {}
    }
}

fn collect_pseudo_registers_from_expression(expr: &Expression, registers: &mut BTreeSet<String>) {
    match expr {
        Expression::Variable(name) if is_register_name(name) => {
            registers.insert(canonicalize_register_name(name));
        }
        Expression::Variable(name) if is_stack_variable_name(name) => {
            registers.insert(name.to_ascii_lowercase());
        }
        Expression::BinaryOperation { left, right, .. } => {
            collect_pseudo_registers_from_expression(left, registers);
            collect_pseudo_registers_from_expression(right, registers);
        }
        Expression::UnaryOperation { operand, .. } => {
            collect_pseudo_registers_from_expression(operand, registers);
        }
        Expression::FunctionCall { arguments, .. } => {
            for argument in arguments {
                collect_pseudo_registers_from_expression(argument, registers);
            }
        }
        Expression::Assignment { target, value } => {
            collect_pseudo_registers_from_expression(target, registers);
            collect_pseudo_registers_from_expression(value, registers);
        }
        Expression::Cast { value, .. } => {
            collect_pseudo_registers_from_expression(value, registers);
        }
        Expression::AddressOf(expr) | Expression::Dereference(expr) => {
            collect_pseudo_registers_from_expression(expr, registers);
        }
        Expression::ArrayAccess { array, index } => {
            collect_pseudo_registers_from_expression(array, registers);
            collect_pseudo_registers_from_expression(index, registers);
        }
        Expression::MemberAccess { object, .. } => {
            collect_pseudo_registers_from_expression(object, registers);
        }
        _ => {}
    }
}

fn canonicalize_register_name(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    match lower.as_str() {
        "al" | "ah" | "ax" | "eax" | "rax" => "rax",
        "bl" | "bh" | "bx" | "ebx" | "rbx" => "rbx",
        "cl" | "ch" | "cx" | "ecx" | "rcx" => "rcx",
        "dl" | "dh" | "dx" | "edx" | "rdx" => "rdx",
        "sil" | "si" | "esi" | "rsi" => "rsi",
        "dil" | "di" | "edi" | "rdi" => "rdi",
        "bpl" | "bp" | "ebp" | "rbp" => "rbp",
        "spl" | "sp" | "esp" | "rsp" => "rsp",
        "r8b" | "r8w" | "r8d" | "r8" => "r8",
        "r9b" | "r9w" | "r9d" | "r9" => "r9",
        "r10b" | "r10w" | "r10d" | "r10" => "r10",
        "r11b" | "r11w" | "r11d" | "r11" => "r11",
        "r12b" | "r12w" | "r12d" | "r12" => "r12",
        "r13b" | "r13w" | "r13d" | "r13" => "r13",
        "r14b" | "r14w" | "r14d" | "r14" => "r14",
        "r15b" | "r15w" | "r15d" | "r15" => "r15",
        _ => lower.as_str(),
    }
    .to_string()
}

fn is_register_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "al" | "ah"
            | "ax"
            | "eax"
            | "rax"
            | "bl"
            | "bh"
            | "bx"
            | "ebx"
            | "rbx"
            | "cl"
            | "ch"
            | "cx"
            | "ecx"
            | "rcx"
            | "dl"
            | "dh"
            | "dx"
            | "edx"
            | "rdx"
            | "sil"
            | "si"
            | "esi"
            | "rsi"
            | "dil"
            | "di"
            | "edi"
            | "rdi"
            | "bpl"
            | "bp"
            | "ebp"
            | "rbp"
            | "spl"
            | "sp"
            | "esp"
            | "rsp"
            | "r8b"
            | "r8w"
            | "r8d"
            | "r8"
            | "r9b"
            | "r9w"
            | "r9d"
            | "r9"
            | "r10b"
            | "r10w"
            | "r10d"
            | "r10"
            | "r11b"
            | "r11w"
            | "r11d"
            | "r11"
            | "r12b"
            | "r12w"
            | "r12d"
            | "r12"
            | "r13b"
            | "r13w"
            | "r13d"
            | "r13"
            | "r14b"
            | "r14w"
            | "r14d"
            | "r14"
            | "r15b"
            | "r15w"
            | "r15d"
            | "r15"
    )
}

fn is_stack_variable_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("local_") || lower.starts_with("arg_") || lower.starts_with("stack_")
}

trait BinaryOperatorText {
    fn symbol(self) -> &'static str;
}

impl BinaryOperatorText for BinaryOperator {
    fn symbol(self) -> &'static str {
        match self {
            BinaryOperator::Equal => "==",
            BinaryOperator::NotEqual => "!=",
            BinaryOperator::LessThan => "<",
            BinaryOperator::LessThanOrEqual => "<=",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::GreaterThanOrEqual => ">=",
            BinaryOperator::BitwiseAnd => "&",
            _ => "?",
        }
    }
}
