//! C code generator from AST

use crate::analysis::TypeInfo;
use crate::decompiler::ast::{BinaryOperator, Expression, Function, Statement, UnaryOperator};

/// C generator configuration
#[derive(Debug, Clone)]
pub struct CGeneratorConfig {
    /// Indentation size
    pub indent_size: usize,
    /// Whether to include comments
    pub include_comments: bool,
    /// Whether to use stdint.h types
    pub use_stdint: bool,
}

impl Default for CGeneratorConfig {
    fn default() -> Self {
        Self {
            indent_size: 4,
            include_comments: true,
            use_stdint: true,
        }
    }
}

/// C code generator
pub struct CGenerator {
    config: CGeneratorConfig,
    indent_level: usize,
}

impl CGenerator {
    /// Create a new C generator
    pub fn new(config: CGeneratorConfig) -> Self {
        Self {
            config,
            indent_level: 0,
        }
    }

    /// Generate C code from a function
    pub fn generate_function(&mut self, func: &Function) -> String {
        let mut output = String::new();

        // Function signature
        output.push_str(&self.generate_function_signature(func));
        output.push_str(" {\n");
        self.indent_level += 1;

        // Function body
        for stmt in &func.body {
            output.push_str(&self.generate_statement(stmt));
            output.push('\n');
        }

        self.indent_level -= 1;
        output.push_str("}\n");

        output
    }

    /// Generate function signature
    fn generate_function_signature(&self, func: &Function) -> String {
        let return_type = self.type_to_c_string(&func.return_type);
        let params: Vec<String> = func
            .parameters
            .iter()
            .map(|p| {
                let param_type = self.type_to_c_string(&p.type_info);
                format!("{} {}", param_type, p.name)
            })
            .collect();

        let params_str = if params.is_empty() {
            "void".to_string()
        } else {
            params.join(", ")
        };

        format!("{} {}({})", return_type, func.name, params_str)
    }

    /// Generate C code from a statement
    fn generate_statement(&mut self, stmt: &Statement) -> String {
        let indent = " ".repeat(self.indent_level * self.config.indent_size);

        match stmt {
            Statement::Expression(expr) => {
                format!("{}{};", indent, self.generate_expression(expr))
            }
            Statement::Return(None) => {
                format!("{}return;", indent)
            }
            Statement::Return(Some(expr)) => {
                format!("{}return {};", indent, self.generate_expression(expr))
            }
            Statement::If {
                condition,
                then_block,
                else_block,
            } => {
                let mut output = format!(
                    "{}if ({}) {{\n",
                    indent,
                    self.generate_expression(condition)
                );
                self.indent_level += 1;

                for s in then_block {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));

                if let Some(else_block) = else_block {
                    output.push_str(" else {\n");
                    self.indent_level += 1;

                    for s in else_block {
                        output.push_str(&self.generate_statement(s));
                        output.push('\n');
                    }

                    self.indent_level -= 1;
                    output.push_str(&format!("{}}}", indent));
                }

                output
            }
            Statement::While { condition, body } => {
                let mut output = format!(
                    "{}while ({}) {{\n",
                    indent,
                    self.generate_expression(condition)
                );
                self.indent_level += 1;

                for s in body {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));
                output
            }
            Statement::For {
                init,
                condition,
                update,
                body,
            } => {
                let init_str = init
                    .as_ref()
                    .map(|s| self.generate_statement(s).trim_end_matches(';').to_string())
                    .unwrap_or_else(|| "".to_string());

                let cond_str = condition
                    .as_ref()
                    .map(|c| self.generate_expression(c))
                    .unwrap_or_else(|| "1".to_string());

                let update_str = update
                    .as_ref()
                    .map(|c| self.generate_expression(c))
                    .unwrap_or_else(|| "".to_string());

                let mut output = format!(
                    "{}for ({}; {}; {}) {{\n",
                    indent, init_str, cond_str, update_str
                );
                self.indent_level += 1;

                for s in body {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));
                output
            }
            Statement::VariableDeclaration {
                name,
                type_info,
                init,
            } => {
                let type_str = self.type_to_c_string(type_info);
                match init {
                    Some(expr) => format!(
                        "{}{} {} = {};",
                        indent,
                        type_str,
                        name,
                        self.generate_expression(expr)
                    ),
                    None => format!("{}{} {};", indent, type_str, name),
                }
            }
            Statement::Block(statements) => {
                let mut output = format!("{}{{\n", indent);
                self.indent_level += 1;

                for s in statements {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));
                output
            }
            Statement::Break => {
                format!("{}break;", indent)
            }
            Statement::Continue => {
                format!("{}continue;", indent)
            }
            Statement::Empty => {
                format!("{};", indent)
            }
            Statement::InlineAsm { address, disasm } => {
                // Emit as a C comment so output stays compilable. The address
                // prefix anchors each line back to the original binary for
                // diagnostics and for later structuring passes.
                format!("{}/* 0x{:X}: {} */", indent, address, disasm)
            }
        }
    }

    /// Generate C code from an expression
    fn generate_expression(&self, expr: &Expression) -> String {
        match expr {
            Expression::IntegerLiteral(value) => value.to_string(),
            Expression::StringLiteral(s) => format!("\"{}\"", s),
            Expression::Variable(name) => name.clone(),
            Expression::BinaryOperation { op, left, right } => {
                let left_str = self.generate_expression(left);
                let right_str = self.generate_expression(right);
                let op_str = self.binary_operator_to_string(*op);
                format!("({} {} {})", left_str, op_str, right_str)
            }
            Expression::UnaryOperation { op, operand } => {
                let operand_str = self.generate_expression(operand);
                let op_str = self.unary_operator_to_string(*op);
                format!("{}{}", op_str, operand_str)
            }
            Expression::FunctionCall {
                function,
                arguments,
            } => {
                let args: Vec<String> = arguments
                    .iter()
                    .map(|a| self.generate_expression(a))
                    .collect();
                format!("{}({})", function, args.join(", "))
            }
            Expression::Assignment { target, value } => {
                let target_str = self.generate_expression(target);
                let value_str = self.generate_expression(value);
                format!("{} = {}", target_str, value_str)
            }
            Expression::Cast { type_info, value } => {
                let type_str = self.type_to_c_string(type_info);
                let value_str = self.generate_expression(value);
                format!("({}){}", type_str, value_str)
            }
            Expression::AddressOf(expr) => {
                let expr_str = self.generate_expression(expr);
                format!("&{}", expr_str)
            }
            Expression::Dereference(expr) => {
                let expr_str = self.generate_expression(expr);
                format!("*{}", expr_str)
            }
            Expression::ArrayAccess { array, index } => {
                let array_str = self.generate_expression(array);
                let index_str = self.generate_expression(index);
                format!("{}[{}]", array_str, index_str)
            }
            Expression::MemberAccess { object, member } => {
                let object_str = self.generate_expression(object);
                format!("{}.{}", object_str, member)
            }
            Expression::Unknown(s) => s.clone(),
        }
    }

    /// Convert binary operator to C string
    fn binary_operator_to_string(&self, op: BinaryOperator) -> &'static str {
        match op {
            BinaryOperator::Add => "+",
            BinaryOperator::Subtract => "-",
            BinaryOperator::Multiply => "*",
            BinaryOperator::Divide => "/",
            BinaryOperator::Modulo => "%",
            BinaryOperator::Equal => "==",
            BinaryOperator::NotEqual => "!=",
            BinaryOperator::LessThan => "<",
            BinaryOperator::LessThanOrEqual => "<=",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::GreaterThanOrEqual => ">=",
            BinaryOperator::LogicalAnd => "&&",
            BinaryOperator::LogicalOr => "||",
            BinaryOperator::BitwiseAnd => "&",
            BinaryOperator::BitwiseOr => "|",
            BinaryOperator::BitwiseXor => "^",
            BinaryOperator::LeftShift => "<<",
            BinaryOperator::RightShift => ">>",
        }
    }

    /// Convert unary operator to C string
    fn unary_operator_to_string(&self, op: UnaryOperator) -> &'static str {
        match op {
            UnaryOperator::Negate => "-",
            UnaryOperator::LogicalNot => "!",
            UnaryOperator::BitwiseNot => "~",
            UnaryOperator::Address => "&",
            UnaryOperator::Dereference => "*",
        }
    }

    /// Convert type info to C string
    fn type_to_c_string(&self, type_info: &TypeInfo) -> String {
        type_info.to_c_type().to_string()
    }
}

impl Default for CGenerator {
    fn default() -> Self {
        Self::new(CGeneratorConfig::default())
    }
}
