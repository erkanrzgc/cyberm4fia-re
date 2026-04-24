//! Code optimization

use crate::decompiler::ast::{BinaryOperator, Expression, Function, Statement};

/// Optimization level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationLevel {
    /// No optimization
    None,
    /// Basic optimizations
    Basic,
    /// Aggressive optimizations
    Aggressive,
}

/// Optimizer
pub struct Optimizer {
    level: OptimizationLevel,
}

impl Optimizer {
    /// Create a new optimizer
    pub fn new(level: OptimizationLevel) -> Self {
        Self { level }
    }

    /// Optimize a function
    pub fn optimize_function(&self, func: &mut Function) {
        if self.level == OptimizationLevel::None {
            return;
        }

        // Optimize statements
        for stmt in &mut func.body {
            self.optimize_statement(stmt);
        }

        // Remove empty statements
        func.body.retain(|stmt| !matches!(stmt, Statement::Empty));

        if self.level == OptimizationLevel::Aggressive {
            // Aggressive optimizations
            self.optimize_aggressive(func);
        }
    }

    /// Optimize a statement
    fn optimize_statement(&self, stmt: &mut Statement) {
        match stmt {
            Statement::Expression(expr) => {
                self.optimize_expression(expr);
            }
            Statement::Return(Some(expr)) => {
                self.optimize_expression(expr);
            }
            Statement::If {
                condition,
                then_block,
                else_block,
            } => {
                self.optimize_expression(condition);
                for s in then_block {
                    self.optimize_statement(s);
                }
                if let Some(else_block) = else_block {
                    for s in else_block {
                        self.optimize_statement(s);
                    }
                }
            }
            Statement::While { condition, body } => {
                self.optimize_expression(condition);
                for s in body {
                    self.optimize_statement(s);
                }
            }
            Statement::For {
                init,
                condition,
                update,
                body,
            } => {
                if let Some(init_stmt) = init {
                    self.optimize_statement(init_stmt);
                }
                if let Some(cond_expr) = condition {
                    self.optimize_expression(cond_expr);
                }
                if let Some(update_expr) = update {
                    self.optimize_expression(update_expr);
                }
                for s in body {
                    self.optimize_statement(s);
                }
            }
            Statement::Block(statements) => {
                for s in statements {
                    self.optimize_statement(s);
                }
            }
            _ => {}
        }
    }

    /// Optimize an expression
    fn optimize_expression(&self, expr: &mut Expression) {
        match expr {
            Expression::BinaryOperation { op, left, right } => {
                self.optimize_expression(left);
                self.optimize_expression(right);

                // Constant folding
                if let Some(folded) = self.fold_constant(*op, left, right) {
                    *expr = folded;
                }
            }
            Expression::UnaryOperation { operand, .. } => {
                self.optimize_expression(operand);
            }
            Expression::FunctionCall { arguments, .. } => {
                for arg in arguments {
                    self.optimize_expression(arg);
                }
            }
            Expression::Assignment { target, value } => {
                self.optimize_expression(target);
                self.optimize_expression(value);
            }
            Expression::Cast { value, .. } => {
                self.optimize_expression(value);
            }
            Expression::AddressOf(expr) | Expression::Dereference(expr) => {
                self.optimize_expression(expr);
            }
            Expression::ArrayAccess { array, index } => {
                self.optimize_expression(array);
                self.optimize_expression(index);
            }
            Expression::MemberAccess { object, .. } => {
                self.optimize_expression(object);
            }
            _ => {}
        }
    }

    /// Fold constant expressions
    fn fold_constant(
        &self,
        op: BinaryOperator,
        left: &Expression,
        right: &Expression,
    ) -> Option<Expression> {
        let left_val = match left {
            Expression::IntegerLiteral(v) => Some(*v),
            _ => None,
        };

        let right_val = match right {
            Expression::IntegerLiteral(v) => Some(*v),
            _ => None,
        };

        if let (Some(l), Some(r)) = (left_val, right_val) {
            let result = match op {
                BinaryOperator::Add => l + r,
                BinaryOperator::Subtract => l - r,
                BinaryOperator::Multiply => l * r,
                BinaryOperator::Divide => l / r,
                BinaryOperator::Modulo => l % r,
                BinaryOperator::BitwiseAnd => l & r,
                BinaryOperator::BitwiseOr => l | r,
                BinaryOperator::BitwiseXor => l ^ r,
                BinaryOperator::LeftShift => l << r,
                BinaryOperator::RightShift => l >> r,
                _ => return None,
            };
            Some(Expression::IntegerLiteral(result))
        } else {
            None
        }
    }

    /// Aggressive optimizations
    fn optimize_aggressive(&self, func: &mut Function) {
        // Remove dead code
        self.remove_dead_code(func);

        // Inline simple functions
        self.inline_simple_functions(func);
    }

    /// Remove dead code
    fn remove_dead_code(&self, func: &mut Function) {
        // Mark reachable statements
        let mut reachable = vec![false; func.body.len()];

        if !func.body.is_empty() {
            reachable[0] = true;
        }

        for (i, stmt) in func.body.iter().enumerate() {
            if !reachable[i] {
                continue;
            }

            match stmt {
                Statement::If {
                    then_block,
                    else_block: _,
                    ..
                } => {
                    // Mark then block as reachable
                    if let Some(first) = then_block.first() {
                        if let Statement::Expression(expr) = first {
                            if let Expression::Variable(name) = expr {
                                if let Some(j) = func.body.iter().position(|s| {
                                    matches!(s, Statement::VariableDeclaration { name: n, .. } if n == name)
                                }) {
                                    reachable[j] = true;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Keep only reachable statements
        let mut new_body = Vec::new();
        for (i, stmt) in func.body.iter().enumerate() {
            if reachable[i] {
                new_body.push(stmt.clone());
            }
        }

        func.body = new_body;
    }

    /// Inline simple functions
    fn inline_simple_functions(&self, _func: &mut Function) {
        // TODO: Implement function inlining
    }
}

impl Default for Optimizer {
    fn default() -> Self {
        Self::new(OptimizationLevel::Basic)
    }
}
