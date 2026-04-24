//! Abstract Syntax Tree for decompiled code

use crate::analysis::TypeInfo;

/// AST node type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstNodeType {
    /// Function
    Function,
    /// Statement
    Statement,
    /// Expression
    Expression,
    /// Variable declaration
    VariableDeclaration,
    /// Type declaration
    TypeDeclaration,
}

/// Expression
#[derive(Debug, Clone)]
pub enum Expression {
    /// Integer literal
    IntegerLiteral(i64),
    /// String literal
    StringLiteral(String),
    /// Variable reference
    Variable(String),
    /// Binary operation
    BinaryOperation {
        op: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Unary operation
    UnaryOperation {
        op: UnaryOperator,
        operand: Box<Expression>,
    },
    /// Function call
    FunctionCall {
        function: String,
        arguments: Vec<Expression>,
    },
    /// Assignment
    Assignment {
        target: Box<Expression>,
        value: Box<Expression>,
    },
    /// Cast
    Cast {
        type_info: TypeInfo,
        value: Box<Expression>,
    },
    /// Address of
    AddressOf(Box<Expression>),
    /// Dereference
    Dereference(Box<Expression>),
    /// Array access
    ArrayAccess {
        array: Box<Expression>,
        index: Box<Expression>,
    },
    /// Member access
    MemberAccess {
        object: Box<Expression>,
        member: String,
    },
    /// Unknown
    Unknown(String),
}

/// Binary operator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LogicalAnd,
    LogicalOr,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
}

/// Unary operator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOperator {
    Negate,
    LogicalNot,
    BitwiseNot,
    Address,
    Dereference,
}

/// Statement
#[derive(Debug, Clone)]
pub enum Statement {
    /// Expression statement
    Expression(Expression),
    /// Return statement
    Return(Option<Expression>),
    /// If statement
    If {
        condition: Expression,
        then_block: Vec<Statement>,
        else_block: Option<Vec<Statement>>,
    },
    /// While loop
    While {
        condition: Expression,
        body: Vec<Statement>,
    },
    /// For loop
    For {
        init: Option<Box<Statement>>,
        condition: Option<Expression>,
        update: Option<Expression>,
        body: Vec<Statement>,
    },
    /// Variable declaration
    VariableDeclaration {
        name: String,
        type_info: TypeInfo,
        init: Option<Expression>,
    },
    /// Block
    Block(Vec<Statement>),
    /// Break
    Break,
    /// Continue
    Continue,
    /// Empty
    Empty,
    /// Raw disassembly placeholder. Every AST node stays addressable so later
    /// structuring passes can correlate back to the original instruction.
    InlineAsm { address: u64, disasm: String },
}

/// Function
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub return_type: TypeInfo,
    pub parameters: Vec<Parameter>,
    pub body: Vec<Statement>,
    pub is_variadic: bool,
}

/// Function parameter
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub type_info: TypeInfo,
}

/// AST node
#[derive(Debug, Clone)]
pub struct AstNode {
    pub node_type: AstNodeType,
    pub expression: Option<Expression>,
    pub statement: Option<Statement>,
    pub function: Option<Function>,
}

impl AstNode {
    /// Create a new AST node from an expression
    pub fn from_expression(expr: Expression) -> Self {
        Self {
            node_type: AstNodeType::Expression,
            expression: Some(expr),
            statement: None,
            function: None,
        }
    }

    /// Create a new AST node from a statement
    pub fn from_statement(stmt: Statement) -> Self {
        Self {
            node_type: AstNodeType::Statement,
            expression: None,
            statement: Some(stmt),
            function: None,
        }
    }

    /// Create a new AST node from a function
    pub fn from_function(func: Function) -> Self {
        Self {
            node_type: AstNodeType::Function,
            expression: None,
            statement: None,
            function: Some(func),
        }
    }
}
