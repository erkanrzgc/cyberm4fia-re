//! Analysis module

pub mod functions;
pub mod patterns;
pub mod runtime;
pub mod strings;
pub mod types;

pub use functions::{FunctionDetector, FunctionInfo};
pub use patterns::{PatternMatch, PatternMatcher};
pub use runtime::{RuntimeDetectionInputs, RuntimeDetector, RuntimeFamily, RuntimeMatch};
pub use strings::{StringExtractor, StringInfo};
pub use types::{TypeInference, TypeInfo};
