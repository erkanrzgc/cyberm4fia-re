//! Analysis module

pub mod functions;
pub mod patterns;
pub mod runtime;
pub mod runtime_artifacts;
pub mod runtime_report;
pub mod strings;
pub mod types;

pub use functions::{FunctionDetector, FunctionInfo};
pub use patterns::{PatternMatch, PatternMatcher};
pub use runtime::{RuntimeDetectionInputs, RuntimeDetector, RuntimeFamily, RuntimeMatch};
pub use runtime_artifacts::{
    RuntimeArtifactExtractor, RuntimeArtifactInputs, RuntimeArtifactResult,
};
pub use runtime_report::{
    RuntimeAction, RuntimeArtifact, RuntimeReport, RuntimeReportBuilder, RuntimeReportInputs,
};
pub use strings::{StringExtractor, StringInfo};
pub use types::{TypeInference, TypeInfo};
