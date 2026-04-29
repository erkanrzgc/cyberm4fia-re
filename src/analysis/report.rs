//! Structured reverse-engineering report package.

use crate::analysis::functions::FunctionInfo;
use crate::analysis::runtime::RuntimeMatch;
use crate::analysis::strings::StringInfo;
use crate::binary::parser::{ExportInfo, ImportInfo};
use crate::disasm::control_flow::Instruction;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

/// Inputs for building a complete reverse-engineering report package.
pub struct AnalysisReportInputs<'a> {
    pub input_path: &'a str,
    pub format: &'a str,
    pub architecture: &'a str,
    pub entry_point: u64,
    pub instruction_count: usize,
    pub basic_block_count: usize,
    pub functions: &'a [FunctionInfo],
    pub strings: &'a [StringInfo],
    pub imports: &'a [ImportInfo],
    pub exports: &'a [ExportInfo],
    pub runtime_matches: &'a [RuntimeMatch],
}

/// Top-level structured analysis package.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReportPackage {
    pub summary: AnalysisSummary,
    pub functions: Vec<FunctionReport>,
    pub strings: Vec<StringReport>,
    pub imports: Vec<ImportReport>,
    pub exports: Vec<ExportReport>,
}

/// Human-scale counts and binary identity.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    pub input_path: String,
    pub format: String,
    pub architecture: String,
    pub entry_point: u64,
    pub instruction_count: usize,
    pub basic_block_count: usize,
    pub function_count: usize,
    pub string_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub runtime_hints: Vec<RuntimeHintReport>,
}

/// Runtime hint summary.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeHintReport {
    pub name: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
    pub guidance: String,
}

/// Function relationship report.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionReport {
    pub name: String,
    pub address: u64,
    pub size: usize,
    pub instruction_count: usize,
    pub is_import: bool,
    pub is_export: bool,
    pub calls: Vec<CallReference>,
    pub string_refs: Vec<StringReference>,
}

/// Direct call target reference.
#[derive(Debug, Clone, Serialize)]
pub struct CallReference {
    pub instruction_address: u64,
    pub target_address: u64,
    pub target_name: Option<String>,
}

/// String reference found inside a function.
#[derive(Debug, Clone, Serialize)]
pub struct StringReference {
    pub instruction_address: u64,
    pub address: u64,
    pub symbol: String,
    pub value: String,
}

/// Extracted string report.
#[derive(Debug, Clone, Serialize)]
pub struct StringReport {
    pub address: u64,
    pub symbol: String,
    pub value: String,
    pub encoding: String,
    pub length: usize,
}

/// Import table report.
#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub name: String,
    pub functions: Vec<String>,
}

/// Export table report.
#[derive(Debug, Clone, Serialize)]
pub struct ExportReport {
    pub name: String,
    pub address: u64,
    pub ordinal: Option<u16>,
}

/// Builds serializable reverse-engineering report packages.
pub struct AnalysisReportBuilder;

impl AnalysisReportBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, inputs: AnalysisReportInputs<'_>) -> AnalysisReportPackage {
        let function_names = build_function_name_map(inputs.functions);
        let string_reports = inputs.strings.iter().map(string_report).collect::<Vec<_>>();
        let string_map = inputs
            .strings
            .iter()
            .map(|string| (string.address, string))
            .collect::<HashMap<_, _>>();

        AnalysisReportPackage {
            summary: AnalysisSummary {
                input_path: inputs.input_path.to_string(),
                format: inputs.format.to_string(),
                architecture: inputs.architecture.to_string(),
                entry_point: inputs.entry_point,
                instruction_count: inputs.instruction_count,
                basic_block_count: inputs.basic_block_count,
                function_count: inputs.functions.len(),
                string_count: inputs.strings.len(),
                import_count: inputs.imports.len(),
                export_count: inputs.exports.len(),
                runtime_hints: inputs
                    .runtime_matches
                    .iter()
                    .map(|runtime| RuntimeHintReport {
                        name: runtime.name.to_string(),
                        confidence: runtime.confidence,
                        evidence: runtime.evidence.clone(),
                        guidance: runtime.guidance.to_string(),
                    })
                    .collect(),
            },
            functions: inputs
                .functions
                .iter()
                .map(|function| function_report(function, &function_names, &string_map))
                .collect(),
            strings: string_reports,
            imports: inputs
                .imports
                .iter()
                .map(|import| ImportReport {
                    name: import.name.clone(),
                    functions: import.functions.clone(),
                })
                .collect(),
            exports: inputs
                .exports
                .iter()
                .map(|export| ExportReport {
                    name: export.name.clone(),
                    address: export.address,
                    ordinal: export.ordinal,
                })
                .collect(),
        }
    }
}

impl Default for AnalysisReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn build_function_name_map(functions: &[FunctionInfo]) -> HashMap<u64, String> {
    functions
        .iter()
        .map(|function| (function.address, function.name.clone()))
        .collect()
}

fn function_report(
    function: &FunctionInfo,
    function_names: &HashMap<u64, String>,
    strings: &HashMap<u64, &StringInfo>,
) -> FunctionReport {
    FunctionReport {
        name: function.name.clone(),
        address: function.address,
        size: function.size,
        instruction_count: function.instructions.len(),
        is_import: function.is_import,
        is_export: function.is_export,
        calls: call_references(function, function_names),
        string_refs: string_references(function, strings),
    }
}

fn call_references(
    function: &FunctionInfo,
    function_names: &HashMap<u64, String>,
) -> Vec<CallReference> {
    function
        .instructions
        .iter()
        .filter_map(|instruction| {
            let target = call_target(instruction)?;
            Some(CallReference {
                instruction_address: instruction.address(),
                target_address: target,
                target_name: function_names.get(&target).cloned(),
            })
        })
        .collect()
}

fn string_references(
    function: &FunctionInfo,
    strings: &HashMap<u64, &StringInfo>,
) -> Vec<StringReference> {
    let mut refs = Vec::new();
    let mut seen = BTreeSet::new();

    for instruction in &function.instructions {
        for address in referenced_addresses(instruction) {
            let Some(string) = strings.get(&address) else {
                continue;
            };
            if !seen.insert((instruction.address(), address)) {
                continue;
            }
            refs.push(StringReference {
                instruction_address: instruction.address(),
                address,
                symbol: string_symbol(address),
                value: string.value.clone(),
            });
        }
    }

    refs
}

fn call_target(instruction: &Instruction) -> Option<u64> {
    match instruction {
        Instruction::X86(instruction) if instruction.is_call() => instruction.near_branch_target,
        Instruction::Arm(_) if instruction.is_call() => None,
        _ => None,
    }
}

fn referenced_addresses(instruction: &Instruction) -> Vec<u64> {
    let text = match instruction {
        Instruction::X86(instruction) => {
            if instruction.operands.is_empty() {
                instruction.mnemonic.clone()
            } else {
                format!("{} {}", instruction.mnemonic, instruction.operands)
            }
        }
        Instruction::Arm(instruction) => {
            if instruction.operands.is_empty() {
                instruction.mnemonic.clone()
            } else {
                format!("{} {}", instruction.mnemonic, instruction.operands)
            }
        }
    };

    collect_hex_addresses(&text)
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

fn string_report(string: &StringInfo) -> StringReport {
    StringReport {
        address: string.address,
        symbol: string_symbol(string.address),
        value: string.value.clone(),
        encoding: format!("{:?}", string.encoding),
        length: string.length,
    }
}

fn string_symbol(address: u64) -> String {
    format!("str_{:X}", address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::FunctionInfo;
    use crate::analysis::strings::{StringEncoding, StringInfo};
    use crate::binary::parser::{ExportInfo, ImportInfo};
    use crate::disasm::control_flow::Instruction;
    use crate::disasm::X86Instruction;

    fn x86(address: u64, mnemonic: &str, operands: &str, target: Option<u64>) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: vec![0x90],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length: 1,
            near_branch_target: target,
        })
    }

    fn function(name: &str, address: u64, instructions: Vec<Instruction>) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            address,
            size: instructions.len(),
            instructions,
            is_import: false,
            is_export: false,
        }
    }

    fn string(address: u64, value: &str) -> StringInfo {
        StringInfo {
            address,
            value: value.to_string(),
            encoding: StringEncoding::Ascii,
            length: value.len(),
        }
    }

    #[test]
    fn package_maps_direct_calls_to_known_function_names() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![x86(0x1000, "call", "2000h", Some(0x2000))],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 2,
            basic_block_count: 2,
            functions: &functions,
            strings: &[],
            imports: &[],
            exports: &[],
            runtime_matches: &[],
        });

        let caller = package
            .functions
            .iter()
            .find(|function| function.name == "sub_1000")
            .expect("caller exists");

        assert_eq!(caller.calls.len(), 1);
        assert_eq!(caller.calls[0].target_address, 0x2000);
        assert_eq!(caller.calls[0].target_name.as_deref(), Some("sub_2000"));
    }

    #[test]
    fn package_maps_exact_string_references() {
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![x86(0x1000, "lea", "rcx, [3000h]", None)],
        )];
        let strings = vec![string(0x3000, "hello")];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 1,
            basic_block_count: 1,
            functions: &functions,
            strings: &strings,
            imports: &[],
            exports: &[],
            runtime_matches: &[],
        });

        let refs = &package.functions[0].string_refs;
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].address, 0x3000);
        assert_eq!(refs[0].symbol, "str_3000");
        assert_eq!(refs[0].value, "hello");
    }

    #[test]
    fn package_summary_counts_analysis_outputs() {
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![x86(0x1000, "ret", "", None)],
        )];
        let strings = vec![string(0x3000, "hello")];
        let imports = vec![ImportInfo {
            name: "kernel32.dll".to_string(),
            functions: vec!["CreateFileW".to_string()],
        }];
        let exports = vec![ExportInfo {
            name: "Exported".to_string(),
            address: 0x1000,
            ordinal: Some(1),
        }];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 1,
            basic_block_count: 1,
            functions: &functions,
            strings: &strings,
            imports: &imports,
            exports: &exports,
            runtime_matches: &[],
        });

        assert_eq!(package.summary.function_count, 1);
        assert_eq!(package.summary.string_count, 1);
        assert_eq!(package.summary.import_count, 1);
        assert_eq!(package.summary.export_count, 1);
        assert_eq!(package.imports[0].functions, vec!["CreateFileW"]);
        assert_eq!(package.exports[0].ordinal, Some(1));
    }
}
