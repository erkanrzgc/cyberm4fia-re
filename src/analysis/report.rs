//! Structured reverse-engineering report package.

use crate::analysis::functions::FunctionInfo;
use crate::analysis::runtime::RuntimeMatch;
use crate::analysis::strings::StringInfo;
use crate::binary::parser::{ExportInfo, ImportInfo, SectionInfo};
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
    pub sections: &'a [SectionInfo],
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
    pub cfg_summary: CfgSummaryReport,
    pub functions: Vec<FunctionReport>,
    pub call_graph: Vec<CallGraphEdge>,
    pub sections: Vec<SectionReport>,
    pub strings: Vec<StringReport>,
    pub suspicious_strings: Vec<SuspiciousStringReport>,
    pub strings_by_function: Vec<FunctionStringIndex>,
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

/// CFG-wide summary for quick triage.
#[derive(Debug, Clone, Serialize)]
pub struct CfgSummaryReport {
    pub basic_block_count: usize,
    pub direct_call_count: usize,
    pub conditional_branch_count: usize,
    pub unconditional_branch_count: usize,
    pub return_count: usize,
}

/// Function relationship report.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionReport {
    pub name: String,
    pub address: u64,
    pub size: usize,
    pub instruction_count: usize,
    pub basic_block_estimate: usize,
    pub is_import: bool,
    pub is_export: bool,
    pub calls: Vec<CallReference>,
    pub string_refs: Vec<StringReference>,
}

/// One call graph edge, grouped by caller and callee.
#[derive(Debug, Clone, Serialize)]
pub struct CallGraphEdge {
    pub caller_name: String,
    pub caller_address: u64,
    pub callee_address: u64,
    pub callee_name: Option<String>,
    pub call_count: usize,
    pub call_sites: Vec<u64>,
}

/// Binary section report.
#[derive(Debug, Clone, Serialize)]
pub struct SectionReport {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub raw_size: usize,
    pub is_code: bool,
    pub is_data: bool,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
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

/// Suspicious or high-signal string report.
#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousStringReport {
    pub address: u64,
    pub symbol: String,
    pub value: String,
    pub category: String,
}

/// String references grouped by function.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionStringIndex {
    pub function_name: String,
    pub function_address: u64,
    pub strings: Vec<StringReference>,
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

        let functions = inputs
            .functions
            .iter()
            .map(|function| function_report(function, &function_names, &string_map))
            .collect::<Vec<_>>();
        let cfg_summary = cfg_summary(inputs.basic_block_count, inputs.functions);
        let call_graph = call_graph_edges(&functions);
        let strings_by_function = strings_by_function(&functions);

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
            cfg_summary,
            functions,
            call_graph,
            sections: inputs.sections.iter().map(section_report).collect(),
            strings: string_reports,
            suspicious_strings: inputs
                .strings
                .iter()
                .filter_map(suspicious_string_report)
                .collect(),
            strings_by_function,
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

fn call_graph_edges(functions: &[FunctionReport]) -> Vec<CallGraphEdge> {
    let mut edges: HashMap<(u64, u64), CallGraphEdge> = HashMap::new();

    for function in functions {
        for call in &function.calls {
            let edge = edges
                .entry((function.address, call.target_address))
                .or_insert_with(|| CallGraphEdge {
                    caller_name: function.name.clone(),
                    caller_address: function.address,
                    callee_address: call.target_address,
                    callee_name: call.target_name.clone(),
                    call_count: 0,
                    call_sites: Vec::new(),
                });
            edge.call_count += 1;
            edge.call_sites.push(call.instruction_address);
        }
    }

    let mut edges = edges.into_values().collect::<Vec<_>>();
    edges.sort_by_key(|edge| (edge.caller_address, edge.callee_address));
    edges
}

fn strings_by_function(functions: &[FunctionReport]) -> Vec<FunctionStringIndex> {
    functions
        .iter()
        .filter(|function| !function.string_refs.is_empty())
        .map(|function| FunctionStringIndex {
            function_name: function.name.clone(),
            function_address: function.address,
            strings: function.string_refs.clone(),
        })
        .collect()
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
        basic_block_estimate: basic_block_estimate(function),
        is_import: function.is_import,
        is_export: function.is_export,
        calls: call_references(function, function_names),
        string_refs: string_references(function, strings),
    }
}

fn cfg_summary(basic_block_count: usize, functions: &[FunctionInfo]) -> CfgSummaryReport {
    let mut direct_call_count = 0;
    let mut conditional_branch_count = 0;
    let mut unconditional_branch_count = 0;
    let mut return_count = 0;

    for instruction in functions.iter().flat_map(|function| &function.instructions) {
        if instruction.is_call() {
            direct_call_count += 1;
        }
        if instruction.is_conditional_jump() {
            conditional_branch_count += 1;
        }
        if instruction.is_unconditional_jump() {
            unconditional_branch_count += 1;
        }
        if instruction.is_return() {
            return_count += 1;
        }
    }

    CfgSummaryReport {
        basic_block_count,
        direct_call_count,
        conditional_branch_count,
        unconditional_branch_count,
        return_count,
    }
}

fn basic_block_estimate(function: &FunctionInfo) -> usize {
    let branch_or_call_count = function
        .instructions
        .iter()
        .filter(|instruction| {
            instruction.is_call()
                || instruction.is_conditional_jump()
                || instruction.is_unconditional_jump()
        })
        .count();

    if function.instructions.is_empty() {
        0
    } else {
        branch_or_call_count + 1
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

fn section_report(section: &SectionInfo) -> SectionReport {
    SectionReport {
        name: section.name.clone(),
        virtual_address: section.virtual_address,
        size: section.size,
        raw_size: section.raw_data.len(),
        is_code: section.characteristics.is_code,
        is_data: section.characteristics.is_data,
        is_readable: section.characteristics.is_readable,
        is_writable: section.characteristics.is_writable,
        is_executable: section.characteristics.is_executable,
    }
}

fn suspicious_string_report(string: &StringInfo) -> Option<SuspiciousStringReport> {
    let category = suspicious_string_category(&string.value)?;
    Some(SuspiciousStringReport {
        address: string.address,
        symbol: string_symbol(string.address),
        value: string.value.clone(),
        category: category.to_string(),
    })
}

fn suspicious_string_category(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some("url")
    } else if lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("/bin/sh")
        || lower.contains("curl ")
        || lower.contains("wget ")
    {
        Some("command")
    } else if lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("secret")
    {
        Some("credential_hint")
    } else if lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".sys")
        || lower.contains("\\software\\")
    {
        Some("platform_indicator")
    } else {
        None
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
    use crate::binary::parser::{ExportInfo, ImportInfo, SectionCharacteristics, SectionInfo};
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
            sections: &[],
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
            sections: &[],
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
            sections: &[],
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

    fn section(
        name: &str,
        address: u64,
        size: u64,
        characteristics: SectionCharacteristics,
    ) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            virtual_address: address,
            size,
            raw_data: vec![0; size as usize],
            characteristics,
        }
    }

    #[test]
    fn package_includes_sections_cfg_summary_and_suspicious_strings() {
        let sections = vec![
            section(
                ".text",
                0x1000,
                0x200,
                SectionCharacteristics {
                    is_code: true,
                    is_readable: true,
                    is_executable: true,
                    ..SectionCharacteristics::default()
                },
            ),
            section(
                ".rdata",
                0x3000,
                0x80,
                SectionCharacteristics {
                    is_data: true,
                    is_readable: true,
                    ..SectionCharacteristics::default()
                },
            ),
        ];
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![
                x86(0x1000, "call", "2000h", Some(0x2000)),
                x86(0x1005, "jne", "1010h", Some(0x1010)),
            ],
        )];
        let strings = vec![string(0x3000, "http://evil.test/payload")];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 2,
            basic_block_count: 3,
            sections: &sections,
            functions: &functions,
            strings: &strings,
            imports: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(package.sections.len(), 2);
        assert_eq!(package.sections[0].name, ".text");
        assert!(package.sections[0].is_executable);
        assert_eq!(package.cfg_summary.basic_block_count, 3);
        assert_eq!(package.cfg_summary.direct_call_count, 1);
        assert_eq!(package.cfg_summary.conditional_branch_count, 1);
        assert_eq!(package.functions[0].basic_block_estimate, 3);
        assert_eq!(package.suspicious_strings[0].address, 0x3000);
        assert_eq!(package.suspicious_strings[0].category, "url");
    }

    #[test]
    fn package_builds_deduplicated_call_graph_edges_with_call_sites() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![
                    x86(0x1000, "call", "2000h", Some(0x2000)),
                    x86(0x1005, "call", "2000h", Some(0x2000)),
                ],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 3,
            basic_block_count: 2,
            sections: &[],
            functions: &functions,
            strings: &[],
            imports: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(package.call_graph.len(), 1);
        assert_eq!(package.call_graph[0].caller_name, "sub_1000");
        assert_eq!(
            package.call_graph[0].callee_name.as_deref(),
            Some("sub_2000")
        );
        assert_eq!(package.call_graph[0].call_count, 2);
        assert_eq!(package.call_graph[0].call_sites, vec![0x1000, 0x1005]);
    }

    #[test]
    fn package_indexes_strings_by_function() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![x86(0x1000, "lea", "rcx, [3000h]", None)],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
        ];
        let strings = vec![string(0x3000, "hello")];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 2,
            basic_block_count: 2,
            sections: &[],
            functions: &functions,
            strings: &strings,
            imports: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(package.strings_by_function.len(), 1);
        assert_eq!(package.strings_by_function[0].function_name, "sub_1000");
        assert_eq!(package.strings_by_function[0].strings.len(), 1);
        assert_eq!(package.strings_by_function[0].strings[0].symbol, "str_3000");
    }
}
