//! Runtime and source-language family detection.
//!
//! This pass does not promise source recovery. It identifies strong packaging,
//! VM, and language-runtime fingerprints so later stages can choose a better
//! analysis path: Python bundle extraction, CLR/IL guidance, Dart/Flutter AOT
//! reporting, or native pseudocode fallback.

use crate::analysis::strings::StringInfo;
use crate::binary::parser::{ExportInfo, ImportInfo, SectionInfo};

/// Inputs used by runtime/language detection.
pub struct RuntimeDetectionInputs<'a> {
    pub sections: &'a [SectionInfo],
    pub imports: &'a [ImportInfo],
    pub exports: &'a [ExportInfo],
    pub strings: &'a [StringInfo],
}

/// High-level runtime or source-language family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFamily {
    PythonPackaged,
    PythonNative,
    DartFlutter,
    DotNetClr,
    Go,
    Rust,
    ElectronNode,
    Jvm,
}

impl RuntimeFamily {
    pub fn name(self) -> &'static str {
        match self {
            RuntimeFamily::PythonPackaged => "Python packaged executable",
            RuntimeFamily::PythonNative => "Python native/embedded runtime",
            RuntimeFamily::DartFlutter => "Dart/Flutter AOT",
            RuntimeFamily::DotNetClr => ".NET CLR",
            RuntimeFamily::Go => "Go native binary",
            RuntimeFamily::Rust => "Rust native binary",
            RuntimeFamily::ElectronNode => "Electron/Node packaged app",
            RuntimeFamily::Jvm => "JVM/Java packaged app",
        }
    }
}

/// One detected runtime family with human-readable evidence.
#[derive(Debug, Clone)]
pub struct RuntimeMatch {
    pub family: RuntimeFamily,
    pub name: &'static str,
    pub confidence: u8,
    pub evidence: Vec<String>,
    pub guidance: &'static str,
}

/// Conservative runtime detector.
pub struct RuntimeDetector;

impl RuntimeDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, inputs: RuntimeDetectionInputs<'_>) -> Vec<RuntimeMatch> {
        let mut matches = Vec::new();

        push_if_some(&mut matches, detect_python_packaged(&inputs));
        push_if_some(&mut matches, detect_python_native(&inputs));
        push_if_some(&mut matches, detect_dart_flutter(&inputs));
        push_if_some(&mut matches, detect_dotnet(&inputs));
        push_if_some(&mut matches, detect_go(&inputs));
        push_if_some(&mut matches, detect_rust(&inputs));
        push_if_some(&mut matches, detect_electron_node(&inputs));
        push_if_some(&mut matches, detect_jvm(&inputs));

        matches.sort_by(|left, right| {
            right
                .confidence
                .cmp(&left.confidence)
                .then_with(|| left.name.cmp(right.name))
        });
        matches
    }
}

impl Default for RuntimeDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn push_if_some(matches: &mut Vec<RuntimeMatch>, runtime: Option<RuntimeMatch>) {
    if let Some(runtime) = runtime {
        matches.push(runtime);
    }
}

fn detect_python_packaged(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();

    add_string_evidence(
        inputs,
        &mut evidence,
        "PYZ-00.pyz",
        "PyInstaller PYZ archive",
    );
    add_string_evidence(
        inputs,
        &mut evidence,
        "_MEIPASS",
        "PyInstaller temp extraction marker",
    );
    add_string_evidence(inputs, &mut evidence, "pyi_rth", "PyInstaller runtime hook");
    add_string_evidence(inputs, &mut evidence, "__nuitka", "Nuitka marker");
    add_string_evidence(inputs, &mut evidence, "Nuitka", "Nuitka marker");

    if import_name_contains(inputs, "python") {
        evidence.push("imports Python runtime library".to_string());
    }

    make_match(
        RuntimeFamily::PythonPackaged,
        evidence,
        "Try extracting embedded archives and decompiling recovered .pyc files; native Nuitka/Cython output falls back to native analysis.",
    )
}

fn detect_python_native(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();

    if import_name_contains(inputs, "python") {
        evidence.push("imports Python runtime library".to_string());
    }
    if import_function_contains(inputs, "Py_Initialize") {
        evidence.push("imports Py_Initialize".to_string());
    }
    if import_function_contains(inputs, "PyImport_") {
        evidence.push("imports PyImport API".to_string());
    }
    add_string_evidence(
        inputs,
        &mut evidence,
        "Py_Initialize",
        "CPython embedding API",
    );
    add_string_evidence(inputs, &mut evidence, "PyImport_", "CPython import API");

    make_match(
        RuntimeFamily::PythonNative,
        evidence,
        "Python runtime is present, but source recovery depends on whether bytecode or packaged modules remain embedded.",
    )
}

fn detect_dart_flutter(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();

    add_section_evidence(
        inputs,
        &mut evidence,
        "vm_snapshot",
        "Dart VM snapshot section",
    );
    add_section_evidence(
        inputs,
        &mut evidence,
        "isolate_snapshot",
        "Dart isolate snapshot section",
    );
    add_string_evidence(inputs, &mut evidence, "Flutter", "Flutter marker");
    add_string_evidence(inputs, &mut evidence, "Dart VM", "Dart VM marker");
    add_string_evidence(inputs, &mut evidence, "dart:ui", "Flutter dart:ui library");
    add_string_evidence(
        inputs,
        &mut evidence,
        "_kDartIsolateSnapshotInstructions",
        "Dart AOT snapshot symbol",
    );

    make_match(
        RuntimeFamily::DartFlutter,
        evidence,
        "Dart/Flutter release builds are usually AOT native code; recover metadata, strings, and native pseudocode rather than exact Dart source.",
    )
}

fn detect_dotnet(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();
    let mut has_strong_clr_marker = false;

    if import_name_contains(inputs, "mscoree") {
        evidence.push("imports mscoree.dll".to_string());
        has_strong_clr_marker = true;
    }
    if import_function_contains(inputs, "_CorExeMain") {
        evidence.push("imports _CorExeMain".to_string());
        has_strong_clr_marker = true;
    }
    if has_string_or_section_marker(inputs, "BSJB") {
        evidence.push(".NET metadata signature".to_string());
        has_strong_clr_marker = true;
    }
    if has_strong_clr_marker && has_string_or_section_marker(inputs, "#~") {
        evidence.push(".NET metadata stream".to_string());
    }

    if !has_strong_clr_marker {
        return None;
    }

    make_match(
        RuntimeFamily::DotNetClr,
        evidence,
        ".NET keeps IL and metadata; prefer CLR metadata/IL decompilation before native pseudocode.",
    )
}

fn detect_go(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();

    add_section_evidence(inputs, &mut evidence, ".gopclntab", "Go pclntab section");
    add_section_evidence(
        inputs,
        &mut evidence,
        "go.buildinfo",
        "Go build info section",
    );
    add_string_evidence(inputs, &mut evidence, "Go build ID:", "Go build id");
    add_string_evidence(
        inputs,
        &mut evidence,
        "runtime.gopanic",
        "Go runtime symbol",
    );
    add_string_evidence(inputs, &mut evidence, "runtime.main", "Go runtime symbol");

    make_match(
        RuntimeFamily::Go,
        evidence,
        "Go is native code but often preserves pclntab/buildinfo for function names and richer call graph recovery.",
    )
}

fn detect_rust(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();

    add_string_evidence(inputs, &mut evidence, "core::panicking", "Rust panic path");
    add_string_evidence(inputs, &mut evidence, "rust_panic", "Rust panic symbol");
    add_string_evidence(
        inputs,
        &mut evidence,
        "rust_begin_unwind",
        "Rust unwind symbol",
    );
    add_string_evidence(
        inputs,
        &mut evidence,
        "std::rt::lang_start",
        "Rust runtime entry",
    );

    make_match(
        RuntimeFamily::Rust,
        evidence,
        "Rust is native code; use symbol remnants, panic paths, strings, and native decompilation rather than expecting source recovery.",
    )
}

fn detect_electron_node(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();

    if import_name_contains(inputs, "node") {
        evidence.push("imports Node runtime library".to_string());
    }
    add_string_evidence(inputs, &mut evidence, "Electron", "Electron marker");
    add_string_evidence(inputs, &mut evidence, "app.asar", "Electron asar archive");
    add_string_evidence(inputs, &mut evidence, "node_modules", "Node package tree");
    add_string_evidence(
        inputs,
        &mut evidence,
        "resources/app",
        "Electron resources path",
    );

    make_match(
        RuntimeFamily::ElectronNode,
        evidence,
        "Look for app.asar/resources and JavaScript assets before treating the executable as only native code.",
    )
}

fn detect_jvm(inputs: &RuntimeDetectionInputs<'_>) -> Option<RuntimeMatch> {
    let mut evidence = Vec::new();

    add_string_evidence(
        inputs,
        &mut evidence,
        "java/lang/Object",
        "JVM class reference",
    );
    add_string_evidence(
        inputs,
        &mut evidence,
        "META-INF/MANIFEST.MF",
        "JAR manifest",
    );
    add_string_evidence(inputs, &mut evidence, "Launch4j", "Java exe wrapper");
    if import_name_contains(inputs, "jvm") {
        evidence.push("imports JVM runtime library".to_string());
    }

    make_match(
        RuntimeFamily::Jvm,
        evidence,
        "JVM packaging may contain class/JAR content; prefer bytecode decompilation when classes can be extracted.",
    )
}

fn make_match(
    family: RuntimeFamily,
    evidence: Vec<String>,
    guidance: &'static str,
) -> Option<RuntimeMatch> {
    if evidence.is_empty() {
        return None;
    }

    let confidence = (60 + evidence.len().saturating_sub(1) as u8 * 15).min(95);
    Some(RuntimeMatch {
        family,
        name: family.name(),
        confidence,
        evidence,
        guidance,
    })
}

fn add_section_evidence(
    inputs: &RuntimeDetectionInputs<'_>,
    evidence: &mut Vec<String>,
    needle: &str,
    label: &str,
) {
    if let Some(section) = inputs
        .sections
        .iter()
        .find(|section| contains_case_insensitive(&section.name, needle))
    {
        evidence.push(format!("{} ({})", label, section.name));
    }
}

fn add_string_evidence(
    inputs: &RuntimeDetectionInputs<'_>,
    evidence: &mut Vec<String>,
    needle: &str,
    label: &str,
) {
    if has_string_or_section_marker(inputs, needle) {
        evidence.push(label.to_string());
    }
}

fn has_string_or_section_marker(inputs: &RuntimeDetectionInputs<'_>, needle: &str) -> bool {
    inputs
        .strings
        .iter()
        .any(|string| contains_case_insensitive(&string.value, needle))
        || inputs
            .sections
            .iter()
            .any(|section| contains_ascii_bytes_case_insensitive(&section.raw_data, needle))
}

fn import_name_contains(inputs: &RuntimeDetectionInputs<'_>, needle: &str) -> bool {
    inputs
        .imports
        .iter()
        .any(|import| contains_case_insensitive(&import.name, needle))
}

fn import_function_contains(inputs: &RuntimeDetectionInputs<'_>, needle: &str) -> bool {
    inputs.imports.iter().any(|import| {
        import
            .functions
            .iter()
            .any(|function| contains_case_insensitive(function, needle))
    })
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn contains_ascii_bytes_case_insensitive(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| ascii_bytes_eq_ignore_case(window, needle))
}

fn ascii_bytes_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.iter()
        .zip(right.iter())
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::strings::{StringEncoding, StringInfo};
    use crate::binary::parser::{ExportInfo, ImportInfo, SectionCharacteristics, SectionInfo};

    fn section(name: &str, data: &[u8]) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            virtual_address: 0x1000,
            size: data.len() as u64,
            raw_data: data.to_vec(),
            characteristics: SectionCharacteristics::default(),
        }
    }

    fn import(name: &str, functions: &[&str]) -> ImportInfo {
        ImportInfo {
            name: name.to_string(),
            functions: functions.iter().map(|name| name.to_string()).collect(),
        }
    }

    fn string(value: &str) -> StringInfo {
        StringInfo {
            address: 0x2000,
            value: value.to_string(),
            encoding: StringEncoding::Ascii,
            length: value.len(),
        }
    }

    fn detect(
        sections: &[SectionInfo],
        imports: &[ImportInfo],
        strings: &[StringInfo],
    ) -> Vec<RuntimeMatch> {
        RuntimeDetector::new().detect(RuntimeDetectionInputs {
            sections,
            imports,
            exports: &[] as &[ExportInfo],
            strings,
        })
    }

    fn match_for(matches: &[RuntimeMatch], family: RuntimeFamily) -> &RuntimeMatch {
        matches
            .iter()
            .find(|runtime| runtime.family == family)
            .expect("runtime family should be detected")
    }

    #[test]
    fn detects_pyinstaller_style_python_bundle() {
        let sections = vec![section(
            ".rdata",
            b"\xFFPYZ-00.pyz\0_MEIPASS\0pyi_rth_pkgres",
        )];
        let imports = vec![import("python311.dll", &["Py_Initialize"])];
        let strings = vec![string("pyi_rth_pkgres")];

        let matches = detect(&sections, &imports, &strings);
        let python = match_for(&matches, RuntimeFamily::PythonPackaged);

        assert!(python.confidence >= 90);
        assert!(python.evidence.iter().any(|item| item.contains("PYZ")));
        assert!(python.guidance.contains(".pyc"));
    }

    #[test]
    fn detects_embedded_cpython_without_packager_markers() {
        let sections = vec![];
        let imports = vec![import(
            "python310.dll",
            &["Py_Initialize", "PyImport_Import"],
        )];
        let strings = vec![];

        let matches = detect(&sections, &imports, &strings);
        let python = match_for(&matches, RuntimeFamily::PythonNative);

        assert!(python.confidence >= 75);
        assert!(python.guidance.contains("bytecode"));
    }

    #[test]
    fn detects_dart_flutter_aot_snapshot_indicators() {
        let sections = vec![
            section("vm_snapshot_data", b""),
            section("isolate_snapshot_instructions", b""),
        ];
        let imports = vec![];
        let strings = vec![
            string("Flutter"),
            string("_kDartIsolateSnapshotInstructions"),
            string("dart:ui"),
        ];

        let matches = detect(&sections, &imports, &strings);
        let dart = match_for(&matches, RuntimeFamily::DartFlutter);

        assert!(dart.confidence >= 85);
        assert!(dart.guidance.contains("AOT"));
    }

    #[test]
    fn detects_dotnet_clr_from_imports_and_metadata() {
        let sections = vec![section(".text", b"BSJB metadata root")];
        let imports = vec![import("mscoree.dll", &["_CorExeMain"])];
        let strings = vec![];

        let matches = detect(&sections, &imports, &strings);
        let dotnet = match_for(&matches, RuntimeFamily::DotNetClr);

        assert!(dotnet.confidence >= 90);
        assert!(dotnet.guidance.contains("IL"));
    }

    #[test]
    fn ignores_weak_dotnet_metadata_stream_without_clr_markers() {
        let sections = vec![section(".rdata", b"native bytes with incidental #~ marker")];
        let imports = vec![];
        let strings = vec![];

        let matches = detect(&sections, &imports, &strings);

        assert!(matches
            .iter()
            .all(|runtime| runtime.family != RuntimeFamily::DotNetClr));
    }

    #[test]
    fn detects_go_runtime_markers() {
        let sections = vec![section(".gopclntab", b"")];
        let imports = vec![];
        let strings = vec![string("Go build ID:"), string("runtime.gopanic")];

        let matches = detect(&sections, &imports, &strings);
        let go = match_for(&matches, RuntimeFamily::Go);

        assert!(go.confidence >= 80);
        assert!(go.evidence.iter().any(|item| item.contains(".gopclntab")));
    }

    #[test]
    fn detects_rust_runtime_markers() {
        let sections = vec![];
        let imports = vec![];
        let strings = vec![string("core::panicking::panic_fmt"), string("rust_panic")];

        let matches = detect(&sections, &imports, &strings);
        let rust = match_for(&matches, RuntimeFamily::Rust);

        assert!(rust.confidence >= 75);
        assert!(rust.guidance.contains("native"));
    }

    #[test]
    fn detects_electron_node_packaged_apps() {
        let sections = vec![section(".rdata", b"app.asar\0node_modules\0Electron")];
        let imports = vec![import("node.dll", &[])];
        let strings = vec![string("app.asar")];

        let matches = detect(&sections, &imports, &strings);
        let electron = match_for(&matches, RuntimeFamily::ElectronNode);

        assert!(electron.confidence >= 85);
        assert!(electron.guidance.contains("asar"));
    }

    #[test]
    fn detects_jvm_wrappers_and_embedded_class_content() {
        let sections = vec![section(".rdata", b"META-INF/MANIFEST.MF\0java/lang/Object")];
        let imports = vec![import("jvm.dll", &["JNI_CreateJavaVM"])];
        let strings = vec![string("Launch4j")];

        let matches = detect(&sections, &imports, &strings);
        let jvm = match_for(&matches, RuntimeFamily::Jvm);

        assert!(jvm.confidence >= 90);
        assert!(jvm.guidance.contains("bytecode"));
    }

    #[test]
    fn returns_no_matches_for_empty_inputs() {
        let matches = detect(&[], &[], &[]);

        assert!(matches.is_empty());
    }
}
