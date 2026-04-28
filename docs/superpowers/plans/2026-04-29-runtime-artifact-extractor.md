# Runtime Artifact Extractor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a CLI mode that writes runtime-specific artifact manifests and extracts safe Python bytecode candidates.

**Architecture:** Add a pure `analysis::runtime_artifacts` module that turns runtime matches, sections, imports, exports, and strings into structured artifact records. Keep filesystem writes in `src/main.rs` so extraction logic stays unit-testable. Reuse the existing runtime detector and runtime report builder as the source of truth.

**Tech Stack:** Rust 2021, `clap` for CLI flags, `serde`/`serde_json` for manifest output, existing `SectionInfo`, `RuntimeMatch`, `StringInfo`, `ImportInfo`, and `ExportInfo` types.

---

## File Structure

- Create `src/analysis/runtime_artifacts.rs`: pure artifact extraction types, PyInstaller/Python heuristics, Dart/Flutter inventory, tests.
- Modify `src/analysis/mod.rs`: register the new module and export only non-conflicting extractor entry types.
- Modify `src/main.rs`: add `--extract-runtime-artifacts`, `--artifacts-dir`, artifact output directory resolution, manifest/report writers.
- Modify `README.md`: document the new CLI flags and feature row.

### Task 1: Runtime Artifact Analysis Module

**Files:**
- Create: `src/analysis/runtime_artifacts.rs`
- Modify: `src/analysis/mod.rs`

- [ ] **Step 1: Write the failing tests**

Add tests in `src/analysis/runtime_artifacts.rs` for:

```rust
#[test]
fn no_runtime_matches_produce_no_artifacts() {
    let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
        runtime_matches: &[],
        sections: &[],
        imports: &[],
        exports: &[],
        strings: &[],
    });

    assert!(result.artifacts.is_empty());
    assert!(result.notes.iter().any(|note| note.contains("No runtime")));
}

#[test]
fn python_pyc_magic_produces_extracted_bytecode_candidate() {
    let pyc = [
        0xA7, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xE3, 1, 2, 3,
    ];
    let sections = vec![section(".rdata", 0x4000, &[b"noise".as_slice(), &pyc].concat())];
    let runtimes = vec![runtime(RuntimeFamily::PythonPackaged)];

    let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
        runtime_matches: &runtimes,
        sections: &sections,
        imports: &[],
        exports: &[],
        strings: &[],
    });

    let artifact = result
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == RuntimeArtifactKind::PythonBytecode)
        .expect("pyc candidate should be extracted");

    assert_eq!(artifact.status, RuntimeArtifactStatus::Extracted);
    assert_eq!(artifact.virtual_address, Some(0x4005));
    assert!(artifact.file_name.as_deref().unwrap().ends_with(".pyc"));
    assert_eq!(&artifact.payload[..4], &[0xA7, 0x0D, 0x0D, 0x0A]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib runtime_artifacts`

Expected: FAIL because `RuntimeArtifactExtractor`, inputs, and artifact enums do not exist yet.

- [ ] **Step 3: Implement minimal extractor**

Create:

```rust
pub struct RuntimeArtifactExtractor;
pub struct RuntimeArtifactInputs<'a> { /* runtime_matches, sections, imports, exports, strings */ }
pub struct RuntimeArtifactResult { pub artifacts: Vec<RuntimeArtifact>, pub notes: Vec<String> }
pub struct RuntimeArtifact { pub name: String, pub kind: RuntimeArtifactKind, pub status: RuntimeArtifactStatus, pub runtime: String, pub source: String, pub virtual_address: Option<u64>, pub size: usize, pub file_name: Option<String>, pub detail: String, #[serde(skip_serializing)] pub payload: Vec<u8> }
```

Implement Python `.pyc` candidate scanning when a Python runtime is present. Treat `?? ?? 0D 0A` plus a marshal code byte at offset `+16` (`0xE3` or `0x63`) as a candidate and extract through the next candidate or section end.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib runtime_artifacts`

Expected: PASS for the initial tests.

### Task 2: Runtime Inventories

**Files:**
- Modify: `src/analysis/runtime_artifacts.rs`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```rust
#[test]
fn python_markers_without_payload_are_inventoried() {
    let sections = vec![section(".rdata", 0x5000, b"PYZ-00.pyz\0_MEIPASS\0pyi_rth_pkgres")];
    let strings = vec![string(0x5010, "pyi_rth_pkgres")];
    let runtimes = vec![runtime(RuntimeFamily::PythonPackaged)];

    let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
        runtime_matches: &runtimes,
        sections: &sections,
        imports: &[],
        exports: &[],
        strings: &strings,
    });

    assert!(result.artifacts.iter().any(|artifact| {
        artifact.status == RuntimeArtifactStatus::Inventoried
            && artifact.detail.contains("PyInstaller")
    }));
}

#[test]
fn dart_flutter_snapshot_markers_are_inventoried_without_source_claims() {
    let sections = vec![section("vm_snapshot_data", 0x6000, b"")];
    let strings = vec![string(0x6010, "dart:ui"), string(0x6020, "Flutter")];
    let runtimes = vec![runtime(RuntimeFamily::DartFlutter)];

    let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
        runtime_matches: &runtimes,
        sections: &sections,
        imports: &[],
        exports: &[],
        strings: &strings,
    });

    assert!(result.artifacts.iter().any(|artifact| artifact.name == "vm_snapshot_data"));
    assert!(result.notes.iter().any(|note| note.contains("not supported")));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib runtime_artifacts`

Expected: FAIL because marker inventory is not complete.

- [ ] **Step 3: Implement marker inventory**

Add PyInstaller marker inventory for `PYZ-00.pyz`, `_MEIPASS`, `pyi_rth`, `Nuitka`, and `__nuitka`. Add Dart/Flutter inventory for section names containing `snapshot` and strings containing `dart:ui`, `Flutter`, `kDartVmSnapshotData`, or `kDartIsolateSnapshotData`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib runtime_artifacts`

Expected: PASS.

### Task 3: CLI Artifact Writer

**Files:**
- Modify: `src/main.rs`
- Modify: `src/analysis/mod.rs`

- [ ] **Step 1: Write the failing test or compile check**

Run: `cargo build`

Expected before implementation: CLI flags do not exist and code does not compile if `main.rs` imports the new extractor before exports are added.

- [ ] **Step 2: Implement CLI flags and writer**

Add:

```rust
#[arg(long)]
extract_runtime_artifacts: bool,

#[arg(long)]
artifacts_dir: Option<String>,
```

When extraction is enabled, call `RuntimeArtifactExtractor`, create the output directory, write `artifacts_manifest.json`, write `runtime_report.txt`, and write any extracted payloads whose status is `Extracted`.

- [ ] **Step 3: Verify build**

Run: `cargo build`

Expected: PASS.

### Task 4: Docs and Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Document:

```bash
cargo run --release -- -i app.exe --extract-runtime-artifacts --artifacts-dir artifacts
```

Mention `runtime_report.txt`, `artifacts_manifest.json`, Python `.pyc` candidates, and Dart/Flutter snapshot inventory.

- [ ] **Step 2: Run full verification**

Run:

```powershell
cargo fmt --check
cargo test --lib
cargo build
git diff --check
```

Expected: all pass.

- [ ] **Step 3: Smoke test**

Run:

```powershell
$dir = Join-Path $env:TEMP 'cyberm4fia_runtime_artifacts_smoke'
if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
cargo run --release -- -i C:\Windows\System32\notepad.exe --extract-runtime-artifacts --artifacts-dir $dir
Test-Path (Join-Path $dir 'runtime_report.txt')
Test-Path (Join-Path $dir 'artifacts_manifest.json')
```

Expected: both `Test-Path` calls print `True`, and the report says no runtime artifacts were found.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add -- README.md src/analysis/mod.rs src/analysis/runtime_artifacts.rs src/main.rs docs/superpowers/plans/2026-04-29-runtime-artifact-extractor.md
git commit -m "feat: extract runtime artifacts"
git push origin master
```
