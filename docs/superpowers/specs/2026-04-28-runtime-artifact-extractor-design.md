# Runtime Artifact Extractor Design

## Goal

Add a CLI mode that extracts runtime-specific artifacts from analyzed binaries, starting with Python/PyInstaller-style payloads and lightweight Dart/Flutter snapshot inventory.

The feature should make `cyberm4fia-re` more useful than a plain C-like decompiler when the input binary was produced by a high-level runtime. It should not claim exact source recovery when the binary format cannot support it.

## User-Facing Behavior

Add:

```bash
decompiler -i app.exe --extract-runtime-artifacts --artifacts-dir artifacts
```

The command still parses the binary, extracts sections and strings, detects runtime families, and writes the normal C output when `-o` is provided. When extraction is enabled, it also creates an artifact directory containing:

- `runtime_report.txt` with detected runtimes, confidence, evidence, and recommended next steps.
- `artifacts_manifest.json` with every extracted or inventoried artifact.
- Extracted binary payloads when the extractor can safely identify byte ranges.

The default artifact directory is `<input file stem>_artifacts` when `--artifacts-dir` is omitted.

## First Slice Scope

The first implementation focuses on safe, testable extraction without pretending to be a full runtime decompiler.

Python/PyInstaller:

- Detect likely PyInstaller archive markers from section bytes and strings.
- Extract recognizable embedded Python bytecode candidates using CPython `.pyc` magic patterns.
- Inventory `PYZ`, `_MEIPASS`, `pyi_rth`, `Nuitka`, and Python DLL/import evidence even when exact extraction is not possible.
- Label each artifact as `extracted` or `inventoried`.

Dart/Flutter:

- Inventory AOT/snapshot indicators such as `vm_snapshot`, `isolate_snapshot`, `kDartVmSnapshotData`, `kDartIsolateSnapshotData`, and Flutter asset strings.
- Do not promise Dart source reconstruction. The report should clearly say AOT binaries require native/snapshot analysis.

Other runtimes:

- Reuse the runtime report output.
- Add manifest entries only for strong evidence already detected by the runtime detector.

## Architecture

Add a new analysis module:

```text
src/analysis/runtime_artifacts.rs
```

Core types:

- `RuntimeArtifactExtractor`
- `RuntimeArtifactInputs`
- `RuntimeArtifactResult`
- `RuntimeArtifact`
- `RuntimeArtifactKind`
- `RuntimeArtifactStatus`

The extractor is pure analysis. It receives runtime matches, sections, imports, exports, and strings. It returns structured results and payload byte ranges. It does not write files directly.

Add a small CLI output layer in `src/main.rs` that:

- Resolves the output directory.
- Creates directories.
- Writes manifest/report files.
- Writes extracted payload bytes.

This keeps filesystem behavior out of the analysis module and makes the extractor unit-testable.

## Data Flow

```text
parse_binary
  -> collect sections/imports/exports/strings
  -> RuntimeDetector
  -> RuntimeReportBuilder
  -> RuntimeArtifactExtractor
  -> CLI artifact writer
```

The normal decompilation pipeline remains intact. Artifact extraction is an additional side path enabled by a CLI flag.

## Error Handling

Extraction should be best-effort:

- If no runtime is detected, still write a report saying no runtime artifacts were found.
- If an artifact directory cannot be created, return an error.
- If one payload cannot be written, fail the command with the artifact path in the error.
- Do not panic on malformed binaries or tiny sections.
- Avoid duplicate artifact names by adding stable numeric suffixes.

## Testing

Unit tests for the analysis module:

- No runtime matches produce an empty extraction result.
- PyInstaller/Python inputs with `.pyc` magic produce extracted bytecode artifact candidates.
- Python markers without byte ranges produce inventoried artifacts.
- Dart/Flutter snapshot strings produce inventoried snapshot artifacts and no source-recovery claim.
- Duplicate artifact names are made stable by the CLI/file naming helper or manifest builder.

CLI-level smoke:

- Existing `cargo test --lib`.
- `cargo build`.
- Run against `C:\Windows\System32\notepad.exe` with extraction enabled to verify the no-runtime path does not create false positives.

## Non-Goals

- Full PyInstaller CArchive parsing in the first slice.
- Bytecode-to-Python source decompilation in the first slice.
- Dart AOT to Dart source recovery.
- Running external tools such as `uncompyle6`, `pycdc`, `pyinstxtractor`, `ilspycmd`, or `dnSpy`.

Those can become follow-up integrations after the local extractor produces reliable manifests.
