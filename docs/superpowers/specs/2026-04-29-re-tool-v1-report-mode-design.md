# Reverse Engineering Tool V1 Report Mode Design

## Goal

Turn `cyberm4fia-re` from a decompiler-only CLI into a practical reverse-engineering assistant that produces a complete triage package for one binary.

The v1 target is not a Ghidra/IDA clone. It is a useful first-pass analyzer: parse the binary, detect runtime families, recover functions, map calls and string references, write readable C output, and save structured reports.

## User-Facing Behavior

Add:

```bash
decompiler -i app.exe --report-dir out
```

When `--report-dir` is present, the tool writes:

- `report.txt`: human-readable triage summary.
- `decompiled.c`: generated C output when `-o` is not supplied.
- `functions.json`: function map with calls and string references.
- `strings.json`: extracted strings.
- `imports.json`: import table.
- `exports.json`: export table.
- `analysis_package.json`: combined structured package.
- `runtime_report.txt` and `artifacts_manifest.json`: existing runtime artifact outputs, written into the same report directory unless `--artifacts-dir` overrides it.

The existing `-o` behavior remains. If both `--report-dir` and `-o` are supplied, C output goes to `-o`, while the report package still goes to `--report-dir`.

## Analysis Content

Function reports include:

- Function name, address, size, export/import flags, and instruction count.
- Direct call targets for x86/x64 near calls, including target function names when known.
- String references found in instruction text by exact extracted string address.

The report package stays conservative: unresolved calls remain address-only, ARM call-target recovery remains a future improvement, and string references only appear when the binary exposes exact referenced addresses.

## Architecture

Add:

```text
src/analysis/report.rs
```

The module is pure analysis:

- It receives parsed data and analysis outputs.
- It returns serializable owned structs.
- It does not write files.

`src/main.rs` owns filesystem behavior:

- Resolve/create the report directory.
- Write JSON and text files.
- Route `decompiled.c` into the report directory when no `-o` was supplied.

## Testing

Add unit tests for:

- A synthetic function that calls another function produces a named call reference.
- A synthetic instruction referencing `3000h` produces a string reference to `str_3000`.
- Summary counts cover functions, strings, imports, exports, instructions, and basic blocks.

Full verification:

- `cargo fmt --check`
- `cargo test --lib`
- `cargo build`
- `git diff --check`
- Smoke run against `C:\Windows\System32\notepad.exe --report-dir <temp>`

## Non-Goals

- Full semantic C decompilation.
- ARM direct-call target recovery.
- Precise parameter/type inference.
- External tool orchestration.
