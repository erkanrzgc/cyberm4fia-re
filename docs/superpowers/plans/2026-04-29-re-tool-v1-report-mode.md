# Reverse Engineering Tool V1 Report Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--report-dir` and structured reverse-engineering report files with function call and string-reference maps.

**Architecture:** Create a pure `analysis::report` module that builds serializable report structs from existing parser, runtime, function, string, and artifact outputs. Keep all filesystem writes in `src/main.rs`, reusing the runtime artifact writer for `runtime_report.txt` and `artifacts_manifest.json`.

**Tech Stack:** Rust 2021, `serde`, `serde_json`, `clap`, existing `FunctionInfo`, `Instruction`, `StringInfo`, `ImportInfo`, `ExportInfo`, and runtime analysis types.

---

### Task 1: Analysis Report Module

**Files:**
- Create: `src/analysis/report.rs`
- Modify: `src/analysis/mod.rs`

- [ ] Write failing unit tests for function call mapping, string-reference mapping, and summary counts.
- [ ] Run `cargo test --lib report` and confirm missing types/functions fail.
- [ ] Implement `AnalysisReportBuilder`, `AnalysisReportInputs`, `AnalysisReportPackage`, summary, function, call, string, import, and export structs.
- [ ] Run `cargo test --lib report` and confirm tests pass.

### Task 2: CLI Report Directory

**Files:**
- Modify: `src/main.rs`

- [ ] Add `--report-dir`.
- [ ] Build an `AnalysisReportPackage` after function/CFG/string/runtime analysis.
- [ ] Write `report.txt`, `functions.json`, `strings.json`, `imports.json`, `exports.json`, and `analysis_package.json`.
- [ ] Route generated C to `<report-dir>/decompiled.c` when `--report-dir` is present and `-o` is absent.
- [ ] Reuse runtime artifact extraction when `--report-dir` is present.
- [ ] Run `cargo build`.

### Task 3: Docs and Verification

**Files:**
- Modify: `README.md`

- [ ] Document `--report-dir out`.
- [ ] Update tests badge/table.
- [ ] Run `cargo fmt --check`, `cargo test --lib`, `cargo build`, and `git diff --check`.
- [ ] Smoke test `notepad.exe` with a fresh temp report directory and verify all report files exist.
- [ ] Commit and push.
