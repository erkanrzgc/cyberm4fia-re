<h1 align="center">cyberm4fia-re</h1>

<p align="center">
  <img src="https://img.shields.io/badge/mission-reverse%20engineering%20via%20rust-red?style=for-the-badge" alt="mission">
</p>

<table align="center"><tr><td valign="middle">
<pre>
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

</pre>
</td><td valign="middle">
<img src="assets/reverse-engineering.png" width="150" alt="reverse engineering">
</td></tr></table>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.75+-blue?style=flat-square&logo=rust" alt="rust">
  <img src="https://img.shields.io/badge/crates-12+-purple?style=flat-square" alt="crates">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/tests-96%20passing-orange?style=flat-square" alt="tests">
  <img src="https://img.shields.io/github/last-commit/erkanrzgc/cyberm4fia-re?style=flat-square" alt="last commit">
</p>

<p align="center">
  <b>cyberm4fia-re</b> is a Rust-powered binary decompiler for ELF, PE, and Mach-O executables —
  disassembles x86 & ARM, detects runtime/language families, emits runtime-specific analysis reports,
  builds control-flow graphs, detects functions, recovers simple stack variables, annotates string references,
  and generates syntax-safe readable C code.
</p>

---

## Features

### Binary Formats

| Format | Description |
|--------|-------------|
| **ELF** | Linux/Unix executables and shared objects |
| **PE** | Windows `.exe` and `.dll` (32-bit & 64-bit) |
| **Mach-O** | macOS executables and dylibs |

### Architectures

| Architecture | Engine |
|---|---|
| x86 / x86-64 | `iced-x86` |
| ARM / AArch64 | `capstone` |

### Decompilation Pipeline

| Stage | Description |
|---|---|
| **Runtime Detection** | Python/PyInstaller/Nuitka, Dart/Flutter, .NET, Go, Rust, Electron/Node, JVM hints |
| **Runtime Reports** | Actionable Python extraction, Dart/Flutter snapshot, CLR/IL, Go/Rust, Electron, JVM guidance |
| **CFG Construction** | Control-flow graph via `petgraph` |
| **Function Detection** | Entry point, exports, call targets, MSVC prologues |
| **AST Lifting** | Pseudo-register and stack assignments (`mov`, `xor reg, reg`, `[rbp-8]`, …) |
| **Structure Recovery** | CFG-aware `if/else` with diamond-shape detection |
| **Condition Recovery** | `cmp/test + jcc` → human-readable expressions |
| **Stack Recovery** | x86 `[rbp±off]` / `[rsp±off]` operands → `local_*`, `arg_*`, `stack_*` variables |
| **String References** | Remaining asm comments annotate matched addresses as `str_XXXX` symbols |
| **C Syntax Hardening** | Escapes strings/comments and sanitizes emitted identifiers |
| **Optimization** | Constant folding, dead-code elimination |
| **C Generation** | Address-annotated C output |

---

## Pipeline

```
parse_binary  ──►  RuntimeDetector  ──►  Runtime hints
       │
       └──────►  disasm (x86 / ARM)  ──►  Vec<Instruction>
                                                    │
                                         FunctionDetector
                                   (entry · exports · call-targets · prologues)
                                                    │
                                          Vec<FunctionInfo>
                                                    │
                                            lift_functions
                                                    │
                                          Vec<ast::Function>
                                                    │
                                   structure_functions_with_cfg
                                (ret · if/else · condition recovery)
                                                    │
                                  Optimizer::optimize_function
                                                    │
                                  CGenerator::generate_function
                                                    │
                                               String (C)
```

---

## Quick Start

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-re.git
cd cyberm4fia-re
cargo build --release
```

```bash
# Decompile a binary
cargo run --release -- -i <binary> -o output.c

# With optimization
cargo run --release -- -i <binary> -o output.c --optimization basic

# Aggressive optimization
cargo run --release -- -i <binary> -o output.c --optimization aggressive
```

**Windows smoke test:**
```bash
cargo run --release -- -i C:\Windows\System32\notepad.exe -o notepad.c
# → 672 functions · 48,053 instructions · 52,000+ lines of C
```

---

## Output Sample

```c
// 0x11BF  sub_11BF  (export)
void sub_11BF(void) {
    uint64_t rax;
    uint64_t r8b;
    /* 0x11BF: sub rsp,98h */
    /* 0x11C6: mov rax,[34400h] */
    rax = 0;
    if ((r8b == 0)) {
        return;
    }
    /* 0x11DE: xor rax,rsp */
}
```

---

## Tests

```bash
cargo test --lib
```

| Module | Tests |
|---|---|
| `disasm::x86` | 5 |
| `disasm::arm` | 10 |
| `disasm::control_flow` | 6 |
| `binary::parser` | 5 |
| `analysis::functions` | 7 |
| `analysis::runtime` | 10 |
| `analysis::runtime_report` | 4 |
| `analysis::strings` | 7 |
| `decompiler::c_syntax` | 12 |
| `decompiler::lifter` | 8 |
| `decompiler::string_refs` | 6 |
| `decompiler::structure` | 16 |

---

## Project Structure

```
src/
├── binary/         # ELF · PE · Mach-O parsing  (goblin)
├── disasm/         # x86 (iced-x86) · ARM (capstone) · CFG
├── analysis/       # function detection · runtime hints/reports · string extraction · types
├── decompiler/     # AST · lifter · structure · string refs · C syntax helpers · optimizer · C gen
└── utils/          # error types
```

---

## Legal Disclaimer

> **This tool is for authorized reverse engineering and educational purposes only.**
> The developers assume no liability for misuse.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
