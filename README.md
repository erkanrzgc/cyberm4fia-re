<div align="center">

# cyberm4fia-re

<p align="center">
  <img src="https://img.shields.io/badge/MISSION-REVERSE%20ENGINEERING%20VIA%20RUST-CC2936?style=for-the-badge&labelColor=0D0D0D"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.75%2B-777777?style=flat-square&labelColor=555555"/>
  <img src="https://img.shields.io/badge/crates-12%2B-4B6BFB?style=flat-square&labelColor=1A1A2E"/>
  <img src="https://img.shields.io/badge/license-MIT-CC2936?style=flat-square&labelColor=2D2D2D"/>
  <img src="https://img.shields.io/badge/tests-58%20passing-2D8A4E?style=flat-square&labelColor=1A1A1A"/>
  <img src="https://img.shields.io/badge/last%20commit-today-00AA55?style=flat-square&labelColor=1A1A1A"/>
</p>

<br/>

**cyberm4fia-re** is a Rust-powered binary decompiler — parses ELF, PE, and Mach-O executables,
disassembles x86 & ARM, builds control-flow graphs, detects functions, and generates readable C code.

<br/>

</div>

---

<div align="center">

## Features

<img src="https://img.shields.io/badge/BINARY-FORMATS-4B6BFB?style=flat-square&labelColor=1A1A2E"/>

</div>

| Format | Description |
|--------|-------------|
| **ELF** | Linux/Unix executables & shared objects |
| **PE** | Windows `.exe` / `.dll` (32-bit & 64-bit) |
| **Mach-O** | macOS executables & dylibs |

<div align="center">
<img src="https://img.shields.io/badge/DISASM-ARCHITECTURES-4B6BFB?style=flat-square&labelColor=1A1A2E"/>
</div>

| Architecture | Engine |
|---|---|
| x86 / x86-64 | `iced-x86` |
| ARM / AArch64 | `capstone` |

<div align="center">
<img src="https://img.shields.io/badge/RECOVERY-DECOMPILATION-4B6BFB?style=flat-square&labelColor=1A1A2E"/>
</div>

- Control-flow graph construction via `petgraph`
- Function detection — entry point, exports, call targets, MSVC prologues
- AST lifting with pseudo-register assignments (`mov`, `xor reg, reg`, …)
- CFG-aware `if/else` recovery with diamond-shape detection
- Condition recovery from `cmp/test + jcc` sequences
- Optimization pass — constant folding, dead-code elimination
- C code generation with address annotations

---

<div align="center">

## Pipeline

</div>

```
parse_binary  ──►  disasm (x86 / ARM)  ──►  Vec<Instruction>
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

<div align="center">

## Quick Start

<img src="https://img.shields.io/badge/INSTALL-REQUIREMENTS-CC2936?style=flat-square&labelColor=2D2D2D"/>

</div>

> Requires: **Rust 1.75+** · **Cargo**

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-re.git
cd cyberm4fia-re
cargo build --release
```

<div align="center">
<img src="https://img.shields.io/badge/USAGE-CLI-CC2936?style=flat-square&labelColor=2D2D2D"/>
</div>

```bash
# Decompile a binary
cargo run --release -- -i <binary> -o output.c

# With optimization
cargo run --release -- -i <binary> -o output.c --optimization basic
cargo run --release -- -i <binary> -o output.c --optimization aggressive
```

**Windows smoke test:**
```bash
cargo run --release -- -i C:\Windows\System32\notepad.exe -o notepad.c
# → 672 functions · 48,053 instructions · 52,000+ lines of C
```

---

<div align="center">

## Output Sample

</div>

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

<div align="center">

## Tests

<img src="https://img.shields.io/badge/TESTS-58%20PASSING-2D8A4E?style=flat-square&labelColor=1A1A1A"/>

</div>

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
| `analysis::strings` | 7 |
| `decompiler::lifter` | 4 |
| `decompiler::structure` | 8 |
| `decompiler::other` | 6 |

---

<div align="center">

## Project Structure

</div>

```
src/
├── binary/         # ELF · PE · Mach-O parsing  (goblin)
├── disasm/         # x86 (iced-x86) · ARM (capstone) · CFG
├── analysis/       # function detection · string extraction · types
├── decompiler/     # AST · lifter · structure · optimizer · C gen
└── utils/          # error types
```

---

<div align="center">

<img src="https://img.shields.io/badge/LICENSE-MIT-CC2936?style=flat-square&labelColor=2D2D2D"/>

MIT © [erkanrzgc](https://github.com/erkanrzgc)

</div>
