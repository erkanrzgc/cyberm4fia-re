<div align="center">

![rust](https://img.shields.io/badge/rust-1.75%2B-gray?style=flat-square&labelColor=555555&color=777777)
![crates](https://img.shields.io/badge/crates-12%2B-blue?style=flat-square&color=4B6BFB)
![license](https://img.shields.io/badge/license-MIT-red?style=flat-square&color=CC2936)
![tests](https://img.shields.io/badge/tests-58%20passing-green?style=flat-square&color=2D8A4E)
![last commit](https://img.shields.io/badge/last%20commit-today-brightgreen?style=flat-square&color=00AA55)

**cyberm4fia-re** is a Rust-powered binary decompiler — parses ELF, PE, and Mach-O executables,
disassembles x86 & ARM, builds control-flow graphs, detects functions, and generates readable C code.

</div>

---

![MISSION](https://img.shields.io/badge/MISSION-REVERSE%20ENGINEERING%20VIA%20RUST-CC2936?style=flat-square&labelColor=2D2D2D)

---

## Features

![ANALYSIS](https://img.shields.io/badge/ANALYSIS-BINARY%20FORMATS-4B6BFB?style=flat-square&labelColor=1A1A2E)

- **ELF** — Linux/Unix executables and shared objects
- **PE** — Windows `.exe` and `.dll` (32-bit & 64-bit)
- **Mach-O** — macOS executables and dylibs

![DISASM](https://img.shields.io/badge/DISASM-ARCHITECTURES-4B6BFB?style=flat-square&labelColor=1A1A2E)

- **x86 / x86-64** via `iced-x86`
- **ARM / AArch64** via `capstone`

![RECOVERY](https://img.shields.io/badge/RECOVERY-DECOMPILATION%20PIPELINE-4B6BFB?style=flat-square&labelColor=1A1A2E)

- Control-flow graph construction (via `petgraph`)
- Function detection — entry point, exports, call targets, MSVC prologues
- AST lifting with pseudo-register assignments (`mov`, `xor`, etc.)
- CFG-aware `if/else` recovery with diamond-shape detection
- Condition recovery from `cmp/test + jcc` sequences
- Optimization pass — constant folding, dead-code elimination
- C code generation with address annotations

---

## Pipeline

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

## Installation

![INSTALL](https://img.shields.io/badge/INSTALL-REQUIREMENTS-CC2936?style=flat-square&labelColor=2D2D2D)

**Requirements:** Rust 1.75+ · Cargo

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-re.git
cd cyberm4fia-re
cargo build --release
```

---

## Usage

![USAGE](https://img.shields.io/badge/USAGE-CLI-CC2936?style=flat-square&labelColor=2D2D2D)

```bash
# Basic decompile
cargo run --release -- -i <binary> -o output.c

# With optimization
cargo run --release -- -i <binary> -o output.c --optimization basic

# Aggressive optimization
cargo run --release -- -i <binary> -o output.c --optimization aggressive
```

**Smoke test (Windows):**
```bash
cargo run --release -- -i C:\Windows\System32\notepad.exe -o notepad.c
# Output: 672 functions · 48,053 instructions · 52k lines of C
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

![TESTS](https://img.shields.io/badge/TESTS-58%20PASSING-2D8A4E?style=flat-square&labelColor=1A1A1A)

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

## Project Structure

```
src/
├── binary/         # ELF · PE · Mach-O parsing (goblin)
├── disasm/         # x86 (iced-x86) · ARM (capstone) · CFG
├── analysis/       # function detection · string extraction · types
├── decompiler/     # AST · lifter · structure · optimizer · C gen
└── utils/          # error types
```

---

## License

![LICENSE](https://img.shields.io/badge/LICENSE-MIT-CC2936?style=flat-square&labelColor=2D2D2D)

MIT © [erkanrzgc](https://github.com/erkanrzgc)
