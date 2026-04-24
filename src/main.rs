//! Decompiler CLI

use clap::Parser;
use decompiler::analysis::functions::FunctionDetectionInputs;
use decompiler::analysis::{FunctionDetector, StringExtractor};
use decompiler::binary::parse_binary;
use decompiler::decompiler::{
    lift_functions, structure_functions_with_cfg, CGenerator, CGeneratorConfig, OptimizationLevel,
    Optimizer,
};
use decompiler::disasm::{ArmDisassembler, ControlFlowGraph, Instruction, X86Disassembler};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "decompiler")]
#[command(about = "Binary to source code decompiler", long_about = None)]
struct Cli {
    /// Input binary file
    #[arg(short, long)]
    input: String,

    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "c")]
    format: String,

    /// Optimization level (none, basic, aggressive)
    #[arg(short = 'O', long, default_value = "basic")]
    optimization: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("decompiler={}", log_level))
        .init();

    info!("Starting decompiler...");

    // Parse binary
    info!("Parsing binary: {}", cli.input);
    let binary = parse_binary(std::path::Path::new(&cli.input))?;

    info!("Format: {}", binary.format().name());
    info!("Architecture: {}", binary.architecture());
    info!("Entry point: 0x{:X}", binary.entry_point());

    // Get code sections
    let code_sections: Vec<_> = binary
        .sections()
        .into_iter()
        .filter(|s| s.characteristics.is_code)
        .collect();

    if code_sections.is_empty() {
        error!("No code sections found in binary");
        return Ok(());
    }

    info!("Found {} code section(s)", code_sections.len());

    // Disassemble code — dispatch per architecture and normalize into the
    // unified `Instruction` enum so downstream analysis is arch-agnostic.
    let mut all_instructions: Vec<Instruction> = Vec::new();
    let arch = binary.architecture();
    for section in &code_sections {
        info!(
            "Disassembling section: {} (0x{:X} - 0x{:X})",
            section.name,
            section.virtual_address,
            section.virtual_address + section.size
        );

        let instructions: Vec<Instruction> = match arch {
            "x86" => X86Disassembler::new_x86()
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::X86)
                .collect(),
            "x64" => X86Disassembler::new_x64()
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::X86)
                .collect(),
            "ARM" => ArmDisassembler::new_arm()?
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::Arm)
                .collect(),
            "ARM64" => ArmDisassembler::new_arm64()?
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::Arm)
                .collect(),
            other => {
                error!("Unsupported architecture: {}", other);
                return Ok(());
            }
        };
        info!("Found {} instructions", instructions.len());
        all_instructions.extend(instructions);
    }

    // Detect functions (seed-based: entry + exports + call targets + prologues)
    info!("Detecting functions...");
    let function_detector = FunctionDetector::new();
    let exports = binary.exports();
    let imports = binary.imports();
    let functions = function_detector.detect(FunctionDetectionInputs {
        instructions: &all_instructions,
        entry_point: binary.entry_point(),
        exports: &exports,
        imports: &imports,
        architecture: arch,
    });
    info!("Found {} functions", functions.len());

    // Extract strings
    info!("Extracting strings...");
    let string_extractor = StringExtractor::new();
    let mut all_strings = Vec::new();
    for section in &binary.sections() {
        if section.characteristics.is_data {
            let strings = string_extractor.extract(&section.raw_data, section.virtual_address);
            info!(
                "Found {} strings in section {}",
                strings.len(),
                section.name
            );
            all_strings.extend(strings);
        }
    }

    // Build control flow graph
    info!("Building control flow graph...");
    let cfg = ControlFlowGraph::from_instructions(&all_instructions);
    info!("CFG has {} basic blocks", cfg.blocks().len());

    // Generate C code
    info!("Generating C code...");
    let mut output = String::new();

    // Add header
    output.push_str("// Decompiled by decompiler\n");
    output.push_str(&format!("// Binary: {}\n", cli.input));
    output.push_str(&format!("// Format: {}\n", binary.format().name()));
    output.push_str(&format!("// Architecture: {}\n", binary.architecture()));
    output.push_str(&format!("// Entry point: 0x{:X}\n\n", binary.entry_point()));

    // Add includes
    output.push_str("#include <stdint.h>\n");
    output.push_str("#include <stddef.h>\n\n");

    // Add string literals
    if !all_strings.is_empty() {
        output.push_str("// String literals\n");
        for s in &all_strings {
            output.push_str(&format!(
                "const char str_{:X}[] = \"{}\";\n",
                s.address, s.value
            ));
        }
        output.push('\n');
    }

    // Lift detected functions into AST form, then structure the unambiguous
    // instructions before emitting through the C generator. The lifter is the
    // single seam between discovery (FunctionInfo) and synthesis
    // (ast::Function); later passes such as structuring and type recovery
    // operate on the AST, not on raw instruction streams.
    let mut ast_functions = lift_functions(&functions);
    structure_functions_with_cfg(&mut ast_functions, &cfg);

    // Apply optimization (currently a no-op for InlineAsm statements, but
    // the hook is in place for when structuring produces real expressions).
    let opt_level = match cli.optimization.as_str() {
        "none" => OptimizationLevel::None,
        "aggressive" => OptimizationLevel::Aggressive,
        _ => OptimizationLevel::Basic,
    };
    let optimizer = Optimizer::new(opt_level);
    for func in &mut ast_functions {
        optimizer.optimize_function(func);
    }

    // Declarations
    output.push_str("// Function declarations\n");
    for (info, func) in functions.iter().zip(ast_functions.iter()) {
        output.push_str(&format!(
            "// 0x{:X}{}\n",
            info.address,
            if info.is_export { " (export)" } else { "" }
        ));
        output.push_str(&format!("void {}(void);\n", func.name));
    }
    output.push('\n');

    // Implementations
    output.push_str("// Function implementations\n");
    let mut generator = CGenerator::new(CGeneratorConfig::default());
    for (info, func) in functions.iter().zip(ast_functions.iter()) {
        output.push_str(&format!(
            "// Function: {} at 0x{:X} (size: {} bytes)\n",
            info.name, info.address, info.size
        ));
        output.push_str(&generator.generate_function(func));
        output.push('\n');
    }

    // Write output
    match cli.output {
        Some(ref path) => {
            std::fs::write(path, output)?;
            info!("Output written to: {}", path);
        }
        None => {
            println!("{}", output);
        }
    }

    info!("Decompilation complete!");

    Ok(())
}
