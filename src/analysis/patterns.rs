//! Code pattern matching

use crate::disasm::Instruction;
use regex::Regex;

/// Pattern match result
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub address: u64,
    pub confidence: f32,
    pub metadata: String,
}

/// Pattern matcher
pub struct PatternMatcher {
    /// Known patterns
    patterns: Vec<Pattern>,
}

/// A code pattern
struct Pattern {
    name: String,
    regex: Regex,
    confidence: f32,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // Common function prologues
        patterns.push(Pattern {
            name: "function_prologue_x86".to_string(),
            regex: Regex::new(r"push (ebp|rbp);\s*mov (ebp|rbp), (esp|rsp)").unwrap(),
            confidence: 0.9,
        });

        patterns.push(Pattern {
            name: "function_prologue_x64".to_string(),
            regex: Regex::new(r"push rbp;\s*mov rbp, rsp").unwrap(),
            confidence: 0.9,
        });

        // String operations
        patterns.push(Pattern {
            name: "string_copy".to_string(),
            regex: Regex::new(r"mov (eax|rax),\s*\[.*\];\s*test (eax|rax),\s*(eax|rax)").unwrap(),
            confidence: 0.7,
        });

        // Loop patterns
        patterns.push(Pattern {
            name: "for_loop".to_string(),
            regex: Regex::new(r"dec (eax|ecx|rcx);\s*jnz").unwrap(),
            confidence: 0.8,
        });

        patterns.push(Pattern {
            name: "while_loop".to_string(),
            regex: Regex::new(r"cmp.*;\s*j[ne|ge|le]").unwrap(),
            confidence: 0.7,
        });

        // Memory allocation
        patterns.push(Pattern {
            name: "malloc_call".to_string(),
            regex: Regex::new(r"call.*malloc").unwrap(),
            confidence: 0.95,
        });

        patterns.push(Pattern {
            name: "free_call".to_string(),
            regex: Regex::new(r"call.*free").unwrap(),
            confidence: 0.95,
        });

        Self { patterns }
    }

    /// Match patterns in instructions
    pub fn match_patterns(&self, instructions: &[Instruction]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Build instruction string for pattern matching
        let instr_str: String = instructions
            .iter()
            .map(|instr| match instr {
                Instruction::X86(x) => x.to_string(),
                Instruction::Arm(a) => a.to_string(),
            })
            .collect::<Vec<_>>()
            .join("; ");

        for pattern in &self.patterns {
            if let Some(caps) = pattern.regex.find(&instr_str) {
                matches.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    address: instructions.first().map(|i| i.address()).unwrap_or(0),
                    confidence: pattern.confidence,
                    metadata: caps.as_str().to_string(),
                });
            }
        }

        matches
    }

    /// Match single instruction patterns
    pub fn match_instruction(&self, instr: &Instruction) -> Vec<PatternMatch> {
        let instr_str = match instr {
            Instruction::X86(x) => x.to_string(),
            Instruction::Arm(a) => a.to_string(),
        };

        let mut matches = Vec::new();

        for pattern in &self.patterns {
            if pattern.regex.is_match(&instr_str) {
                matches.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    address: instr.address(),
                    confidence: pattern.confidence,
                    metadata: instr_str.clone(),
                });
            }
        }

        matches
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}
