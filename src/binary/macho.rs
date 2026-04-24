//! Mach-O format parser

use crate::binary::parser::{
    BinaryInfo, ExportInfo, ImportInfo, SectionCharacteristics, SectionInfo,
};
use crate::binary::{BinaryFormat, BinaryParser};
use crate::utils::error::{Error, Result};
use goblin::mach::constants::{S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS};
use goblin::mach::Mach;

/// Mach-O parser
#[derive(Default)]
pub struct MachOParser;

impl BinaryParser for MachOParser {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn BinaryInfo>> {
        let mach = Mach::parse(data)
            .map_err(|e| Error::BinaryParse(format!("Failed to parse Mach-O: {}", e)))?;

        Ok(Box::new(MachOBinary::from_mach(&mach)))
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
    }
}

/// Mach-O binary information (owned)
pub struct MachOBinary {
    architecture: &'static str,
    entry_point: u64,
    sections: Vec<SectionInfo>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
}

impl MachOBinary {
    fn from_mach(mach: &Mach<'_>) -> Self {
        let macho = match mach {
            Mach::Binary(m) => m,
            Mach::Fat(_) => {
                return Self {
                    architecture: "Fat (Multi-arch)",
                    entry_point: 0,
                    sections: vec![],
                    imports: vec![],
                    exports: vec![],
                };
            }
        };

        let architecture = match macho.header.cputype {
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => "x64",
            goblin::mach::constants::cputype::CPU_TYPE_X86 => "x86",
            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => "ARM64",
            goblin::mach::constants::cputype::CPU_TYPE_ARM => "ARM",
            _ => "Unknown",
        };

        let entry_point = macho.entry;

        let mut sections: Vec<SectionInfo> = Vec::new();
        for segment in macho.segments.iter() {
            let Ok(section_list) = segment.sections() else {
                continue;
            };
            for (section, section_data) in section_list {
                let is_pure_code = section.flags & S_ATTR_PURE_INSTRUCTIONS != 0;
                let has_some_code = section.flags & S_ATTR_SOME_INSTRUCTIONS != 0;
                let is_code = is_pure_code || has_some_code;

                let characteristics = SectionCharacteristics {
                    is_code,
                    is_data: !is_code,
                    is_readable: true,
                    is_writable: false,
                    is_executable: is_code,
                };

                let name = section.name().unwrap_or("<invalid>").to_string();

                sections.push(SectionInfo {
                    name,
                    virtual_address: section.addr,
                    size: section.size,
                    raw_data: section_data.to_vec(),
                    characteristics,
                });
            }
        }

        let imports = match macho.imports() {
            Ok(imps) => {
                let mut dylib_map: std::collections::BTreeMap<String, Vec<String>> =
                    std::collections::BTreeMap::new();
                for imp in imps {
                    dylib_map
                        .entry(imp.dylib.to_string())
                        .or_default()
                        .push(imp.name.to_string());
                }
                dylib_map
                    .into_iter()
                    .map(|(name, functions)| ImportInfo { name, functions })
                    .collect()
            }
            Err(_) => vec![],
        };

        let exports = match macho.exports() {
            Ok(exps) => exps
                .into_iter()
                .map(|export| ExportInfo {
                    name: export.name,
                    address: export.offset,
                    ordinal: None,
                })
                .collect(),
            Err(_) => vec![],
        };

        Self {
            architecture,
            entry_point,
            sections,
            imports,
            exports,
        }
    }
}

impl BinaryInfo for MachOBinary {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
    }

    fn architecture(&self) -> &'static str {
        self.architecture
    }

    fn entry_point(&self) -> u64 {
        self.entry_point
    }

    fn sections(&self) -> Vec<SectionInfo> {
        self.sections.clone()
    }

    fn imports(&self) -> Vec<ImportInfo> {
        self.imports.clone()
    }

    fn exports(&self) -> Vec<ExportInfo> {
        self.exports.clone()
    }
}
