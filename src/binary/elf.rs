//! ELF format parser

use crate::binary::parser::{
    BinaryInfo, ExportInfo, ImportInfo, SectionCharacteristics, SectionInfo,
};
use crate::binary::{BinaryFormat, BinaryParser};
use crate::utils::error::{Error, Result};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use goblin::elf::Elf;

/// ELF parser
#[derive(Default)]
pub struct ElfParser;

impl BinaryParser for ElfParser {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn BinaryInfo>> {
        let elf = Elf::parse(data)
            .map_err(|e| Error::BinaryParse(format!("Failed to parse ELF: {}", e)))?;

        Ok(Box::new(ElfBinary::from_elf(&elf, data)))
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
    }
}

/// ELF binary information (owned)
pub struct ElfBinary {
    architecture: &'static str,
    entry_point: u64,
    sections: Vec<SectionInfo>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
}

impl ElfBinary {
    fn from_elf(elf: &Elf<'_>, data: &[u8]) -> Self {
        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x64",
            goblin::elf::header::EM_386 => "x86",
            goblin::elf::header::EM_AARCH64 => "ARM64",
            goblin::elf::header::EM_ARM => "ARM",
            _ => "Unknown",
        };

        let entry_point = elf.header.e_entry;

        // sh_flags is u64 in goblin's unified ELF view; constants are u32.
        let shf_alloc = u64::from(SHF_ALLOC);
        let shf_exec = u64::from(SHF_EXECINSTR);
        let shf_write = u64::from(SHF_WRITE);

        let sections = elf
            .section_headers
            .iter()
            .map(|section| {
                let name = elf
                    .shdr_strtab
                    .get_at(section.sh_name)
                    .unwrap_or("<invalid>")
                    .to_string();
                let virtual_address = section.sh_addr;
                let size = section.sh_size;
                let raw_data = if section.sh_offset > 0 && section.sh_size > 0 {
                    let start = section.sh_offset as usize;
                    let end = start.saturating_add(size as usize);
                    data.get(start..end).unwrap_or(&[]).to_vec()
                } else {
                    vec![]
                };

                let characteristics = SectionCharacteristics {
                    is_code: section.sh_flags & shf_exec != 0,
                    is_data: section.sh_flags & shf_alloc != 0 && section.sh_flags & shf_exec == 0,
                    is_readable: true,
                    is_writable: section.sh_flags & shf_write != 0,
                    is_executable: section.sh_flags & shf_exec != 0,
                };

                SectionInfo {
                    name,
                    virtual_address,
                    size,
                    raw_data,
                    characteristics,
                }
            })
            .collect();

        let imports = elf
            .libraries
            .iter()
            .map(|lib| ImportInfo {
                name: lib.to_string(),
                functions: vec![],
            })
            .collect();

        let exports = elf
            .syms
            .iter()
            .filter(|sym| sym.st_bind() == goblin::elf::sym::STB_GLOBAL && sym.st_size > 0)
            .filter_map(|sym| {
                let name = elf.strtab.get_at(sym.st_name)?.to_string();
                Some(ExportInfo {
                    name,
                    address: sym.st_value,
                    ordinal: None,
                })
            })
            .collect();

        Self {
            architecture,
            entry_point,
            sections,
            imports,
            exports,
        }
    }
}

impl BinaryInfo for ElfBinary {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
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
