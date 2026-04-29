//! PE/EXE format parser

use crate::binary::parser::{
    BinaryInfo, ExportInfo, ImportAddressInfo, ImportInfo, SectionCharacteristics, SectionInfo,
};
use crate::binary::{BinaryFormat, BinaryParser};
use crate::utils::error::{Error, Result};
use goblin::pe::PE;

/// PE/EXE parser
#[derive(Default)]
pub struct PeParser;

impl BinaryParser for PeParser {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn BinaryInfo>> {
        let pe = PE::parse(data)
            .map_err(|e| Error::BinaryParse(format!("Failed to parse PE: {}", e)))?;

        Ok(Box::new(PeBinary::from_pe(&pe, data)))
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::Pe
    }
}

/// PE binary information (owned — no borrow from parse input)
pub struct PeBinary {
    architecture: &'static str,
    entry_point: u64,
    sections: Vec<SectionInfo>,
    imports: Vec<ImportInfo>,
    import_addresses: Vec<ImportAddressInfo>,
    exports: Vec<ExportInfo>,
}

impl PeBinary {
    fn from_pe(pe: &PE<'_>, data: &[u8]) -> Self {
        let architecture = match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => "x64",
            goblin::pe::header::COFF_MACHINE_X86 => "x86",
            goblin::pe::header::COFF_MACHINE_ARM64 => "ARM64",
            goblin::pe::header::COFF_MACHINE_ARMNT | goblin::pe::header::COFF_MACHINE_ARM => "ARM",
            _ => "Unknown",
        };

        let entry_point = pe.entry as u64;

        let sections = pe
            .sections
            .iter()
            .map(|section| {
                let virtual_address = section.virtual_address as u64;
                let size = section.size_of_raw_data as u64;
                let raw_data = if section.pointer_to_raw_data > 0 {
                    let start = section.pointer_to_raw_data as usize;
                    let end = start.saturating_add(size as usize);
                    data.get(start..end).unwrap_or(&[]).to_vec()
                } else {
                    vec![]
                };

                let characteristics = SectionCharacteristics {
                    is_code: section.characteristics
                        & goblin::pe::section_table::IMAGE_SCN_CNT_CODE
                        != 0,
                    is_data: section.characteristics
                        & goblin::pe::section_table::IMAGE_SCN_CNT_INITIALIZED_DATA
                        != 0,
                    is_readable: section.characteristics
                        & goblin::pe::section_table::IMAGE_SCN_MEM_READ
                        != 0,
                    is_writable: section.characteristics
                        & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE
                        != 0,
                    is_executable: section.characteristics
                        & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
                        != 0,
                };

                // section.name() returns Result<&str, _>
                let name = section.name().unwrap_or("<invalid>").to_string();

                SectionInfo {
                    name,
                    virtual_address,
                    size,
                    raw_data,
                    characteristics,
                }
            })
            .collect();

        // PE imports in goblin 0.8 are a flat Vec<Import> (one entry per function)
        // We group by DLL name for our ImportInfo shape.
        let mut dll_map: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut import_addresses = Vec::new();
        for import in &pe.imports {
            dll_map
                .entry(import.dll.to_string())
                .or_default()
                .push(import.name.to_string());
            import_addresses.push(ImportAddressInfo {
                library: import.dll.to_string(),
                function: import.name.to_string(),
                address: import.offset as u64,
                ordinal: if import.name.starts_with("ORDINAL ") {
                    Some(import.ordinal)
                } else {
                    None
                },
            });
        }
        let imports = dll_map
            .into_iter()
            .map(|(dll, functions)| ImportInfo {
                name: dll,
                functions,
            })
            .collect();

        let exports = pe
            .exports
            .iter()
            .map(|export| ExportInfo {
                name: export.name.map(|n| n.to_string()).unwrap_or_default(),
                address: export.rva as u64,
                ordinal: None,
            })
            .collect();

        Self {
            architecture,
            entry_point,
            sections,
            imports,
            import_addresses,
            exports,
        }
    }
}

impl BinaryInfo for PeBinary {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Pe
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

    fn import_addresses(&self) -> Vec<ImportAddressInfo> {
        self.import_addresses.clone()
    }

    fn exports(&self) -> Vec<ExportInfo> {
        self.exports.clone()
    }
}
