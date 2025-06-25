use linux_perf_data::jitdump::{JitDumpReader, JitDumpRecord};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use yaxpeax_arch::{Arch, DecodeError, LengthedInstruction, Reader, U8Reader};
use yaxpeax_x86::amd64::{Opcode, Operand};

fn serialize_address_as_hex<S>(addr: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("0x{:x}", addr))
}

fn read_file_contents(file_path: &str) -> Option<String> {
    match std::fs::read_to_string(file_path) {
        Ok(contents) => Some(contents),
        Err(_) => None, // File doesn't exist or can't be read
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DebugEntry {
    #[serde(serialize_with = "serialize_address_as_hex")]
    code_addr: u64,
    file_path: String,
    line: u32,
    column: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SourceFile {
    path: String,
    contents: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OutputData {
    functions: Vec<FunctionInfo>,
    source_files: Vec<SourceFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstructionInfo {
    offset: u32,
    instruction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FunctionInfo {
    name: String,
    code_index: u64,
    pid: u32,
    tid: u32,
    #[serde(serialize_with = "serialize_address_as_hex")]
    address: u64,
    size: usize,
    timestamp: u64,
    debug_info: Vec<DebugEntry>,
    disassembly: Vec<InstructionInfo>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [function_name] [jitdump_file]", "jitdump-to-json");
        std::process::exit(1);
    }
    
    let target_function = if args.len() >= 3 { 
        Some(&args[1]) 
    } else { 
        None 
    };
    let jitdump_file = (args.get(if target_function.is_some() { 2 } else { 1 })).map(|s| s.as_str())
        .unwrap();

    let file = std::fs::File::open(jitdump_file)
        .unwrap_or_else(|e| {
            eprintln!("Failed to open {}: {}", jitdump_file, e);
            std::process::exit(1);
        });

    let mut reader = JitDumpReader::new(file).unwrap();
    let em_arch = reader.header().elf_machine_arch as u16;
    
    // Store debug info by code address
    let mut debug_info_map: HashMap<u64, Vec<DebugEntry>> = HashMap::new();
    let mut functions: Vec<FunctionInfo> = Vec::new();
    let mut source_files: HashMap<String, Option<String>> = HashMap::new();
    let mut all_function_names: Vec<String> = Vec::new();
    
    // Track all function addresses and names for call resolution
    let mut function_addresses: HashMap<u64, String> = HashMap::new();

    while let Ok(Some(record)) = reader.next_record() {
        let timestamp = record.timestamp;
        match record.parse().unwrap() {
            JitDumpRecord::CodeDebugInfo(debug_record) => {
                let debug_entries: Vec<DebugEntry> = debug_record.entries
                    .iter()
                    .map(|entry| {
                        let file_path = String::from_utf8_lossy(&entry.file_path.as_slice()).to_string();
                        
                        // Track unique source files
                        if !source_files.contains_key(&file_path) {
                            let file_contents = read_file_contents(&file_path);
                            source_files.insert(file_path.clone(), file_contents);
                        }
                        
                        DebugEntry {
                            code_addr: entry.code_addr,
                            file_path,
                            line: entry.line,
                            column: entry.column,
                        }
                    })
                    .collect();
                
                debug_info_map.insert(debug_record.code_addr, debug_entries);
            }
            JitDumpRecord::CodeLoad(load_record) => {
                let function_name = String::from_utf8_lossy(&load_record.function_name.as_slice()).to_string();
                
                // Always track function addresses and names for call resolution
                function_addresses.insert(load_record.code_addr, function_name.clone());
                
                // If no target function specified, collect all function names
                if target_function.is_none() {
                    all_function_names.push(function_name);
                } else {
                    // Check if this function matches our target
                    if function_name.contains(target_function.unwrap()) {
                        let debug_entries = debug_info_map
                            .get(&load_record.code_addr)
                            .cloned()
                            .unwrap_or_default();
                        
                        let disassembly = disassemble_code(&load_record.code_bytes.as_slice(), em_arch, load_record.code_addr, &function_addresses)
                            .unwrap_or_else(|_| vec![InstructionInfo {
                                offset: 0,
                                instruction: "Failed to disassemble".to_string(),
                                target: None,
                            }]);
                        
                        let function_info = FunctionInfo {
                            name: function_name,
                            code_index: load_record.code_index,
                            pid: load_record.pid,
                            tid: load_record.tid,
                            address: load_record.code_addr,
                            size: load_record.code_bytes.len(),
                            timestamp,
                            debug_info: debug_entries,
                            disassembly,
                        };
                        
                        functions.push(function_info);
                    }
                }
            }
            _ => {
                // Ignore other record types
            }
        }
    }

    // If no target function was specified, just list all function names
    if target_function.is_none() {
        for function_name in all_function_names {
            println!("{}", function_name);
        }
        return;
    }

    if functions.is_empty() {
        eprintln!("No functions found matching '{}'", target_function.unwrap());
        std::process::exit(1);
    }

    // Convert source files HashMap to Vec<SourceFile>
    let source_files_vec: Vec<SourceFile> = source_files
        .into_iter()
        .map(|(path, contents)| SourceFile { path, contents })
        .collect();

    // Create output data structure
    let output_data = OutputData {
        functions,
        source_files: source_files_vec,
    };

    // Output as JSON
    match serde_json::to_string_pretty(&output_data) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Failed to serialize to JSON: {}", e);
            std::process::exit(1);
        }
    }
}

/// ARM
const EM_ARM: u16 = 40;
/// ARM AARCH64
const EM_AARCH64: u16 = 183;
/// Intel 80386
const EM_386: u16 = 3;
/// AMD x86-64 architecture
const EM_X86_64: u16 = 62;

fn disassemble_code(bytes: &[u8], elf_machine_arch: u16, base_address: u64, function_addresses: &HashMap<u64, String>) -> Result<Vec<InstructionInfo>, String> {
    let code_size = bytes.len();
    match elf_machine_arch {
        EM_386 => disassemble::<yaxpeax_x86::protected_mode::Arch>(bytes, base_address, code_size, function_addresses),
        EM_X86_64 => disassemble::<yaxpeax_x86::amd64::Arch>(bytes, base_address, code_size, function_addresses),
        EM_AARCH64 => disassemble::<yaxpeax_arm::armv8::a64::ARMv8>(bytes, base_address, code_size, function_addresses),
        EM_ARM => disassemble::<yaxpeax_arm::armv7::ARMv7>(bytes, base_address, code_size, function_addresses),
        _ => {
            Err(format!(
                "Unrecognized ELF machine architecture {elf_machine_arch}"
            ))
        }
    }
}

trait InstructionDecoding: Arch {
    const ADJUST_BY_AFTER_ERROR: usize;
    type InstructionDisplay<'a>: std::fmt::Display;
    fn make_decoder() -> Self::Decoder;
    fn inst_display(inst: &Self::Instruction, base_address: u64, code_size: usize, offset: u32, function_addresses: &HashMap<u64, String>) -> String;
    fn get_jump_target(inst: &Self::Instruction, base_address: u64, code_size: usize, offset: u32) -> Option<u32>;
}

impl InstructionDecoding for yaxpeax_x86::amd64::Arch {
    const ADJUST_BY_AFTER_ERROR: usize = 1;
    type InstructionDisplay<'a> = yaxpeax_x86::amd64::InstructionDisplayer<'a>;

    fn make_decoder() -> Self::Decoder {
        yaxpeax_x86::amd64::InstDecoder::default()
    }

    fn inst_display(inst: &Self::Instruction, base_address: u64, code_size: usize, offset: u32, function_addresses: &HashMap<u64, String>) -> String {
        fn is_relative_branch(opcode: Opcode) -> bool {
            matches!(
                opcode,
                Opcode::JMP
                    | Opcode::JRCXZ
                    | Opcode::LOOP
                    | Opcode::LOOPZ
                    | Opcode::LOOPNZ
                    | Opcode::JO
                    | Opcode::JNO
                    | Opcode::JB
                    | Opcode::JNB
                    | Opcode::JZ
                    | Opcode::JNZ
                    | Opcode::JNA
                    | Opcode::JA
                    | Opcode::JS
                    | Opcode::JNS
                    | Opcode::JP
                    | Opcode::JNP
                    | Opcode::JL
                    | Opcode::JGE
                    | Opcode::JLE
                    | Opcode::JG
            )
        }

        fn is_relative_call(opcode: Opcode) -> bool {
            matches!(opcode, Opcode::CALL)
        }

        if is_relative_branch(inst.opcode()) || is_relative_call(inst.opcode()) {
            match inst.operand(0) {
                Operand::ImmediateI8 { imm } => {
                    let dest = base_address as i64
                        + offset as i64
                        + inst.len().to_const() as i64
                        + imm as i64;
                    let dest_addr = dest as u64;
                    
                    // Check if destination is within the current code region
                    if dest_addr >= base_address && dest_addr < base_address + code_size as u64 {
                        let relative_offset = dest_addr - base_address;
                        format!("{} 0x{:x}", inst.opcode(), relative_offset)
                    } else {
                        // Try to resolve function name for external destinations
                        if let Some(function_name) = function_addresses.get(&dest_addr) {
                            format!("{} {} # 0x{:x}", inst.opcode(), function_name, dest_addr)
                        } else {
                            format!("{} 0x{:x}", inst.opcode(), dest_addr)
                        }
                    }
                }
                Operand::ImmediateI32 { imm } => {
                    let dest = base_address as i64
                        + offset as i64
                        + inst.len().to_const() as i64
                        + imm as i64;
                    let dest_addr = dest as u64;
                    
                    // Check if destination is within the current code region
                    if dest_addr >= base_address && dest_addr < base_address + code_size as u64 {
                        let relative_offset = dest_addr - base_address;
                        format!("{} 0x{:x}", inst.opcode(), relative_offset)
                    } else {
                        // Try to resolve function name for external destinations
                        if let Some(function_name) = function_addresses.get(&dest_addr) {
                            format!("{} {} # 0x{:x}", inst.opcode(), function_name, dest_addr)
                        } else {
                            format!("{} 0x{:x}", inst.opcode(), dest_addr)
                        }
                    }
                }
                _ => inst.display_with(yaxpeax_x86::amd64::DisplayStyle::Intel).to_string(),
            }
        } else {
            inst.display_with(yaxpeax_x86::amd64::DisplayStyle::Intel).to_string()
        }
    }

    fn get_jump_target(inst: &Self::Instruction, base_address: u64, code_size: usize, offset: u32) -> Option<u32> {
        fn is_relative_branch(opcode: Opcode) -> bool {
            matches!(
                opcode,
                Opcode::JMP
                    | Opcode::JRCXZ
                    | Opcode::LOOP
                    | Opcode::LOOPZ
                    | Opcode::LOOPNZ
                    | Opcode::JO
                    | Opcode::JNO
                    | Opcode::JB
                    | Opcode::JNB
                    | Opcode::JZ
                    | Opcode::JNZ
                    | Opcode::JNA
                    | Opcode::JA
                    | Opcode::JS
                    | Opcode::JNS
                    | Opcode::JP
                    | Opcode::JNP
                    | Opcode::JL
                    | Opcode::JGE
                    | Opcode::JLE
                    | Opcode::JG
            )
        }

        fn is_relative_call(opcode: Opcode) -> bool {
            matches!(opcode, Opcode::CALL)
        }

        if is_relative_branch(inst.opcode()) || is_relative_call(inst.opcode()) {
            match inst.operand(0) {
                Operand::ImmediateI8 { imm } => {
                    let dest = base_address as i64
                        + offset as i64
                        + inst.len().to_const() as i64
                        + imm as i64;
                    let dest_addr = dest as u64;
                    
                    // Check if destination is within the current code region (local jump)
                    if dest_addr >= base_address && dest_addr < base_address + code_size as u64 {
                        let relative_offset = dest_addr - base_address;
                        Some(relative_offset as u32)
                    } else {
                        None // External jump
                    }
                }
                Operand::ImmediateI32 { imm } => {
                    let dest = base_address as i64
                        + offset as i64
                        + inst.len().to_const() as i64
                        + imm as i64;
                    let dest_addr = dest as u64;
                    
                    // Check if destination is within the current code region (local jump)
                    if dest_addr >= base_address && dest_addr < base_address + code_size as u64 {
                        let relative_offset = dest_addr - base_address;
                        Some(relative_offset as u32)
                    } else {
                        None // External jump
                    }
                }
                _ => None,
            }
        } else {
            None // Not a jump/call instruction
        }
    }
}

impl InstructionDecoding for yaxpeax_x86::protected_mode::Arch {
    const ADJUST_BY_AFTER_ERROR: usize = 1;
    type InstructionDisplay<'a> = &'a Self::Instruction;

    fn make_decoder() -> Self::Decoder {
        yaxpeax_x86::protected_mode::InstDecoder::default()
    }

    fn inst_display(inst: &Self::Instruction, _base_address: u64, _code_size: usize, _offset: u32, _function_addresses: &HashMap<u64, String>) -> String {
        inst.to_string()
    }

    fn get_jump_target(_inst: &Self::Instruction, _base_address: u64, _code_size: usize, _offset: u32) -> Option<u32> {
        // Implementation of get_jump_target method
        None
    }
}

impl InstructionDecoding for yaxpeax_arm::armv8::a64::ARMv8 {
    const ADJUST_BY_AFTER_ERROR: usize = 4;
    type InstructionDisplay<'a> = &'a Self::Instruction;

    fn make_decoder() -> Self::Decoder {
        yaxpeax_arm::armv8::a64::InstDecoder::default()
    }

    fn inst_display(inst: &Self::Instruction, _base_address: u64, _code_size: usize, _offset: u32, _function_addresses: &HashMap<u64, String>) -> String {
        inst.to_string()
    }

    fn get_jump_target(_inst: &Self::Instruction, _base_address: u64, _code_size: usize, _offset: u32) -> Option<u32> {
        // Implementation of get_jump_target method
        None
    }
}

impl InstructionDecoding for yaxpeax_arm::armv7::ARMv7 {
    const ADJUST_BY_AFTER_ERROR: usize = 2;
    type InstructionDisplay<'a> = &'a Self::Instruction;

    fn make_decoder() -> Self::Decoder {
        // Assume thumb. The Jitdump format doesn't seem to have a way of indicating
        // ARM or thumb mode for 32 bit arm functions.
        yaxpeax_arm::armv7::InstDecoder::default_thumb()
    }

    fn inst_display(inst: &Self::Instruction, _base_address: u64, _code_size: usize, _offset: u32, _function_addresses: &HashMap<u64, String>) -> String {
        inst.to_string()
    }

    fn get_jump_target(_inst: &Self::Instruction, _base_address: u64, _code_size: usize, _offset: u32) -> Option<u32> {
        // Implementation of get_jump_target method
        None
    }
}

fn disassemble<'a, A: InstructionDecoding>(bytes: &'a [u8], base_address: u64, code_size: usize, function_addresses: &HashMap<u64, String>) -> Result<Vec<InstructionInfo>, String>
where
    u64: From<A::Address>,
    U8Reader<'a>: yaxpeax_arch::Reader<A::Address, A::Word>,
{
    use yaxpeax_arch::Decoder;
    let mut reader = yaxpeax_arch::U8Reader::new(bytes);
    let decoder = A::make_decoder();
    let mut offset = 0;
    let mut instructions = Vec::new();
    
    loop {
        let before = u64::from(reader.total_offset()) as u32;
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let target = A::get_jump_target(&inst, base_address, code_size, offset);
                instructions.push(InstructionInfo {
                    offset,
                    instruction: A::inst_display(&inst, base_address, code_size, offset, function_addresses),
                    target,
                });
                let after = u64::from(reader.total_offset()) as u32;
                offset += after - before;
            }
            Err(e) => {
                if e.data_exhausted() {
                    break;
                }

                let remaining_bytes = &bytes[offset as usize..];
                let s = remaining_bytes
                    .iter()
                    .take(A::ADJUST_BY_AFTER_ERROR)
                    .map(|b| format!("{b:#02x}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let s2 = remaining_bytes
                    .iter()
                    .take(A::ADJUST_BY_AFTER_ERROR)
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");

                instructions.push(InstructionInfo {
                    offset,
                    instruction: format!(
                        ".byte {s:width$} # Invalid instruction {s2}: {e}",
                        width = A::ADJUST_BY_AFTER_ERROR * 6
                    ),
                    target: None,
                });

                offset += A::ADJUST_BY_AFTER_ERROR as u32;
                let Some(reader_bytes) = bytes.get(offset as usize..) else {
                    break;
                };
                reader = U8Reader::new(reader_bytes);
            }
        }
    }
    
    Ok(instructions)
} 