use std::collections::{BTreeMap, HashSet};
use std::ffi::{c_char, c_int, c_void};
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::deriver_json::{
    build_documents_data, check_init_array_data, extract_specs_inner, load_candidate_metadata_data,
    load_runtime_anchors_data, read_bounded_regular_json_bytes, read_host_abi_sidecar_identity_file,
    resolve_constructors_and_seeds_inner, validate_reference_identity_inner,
    MocktailRustDeriverBuildInputs, MocktailRustDeriverRuntimeAnchors, ParsedSpec,
};
use crate::elf_reader::{
    checked_range, cstr_slice_at, parse_elf64_header, parse_elf64_phdrs, parse_elf64_shdrs,
    read_u16_le, read_u32_le, read_u8, section_bytes, Elf64Phdr, Elf64Shdr, ELFCLASS64,
    ELFDATA2LSB, ET_DYN, EV_CURRENT, PF_R, PF_W, PF_X, PT_GNU_RELRO, PT_LOAD, SHF_ALLOC,
    SHF_EXECINSTR, SHF_WRITE, SHN_UNDEF, SHT_ANDROID_RELA, SHT_DYNSYM, SHT_INIT_ARRAY, SHT_NOTE,
    SHT_PROGBITS, SHT_STRTAB, STB_GLOBAL, STB_WEAK, STT_FUNC,
};
use crate::runtime_policies::parse_json_object_str;
use crate::storage_paths::{is_lower_hex, MocktailHostAbiErrorCallback};
use crate::unix_ipc::{
    slice_to_pathbuf, slice_to_str_lossy, write_private_excl_file_checked, MappedReadOnlyFile,
    ReadFileError, WritePrivateError,
};
use crate::update_json::MocktailRustStrSlice;
use crate::{guest_abi, host_guest_abi, parse_elf_build_id_bytes};

const K_MAXIMUM_ELF_BYTES: u64 = 512 * 1024 * 1024;
const K_MAXIMUM_RELOCATIONS: usize = 4 * 1024 * 1024;
const K_MAXIMUM_INIT_ARRAY_ENTRIES: usize = 64 * 1024;
const K_REGISTRY_INITIALIZER_MAXIMUM_BYTES: usize = 0x1000;
const K_RELATIVE_RELOCATION: u32 = 8;
const K_GROUPED_BY_INFO: i64 = 1;
const K_GROUPED_BY_OFFSET_DELTA: i64 = 2;
const K_GROUPED_BY_ADDEND: i64 = 4;
const K_GROUP_HAS_ADDEND: i64 = 8;

const K_REQUIRED_EXPORTS: [&str; 7] = [
    "JNI_OnLoad",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeGameGlobalInit",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeUpdateAdapterInit",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeV2InitWithParams",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeStartLuaAppDM",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeV2StartAppWithParams",
    "Java_com_roblox_engine_jni_NativeGLInterface_nativeCallMessagesFromMainThread",
];

const K_TOOLCHAIN_MARKERS: [&[u8]; 2] = [
    b"Android (13624864, +pgo, +bolt, +lto, +mlgo, based on r530567e) clang version 19.0.1",
    b"Linker: LLD 19.0.1",
];

const K_FMOD_DEVICE_LISTS_SELECT_CONTRACT: &[u8; 120] = &[
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec, 0x50, 0x41,
    0x89, 0xf7, 0x49, 0x89, 0xfe, 0x4c, 0x8b, 0x25, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8b, 0x04, 0x24,
    0x48, 0x89, 0x45, 0xd8, 0x80, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x25, 0x49, 0x8b, 0x04,
    0x24, 0x48, 0x3b, 0x45, 0xd8, 0x0f, 0x85, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xf7, 0x44, 0x89,
    0xfe, 0x48, 0x83, 0xc4, 0x50, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xe9, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x8b, 0x06, 0x4c, 0x89, 0xf7, 0xff, 0x50, 0x28, 0x44, 0x39, 0xf8, 0x0f, 0x8e,
    0x00, 0x00, 0x00, 0x00, 0x31, 0xdb, 0x45, 0x85, 0xff, 0x41, 0x0f, 0x4f, 0xdf, 0x49, 0x8b, 0x7e,
    0x28, 0x89, 0xde, 0xe8, 0x00, 0x00, 0x00, 0x00,
];

#[repr(C)]
pub struct MocktailRustDeriverOptionsView {
    pub reference_library: MocktailRustStrSlice,
    pub reference_profile: MocktailRustStrSlice,
    pub reference_compatibility_manifests_ptr: *const MocktailRustStrSlice,
    pub reference_compatibility_manifests_len: usize,
    pub candidate_payload_directory: MocktailRustStrSlice,
    pub output_directory: MocktailRustStrSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MocktailRustDecodedOperandView {
    pub kind: u8,
    pub size: u8,
    pub rip_relative: bool,
    pub scale: i32,
    pub value: i64,
    pub reg_name: MocktailRustStrSlice,
    pub seg_name: MocktailRustStrSlice,
    pub base_name: MocktailRustStrSlice,
    pub index_name: MocktailRustStrSlice,
}

#[repr(C)]
pub struct MocktailRustDecodedInsnView {
    pub address: u64,
    pub size: u16,
    pub imm_offset: u8,
    pub imm_size: u8,
    pub disp_offset: u8,
    pub disp_size: u8,
    pub control_flow: bool,
    pub returns: bool,
    pub mnemonic: MocktailRustStrSlice,
    pub operands_ptr: *const MocktailRustDecodedOperandView,
    pub operand_count: usize,
}

pub type MocktailDeriverOpenX86Fn = Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>;

pub type MocktailDeriverOnInsnFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, insn: *const MocktailRustDecodedInsnView) -> bool>;

pub type MocktailDeriverDecodeX86Fn = Option<
    unsafe extern "C" fn(
        disasm_ctx: *mut c_void,
        rva: u64,
        bytes_ptr: *const u8,
        bytes_len: usize,
        count: usize,
        on_insn: MocktailDeriverOnInsnFn,
        recv_ctx: *mut c_void,
    ) -> c_int,
>;

pub type MocktailDeriverSidecarIdentityCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        elf_build_id: MocktailRustStrSlice,
        payload_id: MocktailRustStrSlice,
    ),
>;

pub type MocktailDeriverResultCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        profile_path: MocktailRustStrSlice,
        compatibility_path: MocktailRustStrSlice,
    ),
>;

fn to_slice(s: &str) -> MocktailRustStrSlice {
    MocktailRustStrSlice {
        ptr: s.as_ptr() as *const c_char,
        len: s.len(),
    }
}

fn read_small_regular_json(path: &Path) -> Result<String, String> {
    let raw = read_bounded_regular_json_bytes(path)?;
    String::from_utf8(raw).map_err(|_| format!("JSON input is not valid UTF-8: {}", path.display()))
}

fn write_private_excl(path: &Path, contents: &str) -> Result<(), String> {
    write_private_excl_file_checked(path, contents.as_bytes()).map_err(|err| match err {
        WritePrivateError::OpenFailed => "cannot create derived HostAbi artifact".to_string(),
        WritePrivateError::WriteFailed => "cannot write derived HostAbi artifact".to_string(),
        WritePrivateError::SyncFailed => "cannot persist derived HostAbi artifact".to_string(),
    })
}

struct ElfImage {
    mapped: MappedReadOnlyFile,
    segments: Vec<Elf64Phdr>,
    relro_ranges: Vec<(u64, u64)>,
    sections: Vec<Elf64Shdr>,
    by_name: BTreeMap<String, usize>,
    build_id: String,
    sha256: String,
}

impl ElfImage {
    fn open(path: &Path) -> Result<Self, String> {
        let mapped = match MappedReadOnlyFile::open_bounded(
            path,
            false,
            64,
            Some(K_MAXIMUM_ELF_BYTES),
        ) {
            Ok(file) => file,
            Err(ReadFileError::NotFound | ReadFileError::OpenFailed(_)) => {
                return Err(format!("cannot open ELF input: {}", path.display()));
            }
            Err(ReadFileError::InvalidFile) => {
                return Err("ELF input is not a bounded regular file".to_string());
            }
            Err(ReadFileError::ReadFailed) => {
                return Err("cannot map ELF input".to_string());
            }
        };

        let bytes = mapped.as_slice();
        let Some(hdr) = parse_elf64_header(bytes) else {
            return Err("candidate must be a little-endian guest-abi ET_DYN ELF".to_string());
        };
        if hdr.ei_class != ELFCLASS64
            || hdr.e_type != ET_DYN
            || hdr.e_machine != guest_abi::ELF_MACHINE
            || hdr.ei_version != EV_CURRENT
            || hdr.e_version != 1
            || hdr.ei_data != ELFDATA2LSB
        {
            return Err("candidate must be a little-endian guest-abi ET_DYN ELF".to_string());
        }

        let phdrs = parse_elf64_phdrs(bytes, &hdr)
            .map_err(|()| "cannot inspect ELF program header".to_string())?;
        if phdrs.is_empty() {
            return Err("ELF has no program headers".to_string());
        }

        let file_limit = bytes.len() as u64;
        let mut relro_ranges = Vec::new();
        let mut segments = Vec::new();
        for ph in &phdrs {
            if ph.p_type == PT_GNU_RELRO {
                if ph.p_memsz == 0 || ph.p_vaddr > u64::MAX - ph.p_memsz {
                    return Err("ELF PT_GNU_RELRO range is invalid".to_string());
                }
                relro_ranges.push((ph.p_vaddr, ph.p_memsz));
            }
            if ph.p_type != PT_LOAD {
                continue;
            }
            if ph.p_filesz > ph.p_memsz || !checked_range(ph.p_offset, ph.p_filesz, file_limit) {
                return Err("ELF PT_LOAD exceeds file bounds".to_string());
            }
            segments.push(*ph);
        }
        if segments.is_empty() {
            return Err("ELF has no PT_LOAD segments".to_string());
        }

        let sections = parse_elf64_shdrs(bytes, &hdr, true).map_err(|err| match err {
            crate::elf_reader::ShdrError::TableInvalid => "cannot enumerate ELF sections".to_string(),
            crate::elf_reader::ShdrError::SectionOutOfBounds => {
                "ELF section exceeds file bounds".to_string()
            }
        })?;
        if sections.is_empty() {
            return Err("cannot enumerate ELF sections".to_string());
        }

        let mut by_name = BTreeMap::new();
        for sec in &sections {
            if !sec.name.is_empty() && by_name.insert(sec.name.clone(), sec.index).is_some() {
                return Err(format!("ELF contains duplicate section {}", sec.name));
            }
        }

        let mut image = Self {
            mapped,
            segments,
            relro_ranges,
            sections,
            by_name,
            build_id: String::new(),
            sha256: String::new(),
        };
        image.validate_sections()?;

        let Some(build_id) = parse_elf_build_id_bytes(image.bytes()) else {
            return Err("ELF Build ID is not readable".to_string());
        };
        if !is_lower_hex(&build_id, 40) {
            return Err("ELF Build ID is not 20 bytes".to_string());
        }
        image.build_id = build_id;
        let mut hasher = Sha256::new();
        hasher.update(image.bytes());
        image.sha256 = hex::encode(hasher.finalize());
        Ok(image)
    }

    fn bytes(&self) -> &[u8] {
        self.mapped.as_slice()
    }

    fn find_section(&self, name: &str) -> Option<&Elf64Shdr> {
        let idx = *self.by_name.get(name)?;
        self.sections.get(idx)
    }

    fn bytes_at(&self, offset: u64, size: u64) -> Result<&[u8], String> {
        let file_limit = self.bytes().len() as u64;
        if !checked_range(offset, size, file_limit) {
            return Err("ELF byte range exceeds file bounds".to_string());
        }
        let off = offset as usize;
        let sz = size as usize;
        Ok(&self.bytes()[off..off + sz])
    }

    fn section_bytes(&self, sec: &Elf64Shdr) -> Result<&[u8], String> {
        if sec.sh_type == crate::elf_reader::SHT_NOBITS {
            return Err("ELF byte range exceeds file bounds".to_string());
        }
        self.bytes_at(sec.sh_offset, sec.sh_size)
    }

    fn segment_for_memory(&self, rva: u64, size: u64) -> Option<&Elf64Phdr> {
        let mut found: Option<&Elf64Phdr> = None;
        for seg in &self.segments {
            if !seg.contains_memory(rva, size) {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(seg);
        }
        found
    }

    fn require_code(&self, rva: u64, size: u64) -> Result<(), String> {
        let Some(seg) = self.segment_for_memory(rva, size) else {
            return Err("RVA is not in a read/execute ELF segment".to_string());
        };
        if !seg.contains_file(rva, size)
            || (seg.p_flags & (PF_R | PF_X)) != (PF_R | PF_X)
            || (seg.p_flags & PF_W) != 0
        {
            return Err("RVA is not in a read/execute ELF segment".to_string());
        }
        Ok(())
    }

    fn require_writable(&self, rva: u64, size: u64) -> Result<(), String> {
        let Some(seg) = self.segment_for_memory(rva, size) else {
            return Err("RVA is not in a non-executable read/write ELF segment".to_string());
        };
        if (seg.p_flags & (PF_R | PF_W)) != (PF_R | PF_W) || (seg.p_flags & PF_X) != 0 {
            return Err("RVA is not in a non-executable read/write ELF segment".to_string());
        }
        Ok(())
    }

    fn require_relro(&self, rva: u64, size: u64) -> Result<(), String> {
        let matches = self
            .relro_ranges
            .iter()
            .filter(|&&(begin, len)| rva >= begin && checked_range(rva - begin, size, len))
            .count();
        if matches != 1 {
            return Err("RVA is not in a unique PT_GNU_RELRO range".to_string());
        }
        Ok(())
    }

    fn offset_for_rva(&self, rva: u64, size: u64) -> Result<u64, String> {
        let mut selected: Option<&Elf64Phdr> = None;
        for seg in &self.segments {
            if !seg.contains_file(rva, size) {
                continue;
            }
            if selected.is_some() {
                return Err("RVA has no unique file mapping".to_string());
            }
            selected = Some(seg);
        }
        let Some(seg) = selected else {
            return Err("RVA has no file mapping".to_string());
        };
        Ok(seg.p_offset + (rva - seg.p_vaddr))
    }

    fn validate_sections(&self) -> Result<(), String> {
        let text = self.find_section(".text");
        let init = self.find_section(".init_array");
        let rela = self.find_section(".rela.dyn");
        let dynsym = self.find_section(".dynsym");
        let dynstr = self.find_section(".dynstr");
        let note = self.find_section(".note.gnu.build-id");
        let comment = self.find_section(".comment");
        let (Some(text), Some(init), Some(rela), Some(dynsym), Some(dynstr), Some(note), Some(comment)) =
            (text, init, rela, dynsym, dynstr, note, comment)
        else {
            return Err("ELF required section layout is unsupported".to_string());
        };

        let layout_ok = text.sh_type == SHT_PROGBITS
            && (text.sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) == (SHF_ALLOC | SHF_EXECINSTR)
            && (text.sh_flags & SHF_WRITE) == 0
            && init.sh_type == SHT_INIT_ARRAY
            && (init.sh_flags & (SHF_ALLOC | SHF_WRITE)) == (SHF_ALLOC | SHF_WRITE)
            && (init.sh_flags & SHF_EXECINSTR) == 0
            && init.sh_size > 0
            && init.sh_size % 8 == 0
            && (init.sh_size / 8) <= K_MAXIMUM_INIT_ARRAY_ENTRIES as u64
            && (init.sh_entsize == 0 || init.sh_entsize == 8)
            && rela.sh_type == SHT_ANDROID_RELA
            && dynsym.sh_type == SHT_DYNSYM
            && dynstr.sh_type == SHT_STRTAB
            && note.sh_type == SHT_NOTE
            && comment.sh_type == SHT_PROGBITS;
        if !layout_ok {
            return Err("ELF required section layout is unsupported".to_string());
        }
        self.require_code(text.sh_addr, text.sh_size)?;
        self.require_writable(init.sh_addr, init.sh_size)
    }

    fn validate_toolchain(&self) -> Result<(), String> {
        let Some(comment) = self.find_section(".comment") else {
            return Err("ELF is missing .comment".to_string());
        };
        let bytes = self.section_bytes(comment)?;
        for marker in K_TOOLCHAIN_MARKERS {
            if find_subslice(bytes, marker).is_none() {
                return Err("ELF compiler/linker family differs from approved reference".to_string());
            }
        }
        Ok(())
    }

    fn has_required_exports(&self) -> Result<(), String> {
        let Some(symbols) = self.find_section(".dynsym") else {
            return Err("ELF dynamic symbols are invalid".to_string());
        };
        let Some(strings) = self.sections.get(symbols.sh_link as usize) else {
            return Err("ELF dynamic symbols are invalid".to_string());
        };
        if strings.name != ".dynstr" {
            return Err("ELF .dynsym does not reference .dynstr".to_string());
        }
        let dynstr_bytes = section_bytes(self.bytes(), strings)
            .ok_or_else(|| "cannot read ELF dynamic symbols".to_string())?;
        let dynsym_bytes = section_bytes(self.bytes(), symbols)
            .ok_or_else(|| "cannot read ELF dynamic symbols".to_string())?;
        if symbols.sh_entsize < 24 {
            return Err("cannot read ELF dynamic symbols".to_string());
        }
        let entsize = usize::try_from(symbols.sh_entsize)
            .map_err(|_| "cannot read ELF dynamic symbols".to_string())?;
        let count = dynsym_bytes.len() / entsize;
        let mut exported = HashSet::new();
        for idx in 0..count {
            let base = idx * entsize;
            let st_name = read_u32_le(dynsym_bytes, base)
                .ok_or_else(|| "cannot decode ELF dynamic symbol".to_string())?;
            let st_info = read_u8(dynsym_bytes, base + 4)
                .ok_or_else(|| "cannot decode ELF dynamic symbol".to_string())?;
            let st_shndx = read_u16_le(dynsym_bytes, base + 6)
                .ok_or_else(|| "cannot decode ELF dynamic symbol".to_string())?;
            let st_type = st_info & 0x0f;
            let st_bind = st_info >> 4;
            if st_type != STT_FUNC
                || (st_bind != STB_GLOBAL && st_bind != STB_WEAK)
                || st_shndx == SHN_UNDEF
                || st_name == 0
            {
                continue;
            }
            if let Some(name_slice) = cstr_slice_at(dynstr_bytes, st_name as usize) {
                if let Ok(name) = std::str::from_utf8(name_slice) {
                    exported.insert(name);
                }
            }
        }
        for required in K_REQUIRED_EXPORTS {
            if !exported.contains(required) {
                return Err(format!("candidate is missing required JNI export: {required}"));
            }
        }
        Ok(())
    }

    fn relative_relocations(&self) -> Result<BTreeMap<u64, u64>, String> {
        let Some(rela) = self.find_section(".rela.dyn") else {
            return Err("ELF relative relocation metadata is unavailable".to_string());
        };
        let decoded = decode_aps2(self.section_bytes(rela)?)?;
        let mut result = BTreeMap::new();
        for reloc in decoded {
            if (reloc.info & 0xffff_ffff) != K_RELATIVE_RELOCATION as u64 || (reloc.info >> 32) != 0
            {
                continue;
            }
            if result.insert(reloc.offset, reloc.addend).is_some() {
                return Err("ELF contains duplicate relative relocations".to_string());
            }
        }
        Ok(result)
    }

    fn init_array(&self) -> Result<Vec<u64>, String> {
        let (Some(init), Some(rela)) = (self.find_section(".init_array"), self.find_section(".rela.dyn")) else {
            return Err("ELF init-array metadata is unavailable".to_string());
        };
        let decoded = decode_aps2(self.section_bytes(rela)?)?;
        let count = (init.sh_size / 8) as usize;
        let mut selected: Vec<Option<u64>> = vec![None; count];
        for reloc in decoded {
            if reloc.offset < init.sh_addr || reloc.offset >= init.sh_addr + init.sh_size {
                continue;
            }
            if reloc.offset % 8 != 0
                || (reloc.info & 0xffff_ffff) != K_RELATIVE_RELOCATION as u64
                || (reloc.info >> 32) != 0
            {
                return Err(".init_array contains a non-relative relocation".to_string());
            }
            let index = ((reloc.offset - init.sh_addr) / 8) as usize;
            if selected[index].is_some() {
                return Err(".init_array relocation is duplicated".to_string());
            }
            self.require_code(reloc.addend, 1)?;
            selected[index] = Some(reloc.addend);
        }
        selected
            .into_iter()
            .collect::<Option<Vec<u64>>>()
            .ok_or_else(|| ".init_array is not fully covered by APS2 relocations".to_string())
    }
}

struct SlebReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SlebReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn pop(&mut self) -> Result<i64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        let mut byte: u8;
        loop {
            if self.position >= self.bytes.len() || shift >= 70 {
                return Err("invalid or truncated APS2 SLEB128 value".to_string());
            }
            byte = self.bytes[self.position];
            self.position += 1;
            value |= ((byte & 0x7f) as u64).wrapping_shl(shift);
            shift += 7;
            if (byte & 0x80) == 0 {
                break;
            }
        }
        if shift < 64 && (byte & 0x40) != 0 {
            value |= (!0u64).wrapping_shl(shift);
        }
        Ok(value as i64)
    }

    fn at_end(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Relocation {
    offset: u64,
    info: u64,
    addend: u64,
}

/// Decodes an Android `SHT_ANDROID_RELA` APS2 packed relocation stream.
fn decode_aps2(encoded: &[u8]) -> Result<Vec<Relocation>, String> {
    if !encoded.starts_with(b"APS2") {
        return Err(".rela.dyn does not use APS2 encoding".to_string());
    }
    let mut reader = SlebReader::new(&encoded[4..]);
    let count_value = reader.pop()?;
    let first_offset = reader.pop()?;
    if count_value < 0
        || (count_value as u64) > K_MAXIMUM_RELOCATIONS as u64
        || first_offset < 0
    {
        return Err("APS2 relocation header is invalid".to_string());
    }
    let count = count_value as usize;
    let mut relocation_offset = first_offset;
    let mut relocation_info = 0i64;
    let mut relocation_addend = 0i64;
    let mut result = Vec::with_capacity(count);
    while result.len() < count {
        let group_size = reader.pop()?;
        let flags = reader.pop()?;
        if group_size <= 0
            || (group_size as u64) > (count - result.len()) as u64
            || flags < 0
            || (flags & !0x0fi64) != 0
        {
            return Err("APS2 relocation group is invalid".to_string());
        }
        let mut offset_delta = 0i64;
        if (flags & K_GROUPED_BY_OFFSET_DELTA) != 0 {
            offset_delta = reader.pop()?;
        }
        if (flags & K_GROUPED_BY_INFO) != 0 {
            relocation_info = reader.pop()?;
        }
        let addend_mode = flags & (K_GROUP_HAS_ADDEND | K_GROUPED_BY_ADDEND);
        if addend_mode == (K_GROUP_HAS_ADDEND | K_GROUPED_BY_ADDEND) {
            relocation_addend = relocation_addend.wrapping_add(reader.pop()?);
        } else if addend_mode != K_GROUP_HAS_ADDEND {
            relocation_addend = 0;
        }
        for _ in 0..group_size {
            if (flags & K_GROUPED_BY_OFFSET_DELTA) != 0 {
                relocation_offset = relocation_offset.wrapping_add(offset_delta);
            } else {
                relocation_offset = relocation_offset.wrapping_add(reader.pop()?);
            }
            if (flags & K_GROUPED_BY_INFO) == 0 {
                relocation_info = reader.pop()?;
            }
            if addend_mode == K_GROUP_HAS_ADDEND {
                relocation_addend = relocation_addend.wrapping_add(reader.pop()?);
            }
            if relocation_offset < 0 || relocation_info < 0 || relocation_addend < 0 {
                return Err("APS2 relocation exceeds unsigned bounds".to_string());
            }
            result.push(Relocation {
                offset: relocation_offset as u64,
                info: relocation_info as u64,
                addend: relocation_addend as u64,
            });
        }
    }
    if !reader.at_end() {
        return Err("APS2 relocation stream contains trailing bytes".to_string());
    }
    Ok(result)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OperandKind {
    Reg,
    Imm,
    Mem,
}

#[derive(Clone, Debug)]
struct Operand {
    kind: OperandKind,
    reg_name: String,
    seg_name: String,
    base_name: String,
    index_name: String,
    scale: i32,
    value: i64,
    size: u8,
    rip_relative: bool,
}

#[derive(Clone, Debug)]
struct Instruction {
    address: u64,
    size: u16,
    mnemonic: String,
    operands: Vec<Operand>,
    imm_offset: u8,
    imm_size: u8,
    disp_offset: u8,
    disp_size: u8,
    control_flow: bool,
    returns: bool,
}

trait X86Disassembler {
    fn open(&mut self) -> Result<(), String>;
    fn decode_raw(&self, rva: u64, code: &[u8], count: usize) -> Result<Vec<Instruction>, String>;

    fn decode(
        &self,
        image: &ElfImage,
        rva: u64,
        count: usize,
        maximum_bytes: usize,
    ) -> Result<Vec<Instruction>, String> {
        if let Err(err) = image.require_code(rva, 1) {
            return Err(err);
        }
        if count == 0 || count > 256 {
            return Err("signature instruction count is invalid".to_string());
        }
        let offset = image.offset_for_rva(rva, 1)?;
        let file_offset = offset as usize;
        let available = maximum_bytes.min(image.bytes().len().saturating_sub(file_offset));
        let bytes = image.bytes_at(offset, available as u64)?;
        let decoded = self.decode_raw(rva, bytes, count)?;
        if decoded.len() != count {
            return Err("cannot decode normalized instruction signature".to_string());
        }
        let mut expected_address = rva;
        for insn in &decoded {
            if insn.address != expected_address || insn.size == 0 {
                return Err("instruction signature is not contiguous".to_string());
            }
            expected_address = expected_address
                .checked_add(insn.size as u64)
                .ok_or_else(|| "instruction signature is not contiguous".to_string())?;
        }
        image.require_code(rva, expected_address - rva)?;
        Ok(decoded)
    }
}

struct CallbackX86Disassembler {
    ctx: *mut c_void,
    open_cb: MocktailDeriverOpenX86Fn,
    decode_cb: MocktailDeriverDecodeX86Fn,
}

unsafe extern "C" fn collect_decoded_insn_cb(
    recv_ctx: *mut c_void,
    insn_ptr: *const MocktailRustDecodedInsnView,
) -> bool {
    if recv_ctx.is_null() || insn_ptr.is_null() {
        return false;
    }
    let out = &mut *(recv_ctx as *mut Vec<Instruction>);
    let view = &*insn_ptr;
    let op_views = if view.operand_count == 0 {
        &[][..]
    } else if view.operands_ptr.is_null() {
        return false;
    } else {
        std::slice::from_raw_parts(view.operands_ptr, view.operand_count)
    };
    let mut operands = Vec::with_capacity(op_views.len());
    for op in op_views {
        let kind = match op.kind {
            0 => OperandKind::Reg,
            1 => OperandKind::Imm,
            2 => OperandKind::Mem,
            _ => return false,
        };
        operands.push(Operand {
            kind,
            reg_name: slice_to_str_lossy(op.reg_name),
            seg_name: slice_to_str_lossy(op.seg_name),
            base_name: slice_to_str_lossy(op.base_name),
            index_name: slice_to_str_lossy(op.index_name),
            scale: op.scale,
            value: op.value,
            size: op.size,
            rip_relative: op.rip_relative,
        });
    }
    out.push(Instruction {
        address: view.address,
        size: view.size,
        mnemonic: slice_to_str_lossy(view.mnemonic),
        operands,
        imm_offset: view.imm_offset,
        imm_size: view.imm_size,
        disp_offset: view.disp_offset,
        disp_size: view.disp_size,
        control_flow: view.control_flow,
        returns: view.returns,
    });
    true
}

impl X86Disassembler for CallbackX86Disassembler {
    fn open(&mut self) -> Result<(), String> {
        let Some(open_fn) = self.open_cb else {
            return Err("native Capstone major version 5 is required".to_string());
        };
        if unsafe { open_fn(self.ctx) } != 0 {
            return Err("native Capstone major version 5 is required".to_string());
        }
        Ok(())
    }

    fn decode_raw(&self, rva: u64, code: &[u8], count: usize) -> Result<Vec<Instruction>, String> {
        let Some(decode_fn) = self.decode_cb else {
            return Err("native Capstone major version 5 is required".to_string());
        };
        let mut out = Vec::with_capacity(count);
        let status = unsafe {
            decode_fn(
                self.ctx,
                rva,
                code.as_ptr(),
                code.len(),
                count,
                Some(collect_decoded_insn_cb),
                (&mut out as *mut Vec<Instruction>).cast::<c_void>(),
            )
        };
        match status {
            0 => Ok(out),
            1 => Err("native Capstone major version 5 is required".to_string()),
            2 => Err("cannot decode normalized instruction signature".to_string()),
            3 => Err("instruction signature is not contiguous".to_string()),
            4 => Err("signature contains an unsupported x86 operand".to_string()),
            _ => Err("cannot decode normalized instruction signature".to_string()),
        }
    }
}

#[derive(Clone, Debug)]
struct SignatureSpec {
    name: String,
    reference_rva: u64,
    instruction_count: usize,
    registry_size_may_change: bool,
    minimum_anchor_bytes: usize,
    registry_size_indices: [usize; 2],
}

impl SignatureSpec {
    fn basic(name: impl Into<String>, reference_rva: u64, instruction_count: usize) -> Self {
        Self {
            name: name.into(),
            reference_rva,
            instruction_count,
            registry_size_may_change: false,
            minimum_anchor_bytes: 6,
            registry_size_indices: [8, 12],
        }
    }

    fn with_anchor(
        name: impl Into<String>,
        reference_rva: u64,
        instruction_count: usize,
        minimum_anchor_bytes: usize,
    ) -> Self {
        Self {
            name: name.into(),
            reference_rva,
            instruction_count,
            registry_size_may_change: false,
            minimum_anchor_bytes,
            registry_size_indices: [8, 12],
        }
    }
}

#[derive(Clone)]
struct SignatureMatch {
    rva: u64,
    reference: Vec<Instruction>,
    candidate: Vec<Instruction>,
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    let limit = haystack.len() - needle.len();
    let mut i = 0usize;
    while i <= limit {
        let rel = haystack[i..=limit].iter().position(|&b| b == first)?;
        let idx = i + rel;
        if &haystack[idx..idx + needle.len()] == needle {
            return Some(idx);
        }
        i = idx + 1;
    }
    None
}

fn contains_bytes_limited(bytes: &[u8], expected: &[u8], limit: Option<usize>) -> bool {
    let view = match limit {
        Some(lim) if lim < bytes.len() => &bytes[..lim],
        _ => bytes,
    };
    find_subslice(view, expected).is_some()
}

fn same_semantic_operand(
    left: &Operand,
    right: &Operand,
    control_flow: bool,
    wildcard_size: bool,
) -> bool {
    if left.kind != right.kind || left.size != right.size {
        return false;
    }
    match left.kind {
        OperandKind::Reg => left.reg_name == right.reg_name,
        OperandKind::Imm => control_flow || wildcard_size || left.value == right.value,
        OperandKind::Mem => {
            left.seg_name == right.seg_name
                && left.base_name == right.base_name
                && left.index_name == right.index_name
                && left.scale == right.scale
                && left.rip_relative == right.rip_relative
                && (left.rip_relative || left.value == right.value)
        }
    }
}

fn validate_semantics(
    reference: &[Instruction],
    candidate: &[Instruction],
    spec: &SignatureSpec,
) -> Result<(), String> {
    if reference.len() != candidate.len() {
        return Err("normalized signature instruction count changed".to_string());
    }
    for index in 0..reference.len() {
        let left = &reference[index];
        let right = &candidate[index];
        let wildcard = spec.registry_size_may_change
            && (index == spec.registry_size_indices[0] || index == spec.registry_size_indices[1]);
        if left.mnemonic != right.mnemonic || left.operands.len() != right.operands.len() {
            return Err(format!("normalized instruction semantics changed at index {index}"));
        }
        for (op_left, op_right) in left.operands.iter().zip(right.operands.iter()) {
            if !same_semantic_operand(op_left, op_right, left.control_flow, wildcard) {
                return Err(format!("normalized instruction operand changed at index {index}"));
            }
        }
    }
    if spec.registry_size_may_change {
        let mut sizes = [0i64; 2];
        for (output, slot) in sizes.iter_mut().enumerate() {
            let index = spec.registry_size_indices[output];
            let Some(instruction) = candidate.get(index) else {
                return Err("registry initializer size index is outside its signature".to_string());
            };
            if instruction.operands.len() != 2 || instruction.operands[1].kind != OperandKind::Imm {
                return Err("registry initializer size operands changed".to_string());
            }
            *slot = instruction.operands[1].value;
        }
        if sizes[0] != sizes[1] || sizes[0] < 0x100 || sizes[0] > 0x1000 || sizes[0] % 8 != 0 {
            return Err("registry initializer object size is inconsistent".to_string());
        }
    }
    Ok(())
}

fn find_signature_matches(
    reference: &ElfImage,
    candidate: &ElfImage,
    disassembler: &dyn X86Disassembler,
    spec: &SignatureSpec,
    allow_multiple_candidates: bool,
) -> Result<Vec<SignatureMatch>, String> {
    let reference_instructions =
        disassembler.decode(reference, spec.reference_rva, spec.instruction_count, 4096)?;
    let last = reference_instructions
        .last()
        .ok_or_else(|| "cannot decode normalized instruction signature".to_string())?;
    let signature_size = last.address + last.size as u64 - spec.reference_rva;
    let reference_offset = reference.offset_for_rva(spec.reference_rva, signature_size)?;
    let encoded = reference.bytes_at(reference_offset, signature_size)?;

    let mut mask = vec![true; encoded.len()];
    for instruction in &reference_instructions {
        let base = (instruction.address - spec.reference_rva) as usize;
        for (offset, size) in [
            (instruction.imm_offset, instruction.imm_size),
            (instruction.disp_offset, instruction.disp_size),
        ] {
            if size == 0 {
                continue;
            }
            if offset == 0 || (offset as usize) + (size as usize) > instruction.size as usize {
                return Err("Capstone returned an invalid operand encoding range".to_string());
            }
            for idx in (offset as usize)..(offset as usize + size as usize) {
                mask[base + idx] = false;
            }
        }
    }

    let mut anchor_offset = 0usize;
    let mut anchor_size = 0usize;
    let mut run_start = 0usize;
    let mut running = false;
    for index in 0..=mask.len() {
        let enabled = index < mask.len() && mask[index];
        if enabled && !running {
            run_start = index;
            running = true;
        } else if !enabled && running {
            if index - run_start > anchor_size {
                anchor_offset = run_start;
                anchor_size = index - run_start;
            }
            running = false;
        }
    }
    if anchor_size < spec.minimum_anchor_bytes {
        return Err("normalized signature has no selective fixed anchor".to_string());
    }

    let Some(text) = candidate.find_section(".text") else {
        return Err("candidate has no .text section".to_string());
    };
    let candidate_text = candidate.section_bytes(text)?;
    let anchor = &encoded[anchor_offset..anchor_offset + anchor_size];

    let mut matches = Vec::new();
    let mut pos = 0usize;
    while pos + anchor.len() <= candidate_text.len() {
        let Some(rel) = find_subslice(&candidate_text[pos..], anchor) else {
            break;
        };
        let anchor_position = pos + rel;
        if anchor_position >= anchor_offset {
            let signature_offset = anchor_position - anchor_offset;
            if checked_range(
                signature_offset as u64,
                encoded.len() as u64,
                candidate_text.len() as u64,
            ) {
                let window = &candidate_text[signature_offset..signature_offset + encoded.len()];
                if (0..encoded.len()).all(|idx| !mask[idx] || window[idx] == encoded[idx]) {
                    matches.push(signature_offset);
                }
            }
        }
        pos = anchor_position + 1;
    }
    if matches.is_empty() {
        return Err(format!("signature {} matched 0 candidate locations", spec.name));
    }

    let mut semantic_matches = Vec::new();
    let mut first_semantic_error = String::new();
    for &offset in &matches {
        let match_rva = text.sh_addr + offset as u64;
        let candidate_instructions =
            disassembler.decode(candidate, match_rva, spec.instruction_count, 4096);
        let validated = candidate_instructions.and_then(|insns| {
            validate_semantics(&reference_instructions, &insns, spec)?;
            Ok(insns)
        });
        match validated {
            Ok(insns) => {
                semantic_matches.push(SignatureMatch {
                    rva: match_rva,
                    reference: reference_instructions.clone(),
                    candidate: insns,
                });
            }
            Err(err) => {
                if first_semantic_error.is_empty() {
                    first_semantic_error = err;
                }
            }
        }
    }

    if semantic_matches.is_empty() && matches.len() == 1 && !first_semantic_error.is_empty() {
        return Err(first_semantic_error);
    }
    if !allow_multiple_candidates && semantic_matches.len() != 1 {
        return Err(format!(
            "signature {} matched {} semantic candidate locations",
            spec.name,
            semantic_matches.len()
        ));
    }
    Ok(semantic_matches)
}

fn find_signature_match(
    reference: &ElfImage,
    candidate: &ElfImage,
    disassembler: &dyn X86Disassembler,
    spec: &SignatureSpec,
) -> Result<SignatureMatch, String> {
    let mut matches = find_signature_matches(reference, candidate, disassembler, spec, false)?;
    if matches.len() != 1 {
        return Err(format!(
            "signature {} matched {} candidate locations",
            spec.name,
            matches.len()
        ));
    }
    Ok(matches.swap_remove(0))
}

fn find_unique_semantic_signature_match(
    reference: &ElfImage,
    candidate: &ElfImage,
    disassembler: &dyn X86Disassembler,
    spec: &SignatureSpec,
) -> Result<SignatureMatch, String> {
    let mut matches = find_signature_matches(reference, candidate, disassembler, spec, true)?;
    if matches.len() != 1 {
        return Err(format!(
            "signature {} matched {} semantic candidate locations",
            spec.name,
            matches.len()
        ));
    }
    Ok(matches.swap_remove(0))
}

#[derive(Clone, Copy)]
struct FmodRuntimeAnchors {
    vtable: u64,
    string_constructor: u64,
    count_method: u64,
    info_method: u64,
    current_method: u64,
    select_method: u64,
    layout_version: i32,
    input_methods: [u64; 4],
}

impl FmodRuntimeAnchors {
    fn from_raw(raw: &MocktailRustDeriverRuntimeAnchors) -> Self {
        Self {
            vtable: raw.fmod_vtable_rva,
            string_constructor: raw.fmod_string_constructor_rva,
            count_method: raw.fmod_count_method_rva,
            info_method: raw.fmod_info_method_rva,
            current_method: raw.fmod_current_method_rva,
            select_method: raw.fmod_select_method_rva,
            layout_version: raw.fmod_layout_version,
            input_methods: raw.fmod_input_methods,
        }
    }

    fn input_indexes(&self) -> [usize; 4] {
        if self.layout_version == 2 {
            [9, 10, 12, 18]
        } else {
            [8, 9, 10, 16]
        }
    }

    fn current_index(&self) -> usize {
        if self.layout_version == 2 {
            8
        } else {
            7
        }
    }

    fn select_index(&self) -> usize {
        if self.layout_version == 2 {
            19
        } else {
            17
        }
    }
}

struct RuntimeCompatibilityAnchors {
    fullscreen_setter: Option<u64>,
    fmod: Option<FmodRuntimeAnchors>,
}

fn load_runtime_compatibility_anchors(
    paths: &[PathBuf],
    reference_build_id: &str,
) -> Result<RuntimeCompatibilityAnchors, String> {
    let mut contents = Vec::with_capacity(paths.len());
    let mut path_strings = Vec::with_capacity(paths.len());
    for path in paths {
        contents.push(read_small_regular_json(path)?);
        path_strings.push(path.to_string_lossy().into_owned());
    }
    let pairs: Vec<(&str, &str)> = contents
        .iter()
        .zip(path_strings.iter())
        .map(|(c, p)| (c.as_str(), p.as_str()))
        .collect();
    let raw = load_runtime_anchors_data(&pairs, reference_build_id)?;
    Ok(RuntimeCompatibilityAnchors {
        fullscreen_setter: raw.has_fullscreen_setter.then_some(raw.fullscreen_setter_rva),
        fmod: raw.has_fmod.then(|| FmodRuntimeAnchors::from_raw(&raw)),
    })
}

fn has_fullscreen_setter_contract(image: &ElfImage, rva: u64) -> bool {
    const CONTRACT_BYTES: usize = 96;
    if image.require_code(rva, CONTRACT_BYTES as u64).is_err() {
        return false;
    }
    let Ok(offset) = image.offset_for_rva(rva, CONTRACT_BYTES as u64) else {
        return false;
    };
    let Ok(code) = image.bytes_at(offset, CONTRACT_BYTES as u64) else {
        return false;
    };
    if !code.starts_with(b"\x55\x48\x89\xe5") || !contains_bytes_limited(code, b"\x89\xf3", Some(24))
    {
        return false;
    }
    (contains_bytes_limited(code, b"\x38\x98\x59\x01\x00\x00", None)
        && contains_bytes_limited(code, b"\x88\x98\x59\x01\x00\x00", None))
        || (contains_bytes_limited(code, b"\x38\x98\x61\x01\x00\x00", None)
            && contains_bytes_limited(code, b"\x88\x98\x61\x01\x00\x00", None))
}

fn has_fmod_string_constructor_contract(image: &ElfImage, rva: u64) -> bool {
    const EXPECTED: &[u8] = b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x54\x53\x48\x89\xd3\x49\x89\xf6\x49\x89\xff\x48\x83\xfa\x16";
    if image.require_code(rva, EXPECTED.len() as u64).is_err() {
        return false;
    }
    let Ok(offset) = image.offset_for_rva(rva, EXPECTED.len() as u64) else {
        return false;
    };
    image.bytes_at(offset, EXPECTED.len() as u64) == Ok(EXPECTED)
}

fn has_fmod_device_lists_select_contract(image: &ElfImage, rva: u64) -> bool {
    let size = K_FMOD_DEVICE_LISTS_SELECT_CONTRACT.len() as u64;
    if image.require_code(rva, size).is_err() {
        return false;
    }
    let Ok(offset) = image.offset_for_rva(rva, size) else {
        return false;
    };
    let Ok(code) = image.bytes_at(offset, size) else {
        return false;
    };
    for (idx, (&actual, &expected)) in code
        .iter()
        .zip(K_FMOD_DEVICE_LISTS_SELECT_CONTRACT.iter())
        .enumerate()
    {
        let relocated = [24usize, 38, 55, 78, 96, 116]
            .iter()
            .any(|&start| idx >= start && idx < start + 4);
        if !relocated && actual != expected {
            return false;
        }
    }
    true
}

fn derive_runtime_compatibility(
    reference: &ElfImage,
    candidate: &ElfImage,
    disassembler: &dyn X86Disassembler,
    source: &RuntimeCompatibilityAnchors,
) -> Result<RuntimeCompatibilityAnchors, String> {
    let mut result = RuntimeCompatibilityAnchors {
        fullscreen_setter: None,
        fmod: None,
    };
    if let Some(ref_setter) = source.fullscreen_setter {
        if !has_fullscreen_setter_contract(reference, ref_setter) {
            return Err("reference fullscreen setter contract changed".to_string());
        }
        let setter = find_unique_semantic_signature_match(
            reference,
            candidate,
            disassembler,
            &SignatureSpec::with_anchor("fullscreen-setter", ref_setter, 32, 3),
        )?;
        if !has_fullscreen_setter_contract(candidate, setter.rva) {
            return Err("candidate fullscreen setter contract changed".to_string());
        }
        result.fullscreen_setter = Some(setter.rva);
    }

    let Some(old) = source.fmod else {
        return Ok(result);
    };

    const K_COUNT_INDEX: usize = 5;
    const K_INFO_INDEX: usize = 6;
    reference.require_relro(old.vtable, ((old.select_index() + 1) * 8) as u64)?;
    let reference_relocations = reference.relative_relocations()?;
    for (index, method) in [
        (K_COUNT_INDEX, old.count_method),
        (K_INFO_INDEX, old.info_method),
        (old.current_index(), old.current_method),
        (old.select_index(), old.select_method),
    ] {
        let Some(&found) = reference_relocations.get(&(old.vtable + (index * 8) as u64)) else {
            return Err("reference FMOD vtable does not match its methods".to_string());
        };
        if found != method {
            return Err("reference FMOD vtable does not match its methods".to_string());
        }
        reference.require_code(method, 1)?;
    }

    if !has_fmod_string_constructor_contract(reference, old.string_constructor) {
        return Err("reference FMOD string constructor contract changed".to_string());
    }

    let string_constructor = find_unique_semantic_signature_match(
        reference,
        candidate,
        disassembler,
        &SignatureSpec::with_anchor("fmod-string-constructor", old.string_constructor, 32, 3),
    )?;
    let info_method = find_unique_semantic_signature_match(
        reference,
        candidate,
        disassembler,
        &SignatureSpec::with_anchor("fmod-output-info", old.info_method, 18, 3),
    )?;
    let select_method = find_unique_semantic_signature_match(
        reference,
        candidate,
        disassembler,
        &SignatureSpec::with_anchor("fmod-output-select", old.select_method, 18, 3),
    )
    .ok();

    let count_matches = find_signature_matches(
        reference,
        candidate,
        disassembler,
        &SignatureSpec::with_anchor("fmod-output-count", old.count_method, 24, 3),
        true,
    )?;
    let current_matches = find_signature_matches(
        reference,
        candidate,
        disassembler,
        &SignatureSpec::with_anchor("fmod-output-current", old.current_method, 24, 3),
        true,
    )?;
    let count_candidates: HashSet<u64> = count_matches.into_iter().map(|m| m.rva).collect();
    let current_candidates: HashSet<u64> = current_matches.into_iter().map(|m| m.rva).collect();
    if count_candidates.is_empty() || current_candidates.is_empty() {
        return Err("FMOD count/current method signatures have no candidates".to_string());
    }

    let relocations = candidate.relative_relocations()?;
    let mut candidates = Vec::new();
    for (&offset, &addend) in &relocations {
        if addend != info_method.rva || offset < (K_INFO_INDEX * 8) as u64 {
            continue;
        }
        let vtable = offset - (K_INFO_INDEX * 8) as u64;
        let count_slot = relocations.get(&(vtable + (K_COUNT_INDEX * 8) as u64));
        for layout in [1i32, 2] {
            let mut derived = FmodRuntimeAnchors {
                vtable,
                string_constructor: string_constructor.rva,
                count_method: 0,
                info_method: info_method.rva,
                current_method: 0,
                select_method: 0,
                layout_version: layout,
                input_methods: [0; 4],
            };
            let current_slot = relocations.get(&(vtable + (derived.current_index() * 8) as u64));
            let select_slot = relocations.get(&(vtable + (derived.select_index() * 8) as u64));
            let (Some(&count_rva), Some(&current_rva), Some(&select_rva)) =
                (count_slot, current_slot, select_slot)
            else {
                continue;
            };
            if vtable % 8 != 0
                || !count_candidates.contains(&count_rva)
                || !current_candidates.contains(&current_rva)
                || count_rva == current_rva
                || candidate
                    .require_relro(vtable, ((derived.select_index() + 1) * 8) as u64)
                    .is_err()
            {
                continue;
            }
            if layout == 1 {
                if old.layout_version != 1
                    || select_method
                        .as_ref()
                        .is_none_or(|sel| select_rva != sel.rva)
                {
                    continue;
                }
            } else if !has_fmod_device_lists_select_contract(candidate, select_rva) {
                continue;
            }
            derived.count_method = count_rva;
            derived.current_method = current_rva;
            derived.select_method = select_rva;
            candidates.push(derived);
        }
    }
    if candidates.len() != 1 {
        return Err(format!(
            "FMOD output vtable matched {} candidate locations",
            candidates.len()
        ));
    }
    let mut output = candidates[0];
    if !has_fmod_string_constructor_contract(candidate, output.string_constructor) {
        return Err("candidate FMOD string constructor contract changed".to_string());
    }

    if old.input_methods[0] != 0 {
        let fields = [
            "input_count_method_rva",
            "input_info_method_rva",
            "input_current_method_rva",
            "input_select_method_rva",
        ];
        let lengths = [4usize, 16, 12, 16];
        let old_slots = old.input_indexes();
        let new_slots = output.input_indexes();
        for i in 0..fields.len() {
            let old_method = reference_relocations.get(&(old.vtable + (old_slots[i] * 8) as u64));
            let new_method = relocations.get(&(output.vtable + (new_slots[i] * 8) as u64));
            if old_method != Some(&old.input_methods[i]) || new_method.is_none() {
                return Err("FMOD input vtable does not match its methods".to_string());
            }
            let target_rva = *new_method.unwrap();
            let matches = find_signature_matches(
                reference,
                candidate,
                disassembler,
                &SignatureSpec::with_anchor(fields[i], old.input_methods[i], lengths[i], 3),
                true,
            )?;
            if !matches.iter().any(|m| m.rva == target_rva) {
                return Err("candidate FMOD input contract changed".to_string());
            }
            output.input_methods[i] = target_rva;
        }
    }
    result.fmod = Some(output);
    Ok(result)
}

fn find_registry_function_entry(
    image: &ElfImage,
    disassembler: &dyn X86Disassembler,
    body_rva: u64,
    reference_prologue: &[Instruction],
) -> Result<u64, String> {
    const K_PROLOGUE_INSN_COUNT: usize = 8;
    const K_MAX_PROLOGUE_BYTES: u64 = 64;
    if reference_prologue.len() != K_PROLOGUE_INSN_COUNT || body_rva < K_MAX_PROLOGUE_BYTES {
        return Err("reference registry prologue shape is invalid".to_string());
    }
    let mut entries = Vec::new();
    for rva in (body_rva - K_MAX_PROLOGUE_BYTES)..body_rva {
        let Ok(candidate) = disassembler.decode(
            image,
            rva,
            K_PROLOGUE_INSN_COUNT,
            (body_rva - rva) as usize,
        ) else {
            continue;
        };
        let Some(last) = candidate.last() else {
            continue;
        };
        if last.address + last.size as u64 != body_rva {
            continue;
        }
        let mut same = true;
        for (index, (left, right)) in reference_prologue.iter().zip(candidate.iter()).enumerate() {
            if left.mnemonic != right.mnemonic || left.operands.len() != right.operands.len() {
                same = false;
                break;
            }
            for (op_l, op_r) in left.operands.iter().zip(right.operands.iter()) {
                if !same_semantic_operand(op_l, op_r, left.control_flow, index == 7) {
                    same = false;
                    break;
                }
            }
            if !same {
                break;
            }
        }
        if same
            && last.mnemonic == "sub"
            && last.operands.len() == 2
            && last.operands[0].kind == OperandKind::Reg
            && last.operands[0].reg_name == "rsp"
            && last.operands[1].kind == OperandKind::Imm
            && last.operands[1].value >= 0x20
            && last.operands[1].value <= 0x400
            && last.operands[1].value % 8 == 0
        {
            entries.push(rva);
        }
    }
    if entries.len() != 1 {
        return Err("registry initializer body has no unique bounded prologue".to_string());
    }
    Ok(entries[0])
}

fn reg_operand(insn: &Instruction, index: usize, size: u8) -> &str {
    insn.operands
        .get(index)
        .filter(|op| op.kind == OperandKind::Reg && op.size == size)
        .map(|op| op.reg_name.as_str())
        .unwrap_or("")
}

fn normalize_registry_registers(instructions: &mut [Instruction]) -> bool {
    if instructions.len() != 11 {
        return false;
    }
    let zero_reg = reg_operand(&instructions[3], 0, 4).to_string();
    let zero_src = reg_operand(&instructions[3], 1, 4).to_string();
    let factor_reg = reg_operand(&instructions[8], 0, 4).to_string();
    let store_src = reg_operand(&instructions[9], 1, 4).to_string();
    let begin_reg = reg_operand(&instructions[10], 0, 8).to_string();

    let is_saved32 = |r: &str| matches!(r, "r12d" | "r13d" | "r14d" | "r15d");
    let is_pointer = |r: &str| matches!(r, "rcx" | "r12" | "r13" | "r14" | "r15");
    let begin_d = format!("{begin_reg}d");

    if instructions[3].mnemonic != "xor"
        || !is_saved32(&zero_reg)
        || zero_src != zero_reg
        || instructions[8].mnemonic != "mov"
        || (factor_reg != "eax" && !is_saved32(&factor_reg))
        || instructions[9].mnemonic != "mov"
        || store_src != factor_reg
        || instructions[10].mnemonic != "lea"
        || !is_pointer(&begin_reg)
        || zero_reg == factor_reg
        || zero_reg == begin_d
        || factor_reg == begin_d
    {
        return false;
    }

    instructions[3].operands[0].reg_name = "registry-zero".to_string();
    instructions[3].operands[1].reg_name = "registry-zero".to_string();
    instructions[8].operands[0].reg_name = "registry-factor".to_string();
    instructions[9].operands[1].reg_name = "registry-factor".to_string();
    instructions[10].operands[0].reg_name = "registry-begin".to_string();
    true
}

fn find_registry_signature_match(
    reference: &ElfImage,
    candidate: &ElfImage,
    disassembler: &dyn X86Disassembler,
    spec: &SignatureSpec,
) -> Result<SignatureMatch, String> {
    const K_BODY_INDEX: usize = 8;
    const K_BODY_COUNT: usize = 11;
    let reference_full =
        disassembler.decode(reference, spec.reference_rva, spec.instruction_count, 4096)?;
    if reference_full.len() < K_BODY_INDEX + K_BODY_COUNT {
        return Err("reference registry signature is incomplete".to_string());
    }
    let body_spec = SignatureSpec {
        name: "registry-initializer-body".to_string(),
        reference_rva: reference_full[K_BODY_INDEX].address,
        instruction_count: K_BODY_COUNT,
        registry_size_may_change: true,
        minimum_anchor_bytes: spec.minimum_anchor_bytes,
        registry_size_indices: [0, 4],
    };
    let reference_prologue = &reference_full[..K_BODY_INDEX];
    let mut normalized_reference = reference_full[K_BODY_INDEX..K_BODY_INDEX + K_BODY_COUNT].to_vec();

    let body_match = if normalize_registry_registers(&mut normalized_reference) {
        let clear_spec = SignatureSpec {
            name: "registry-size-and-clear".to_string(),
            reference_rva: reference_full[12].address,
            instruction_count: 4,
            registry_size_may_change: true,
            minimum_anchor_bytes: spec.minimum_anchor_bytes,
            registry_size_indices: [0, 0],
        };
        let clear_matches =
            find_signature_matches(reference, candidate, disassembler, &clear_spec, true)?;
        let mut valid = Vec::new();
        for clear in clear_matches {
            if clear.rva < 16 {
                continue;
            }
            let Ok(body) = disassembler.decode(candidate, clear.rva - 16, K_BODY_COUNT, 4096) else {
                continue;
            };
            if body[4].address != clear.rva {
                continue;
            }
            let mut normalized = body.clone();
            if !normalize_registry_registers(&mut normalized)
                || validate_semantics(&normalized_reference, &normalized, &body_spec).is_err()
                || find_registry_function_entry(
                    candidate,
                    disassembler,
                    clear.rva - 16,
                    reference_prologue,
                )
                .is_err()
            {
                continue;
            }
            valid.push(SignatureMatch {
                rva: clear.rva - 16,
                reference: normalized_reference.clone(),
                candidate: body,
            });
        }
        if valid.len() != 1 {
            return Err(format!(
                "registry register contract matched {} candidate locations",
                valid.len()
            ));
        }
        valid.swap_remove(0)
    } else {
        find_signature_match(reference, candidate, disassembler, &body_spec)?
    };

    let candidate_entry = find_registry_function_entry(
        candidate,
        disassembler,
        body_match.rva,
        reference_prologue,
    )?;
    let candidate_full =
        disassembler.decode(candidate, candidate_entry, spec.instruction_count, 4096)?;
    if candidate_full
        .get(K_BODY_INDEX)
        .is_none_or(|insn| insn.address != body_match.rva)
    {
        return Err("candidate registry signature is incomplete".to_string());
    }
    Ok(SignatureMatch {
        rva: candidate_entry,
        reference: reference_full,
        candidate: candidate_full,
    })
}

fn direct_call_target(insn: &Instruction, description: &str) -> Result<u64, String> {
    if insn.mnemonic != "call"
        || insn.operands.len() != 1
        || insn.operands[0].kind != OperandKind::Imm
        || insn.operands[0].value < 0
    {
        return Err(format!("{description} is not one direct call"));
    }
    Ok(insn.operands[0].value as u64)
}

fn direct_jump_target(insn: &Instruction, description: &str) -> Result<u64, String> {
    if insn.mnemonic != "jmp"
        || insn.operands.len() != 1
        || insn.operands[0].kind != OperandKind::Imm
        || insn.operands[0].value < 0
    {
        return Err(format!("{description} is not one direct jump"));
    }
    Ok(insn.operands[0].value as u64)
}

fn find_constructor_boundary_match(
    reference: &ElfImage,
    candidate: &ElfImage,
    disassembler: &dyn X86Disassembler,
    spec: &SignatureSpec,
    reference_entry: u64,
    candidate_entries: &[u64],
) -> Result<SignatureMatch, String> {
    if reference_entry != spec.reference_rva {
        return Err("reference constructor boundary moved outside init-array index 4".to_string());
    }
    let reference_wrapper = disassembler.decode(reference, reference_entry, 1, 16)?;
    let reference_target =
        direct_jump_target(&reference_wrapper[0], "reference constructor boundary")?;
    let target_spec =
        SignatureSpec::basic("constructor-4-target", reference_target, spec.instruction_count);
    let target_match = find_signature_match(reference, candidate, disassembler, &target_spec)?;

    let mut matches = Vec::new();
    for &entry in candidate_entries {
        let Ok(wrapper) = disassembler.decode(candidate, entry, 1, 16) else {
            continue;
        };
        if let Ok(target) = direct_jump_target(&wrapper[0], "constructor boundary") {
            if target == target_match.rva {
                matches.push(SignatureMatch {
                    rva: entry,
                    reference: reference_wrapper.clone(),
                    candidate: wrapper,
                });
            }
        }
    }
    if matches.len() != 1 {
        return Err("constructor boundary has no unique init-array entry".to_string());
    }
    Ok(matches.swap_remove(0))
}

fn rip_targets(insn: &Instruction) -> Vec<u64> {
    let mut out = Vec::new();
    for op in &insn.operands {
        if op.kind == OperandKind::Mem && op.rip_relative {
            if let Some(target) = insn
                .address
                .checked_add(insn.size as u64)
                .and_then(|next| next.checked_add_signed(op.value))
            {
                out.push(target);
            }
        }
    }
    out
}

fn singleton_body_rva(
    image: &ElfImage,
    disassembler: &dyn X86Disassembler,
    entry: u64,
) -> Result<u64, String> {
    let prefix = disassembler.decode(image, entry, 2, 32)?;
    if prefix[0].mnemonic != "push" {
        return Ok(entry);
    }
    let push = &prefix[0];
    let mv = &prefix[1];
    if push.operands.len() != 1
        || push.operands[0].reg_name != "rbp"
        || mv.mnemonic != "mov"
        || mv.operands.len() != 2
        || mv.operands[0].reg_name != "rbp"
        || mv.operands[1].reg_name != "rsp"
    {
        return Err("JNI singleton has an unsupported prologue".to_string());
    }
    Ok(mv.address + mv.size as u64)
}

fn has_singleton_links(instructions: &[Instruction]) -> bool {
    if instructions.len() != 3
        || instructions[0].mnemonic != "lea"
        || instructions[1].mnemonic != "xchg"
        || instructions[2].mnemonic != "mov"
    {
        return false;
    }
    let head = rip_targets(&instructions[0]);
    let slot = rip_targets(&instructions[1]);
    let next = rip_targets(&instructions[2]);
    head.len() == 1
        && slot.len() == 1
        && next.len() == 1
        && slot[0] % 8 == 0
        && head[0] == slot[0] + 8
        && next[0] == head[0]
}

fn find_singleton_signature_match(
    reference: &ElfImage,
    candidate: &ElfImage,
    disassembler: &dyn X86Disassembler,
    spec: &SignatureSpec,
    candidate_entries: &[u64],
) -> Result<SignatureMatch, String> {
    let body = singleton_body_rva(reference, disassembler, spec.reference_rva)?;
    let matches = find_signature_matches(
        reference,
        candidate,
        disassembler,
        &SignatureSpec::with_anchor("jni-singleton-links", body, 3, 3),
        true,
    )?;
    let mut valid = Vec::new();
    for m in matches {
        if !has_singleton_links(&m.reference) || !has_singleton_links(&m.candidate) {
            continue;
        }
        for &entry in candidate_entries {
            if entry != m.rva && (m.rva < 4 || entry != m.rva - 4) {
                continue;
            }
            if let Ok(candidate_body) = singleton_body_rva(candidate, disassembler, entry) {
                if candidate_body == m.rva {
                    valid.push(SignatureMatch {
                        rva: entry,
                        reference: m.reference.clone(),
                        candidate: m.candidate.clone(),
                    });
                }
            }
        }
    }
    if valid.len() != 1 {
        return Err("JNI singleton links have no unique init-array entry".to_string());
    }
    Ok(valid.swap_remove(0))
}

fn mapped_rip_target(
    m: &SignatureMatch,
    reference_target: u64,
    description: &str,
) -> Result<u64, String> {
    let mut candidates = BTreeMap::<u64, ()>::new();
    for (ref_insn, cand_insn) in m.reference.iter().zip(m.candidate.iter()) {
        let ref_targets = rip_targets(ref_insn);
        let cand_targets = rip_targets(cand_insn);
        if ref_targets.len() != cand_targets.len() {
            return Err(format!("{description} RIP-relative operand count changed"));
        }
        for (rt, ct) in ref_targets.into_iter().zip(cand_targets.into_iter()) {
            if rt == reference_target {
                candidates.insert(ct, ());
            }
        }
    }
    if candidates.len() != 1 {
        return Err(format!("{description} has no unique mapped RIP target"));
    }
    Ok(*candidates.keys().next().unwrap())
}

fn derive_registry_slot(
    image: &ElfImage,
    disassembler: &dyn X86Disassembler,
    initializer: u64,
) -> Result<u64, String> {
    let instructions =
        disassembler.decode(image, initializer, 256, K_REGISTRY_INITIALIZER_MAXIMUM_BYTES)?;
    let mut stores = Vec::new();
    let mut found_return = false;
    for insn in &instructions {
        if insn.mnemonic == "mov"
            && insn.operands.len() == 2
            && insn.operands[0].kind == OperandKind::Mem
            && insn.operands[0].rip_relative
            && insn.operands[0].size == 8
            && insn.operands[1].kind == OperandKind::Reg
            && insn.operands[1].reg_name == "rbx"
        {
            if let Some(target) = insn
                .address
                .checked_add(insn.size as u64)
                .and_then(|next| next.checked_add_signed(insn.operands[0].value))
            {
                stores.push(target);
            }
        }
        if insn.returns {
            found_return = true;
            break;
        }
    }
    if !found_return || stores.len() != 1 || stores[0] % 8 != 0 {
        return Err("pre-JNI registry initializer does not publish one slot".to_string());
    }
    image.require_writable(stores[0], 8)?;
    Ok(stores[0])
}

fn parsed_spec_to_sig(spec: ParsedSpec) -> SignatureSpec {
    SignatureSpec {
        name: spec.name.to_string(),
        reference_rva: spec.rva,
        instruction_count: spec.instruction_count,
        registry_size_may_change: spec.registry_size_may_change,
        minimum_anchor_bytes: spec.minimum_anchor_bytes,
        registry_size_indices: [8, 12],
    }
}

fn derive_documents(
    reference: &ElfImage,
    candidate: &ElfImage,
    sidecar_json: &str,
    metadata_json: &str,
    runtime_source: &RuntimeCompatibilityAnchors,
    disassembler: &mut dyn X86Disassembler,
) -> Result<(String, String), String> {
    let sidecar = parse_json_object_str(sidecar_json, true)
        .ok_or_else(|| "JSON input must contain one object".to_string())?;
    validate_reference_identity_inner(&sidecar, &reference.build_id, &reference.sha256)?;
    if reference.build_id == candidate.build_id || reference.sha256 == candidate.sha256 {
        return Err("candidate ELF matches reference ELF".to_string());
    }
    reference.validate_toolchain()?;
    candidate.validate_toolchain()?;
    candidate.has_required_exports()?;

    disassembler.open()?;

    let specs: Vec<SignatureSpec> = extract_specs_inner(&sidecar)?
        .into_iter()
        .map(parsed_spec_to_sig)
        .collect();
    let reference_init = reference.init_array()?;
    let candidate_init = candidate.init_array()?;
    let reference_count = check_init_array_data(&sidecar, reference_init.len(), candidate_init.len())?;

    let mut matches = BTreeMap::<String, SignatureMatch>::new();
    let mut allocate_matches = Vec::<SignatureMatch>::new();
    for spec in specs {
        if spec.name == "allocate" {
            allocate_matches =
                find_signature_matches(reference, candidate, disassembler, &spec, true)?;
            continue;
        }
        let m = match spec.name.as_str() {
            "registry-initializer" => {
                find_registry_signature_match(reference, candidate, disassembler, &spec)?
            }
            "jni-singleton-initializer" => find_singleton_signature_match(
                reference,
                candidate,
                disassembler,
                &spec,
                &candidate_init,
            )?,
            "constructor-4" => find_constructor_boundary_match(
                reference,
                candidate,
                disassembler,
                &spec,
                spec.reference_rva,
                &candidate_init,
            )?,
            _ => find_signature_match(reference, candidate, disassembler, &spec)?,
        };
        matches.insert(spec.name, m);
    }

    let registry_match = matches
        .get("registry-initializer")
        .ok_or_else(|| "allocator signatures are incomplete".to_string())?;
    if allocate_matches.is_empty()
        || registry_match.reference.len() <= 9
        || registry_match.candidate.len() <= 9
    {
        return Err("allocator signatures are incomplete".to_string());
    }
    let reference_allocate = direct_call_target(
        &registry_match.reference[9],
        "reference registry allocator call",
    )?;
    if reference_allocate != allocate_matches[0].reference[0].address {
        return Err("reference registry initializer does not call its allocator bridge".to_string());
    }
    let candidate_allocate = direct_call_target(
        &registry_match.candidate[9],
        "candidate registry allocator call",
    )?;
    let selected: Vec<&SignatureMatch> = allocate_matches
        .iter()
        .filter(|m| m.rva == candidate_allocate)
        .collect();
    if selected.len() != 1 {
        return Err(
            "signature allocate candidates do not identify exactly one registry allocator call"
                .to_string(),
        );
    }
    let registry_initializer = registry_match.rva;
    let registry_call = registry_match.candidate[9].clone();
    let allocate_match = selected[0].clone();
    matches.insert("allocate".to_string(), allocate_match);

    let ctor2 = matches.get("constructor-2").unwrap();
    let ctor3 = matches.get("constructor-3").unwrap();
    let ctor4 = matches.get("constructor-4").unwrap();
    let singleton = matches.get("jni-singleton-initializer").unwrap();
    if ctor2.reference.is_empty() || ctor3.reference.is_empty() || ctor4.reference.is_empty() {
        return Err("constructor role signature has no reference instructions".to_string());
    }

    let ctor_cand_rvas = [ctor2.rva, ctor3.rva, ctor4.rva, singleton.rva];
    let ctor_ref_first_rvas = [
        ctor2.reference[0].address,
        ctor3.reference[0].address,
        ctor4.reference[0].address,
    ];
    let plan = resolve_constructors_and_seeds_inner(
        &sidecar,
        &reference_init,
        &candidate_init,
        &ctor_cand_rvas,
        &ctor_ref_first_rvas,
    )?;

    let allocator_slot = mapped_rip_target(
        matches.get("allocator-object-initializer").unwrap(),
        plan.allocator_object_slot_rva,
        "allocator_object_slot",
    )?;
    let empty_slot = mapped_rip_target(
        matches.get("empty-string-initializer").unwrap(),
        plan.empty_string_slot_rva,
        "empty_string_slot",
    )?;
    let jni_slot = mapped_rip_target(
        singleton,
        plan.jni_singleton_slot_rva,
        "jni_singleton_slot",
    )?;
    let arena_guard = mapped_rip_target(
        matches.get("arena-initializer").unwrap(),
        plan.arena_guard_slot_rva,
        "arena_guard_slot",
    )?;
    let arena_table = mapped_rip_target(
        matches.get("usable-size").unwrap(),
        plan.arena_table_slot_rva,
        "arena_table_slot",
    )?;
    for slot in [allocator_slot, empty_slot, jni_slot, arena_guard, arena_table] {
        candidate.require_writable(slot, 8)?;
    }

    let verified_old_slot =
        derive_registry_slot(reference, disassembler, plan.old_registry_initializer_rva)?;
    if verified_old_slot != plan.old_registry_slot_rva {
        return Err("reference registry slot does not match ELF".to_string());
    }
    let registry_slot = derive_registry_slot(candidate, disassembler, registry_initializer)?;
    let allocate_rva = matches.get("allocate").unwrap().rva;
    if registry_call.operands.len() != 1
        || registry_call.operands[0].kind != OperandKind::Imm
        || registry_call.operands[0].value as u64 != allocate_rva
    {
        return Err("registry initializer no longer calls native allocator".to_string());
    }

    let init_section = candidate
        .find_section(".init_array")
        .ok_or_else(|| "candidate init-array section is unavailable".to_string())?;
    let runtime_compatibility =
        derive_runtime_compatibility(reference, candidate, disassembler, runtime_source)?;

    let fmod = runtime_compatibility.fmod;
    let inputs = MocktailRustDeriverBuildInputs {
        ref_build_id: to_slice(&reference.build_id),
        ref_sha256: to_slice(&reference.sha256),
        cand_build_id: to_slice(&candidate.build_id),
        cand_sha256: to_slice(&candidate.sha256),
        reference_init_count: reference_count,
        candidate_init_count: candidate_init.len(),
        init_array_offset: init_section.sh_addr,
        bridge_rvas: [
            matches.get("small-allocate").unwrap().rva,
            matches.get("usable-size").unwrap().rva,
            matches.get("reallocate").unwrap().rva,
            allocate_rva,
            matches.get("aligned-allocate-direct").unwrap().rva,
            matches.get("free").unwrap().rva,
        ],
        arena_initializer_rva: matches.get("arena-initializer").unwrap().rva,
        allocator_thread_initializer_rva: matches.get("allocator-thread-initializer").unwrap().rva,
        registry_initializer_rva: registry_initializer,
        registry_slot_rva: registry_slot,
        allocator_object_initializer_rva: matches.get("allocator-object-initializer").unwrap().rva,
        empty_string_initializer_rva: matches.get("empty-string-initializer").unwrap().rva,
        jni_singleton_initializer_rva: singleton.rva,
        allocator_object_slot_rva: allocator_slot,
        empty_string_slot_rva: empty_slot,
        jni_singleton_slot_rva: jni_slot,
        arena_guard_slot_rva: arena_guard,
        arena_table_slot_rva: arena_table,
        candidate_constructor_rvas: plan.candidate_constructor_rvas,
        candidate_constructor_indices: plan.candidate_constructor_indices,
        has_derived_fullscreen_setter: runtime_compatibility.fullscreen_setter.is_some(),
        derived_fullscreen_setter_rva: runtime_compatibility.fullscreen_setter.unwrap_or(0),
        has_derived_fmod: fmod.is_some(),
        derived_fmod_vtable_rva: fmod.map_or(0, |f| f.vtable),
        derived_fmod_string_constructor_rva: fmod.map_or(0, |f| f.string_constructor),
        derived_fmod_count_method_rva: fmod.map_or(0, |f| f.count_method),
        derived_fmod_info_method_rva: fmod.map_or(0, |f| f.info_method),
        derived_fmod_current_method_rva: fmod.map_or(0, |f| f.current_method),
        derived_fmod_select_method_rva: fmod.map_or(0, |f| f.select_method),
        derived_fmod_layout_version: fmod.map_or(1, |f| f.layout_version),
        derived_fmod_has_input: fmod.is_some()
            && runtime_source
                .fmod
                .is_some_and(|src| src.input_methods[0] != 0),
        derived_fmod_input_methods: fmod.map_or([0; 4], |f| f.input_methods),
    };

    build_documents_data(&sidecar, metadata_json, &inputs)
}

fn load_candidate_metadata(root: &Path, candidate: &ElfImage) -> Result<String, String> {
    let metadata_path = root.join("roblox_payload.json");
    let metadata_json = read_small_regular_json(&metadata_path)?;
    let dir_name = root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let path_str = metadata_path.to_string_lossy();
    let _ = load_candidate_metadata_data(
        &metadata_json,
        &path_str,
        &dir_name,
        &candidate.build_id,
        &candidate.sha256,
        host_guest_abi(),
    )?;
    Ok(metadata_json)
}

fn derive_host_abi_profile_rs(
    reference_library: &Path,
    reference_profile: &Path,
    reference_compatibility_manifests: &[PathBuf],
    candidate_payload_directory: &Path,
    output_directory: &Path,
    disassembler: &mut dyn X86Disassembler,
) -> Result<(PathBuf, PathBuf), String> {
    if fs::create_dir_all(output_directory).is_err()
        || fs::read_dir(output_directory)
            .map(|mut it| it.next().is_some())
            .unwrap_or(true)
    {
        return Err("HostAbi derivation output directory must be empty".to_string());
    }

    let reference = ElfImage::open(reference_library)?;
    let candidate = ElfImage::open(&candidate_payload_directory.join("libroblox.so"))?;
    let sidecar_json = read_small_regular_json(reference_profile)?;
    let metadata_json = load_candidate_metadata(candidate_payload_directory, &candidate)?;
    let runtime_source =
        load_runtime_compatibility_anchors(reference_compatibility_manifests, &reference.build_id)?;

    let (profile_json, compat_json) = derive_documents(
        &reference,
        &candidate,
        &sidecar_json,
        &metadata_json,
        &runtime_source,
        disassembler,
    )?;

    let profile_path = output_directory.join("host_abi_profile.json");
    let compat_path = output_directory.join("compatibility.json");
    write_private_excl(&profile_path, &profile_json)?;
    write_private_excl(&compat_path, &compat_json)?;
    Ok((profile_path, compat_path))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_deriver_read_sidecar_identity_file(
    sidecar_path: MocktailRustStrSlice,
    on_identity: MocktailDeriverSidecarIdentityCallback,
    on_error: MocktailHostAbiErrorCallback,
    ctx: *mut c_void,
) -> c_int {
    let path = unsafe { slice_to_pathbuf(sidecar_path) };
    match read_host_abi_sidecar_identity_file(&path) {
        Ok((build_id, payload_id)) => {
            if let Some(cb) = on_identity {
                unsafe { cb(ctx, to_slice(&build_id), to_slice(&payload_id)) };
            }
            0
        }
        Err(err) => {
            if let Some(cb) = on_error {
                unsafe { cb(ctx, to_slice(&err)) };
            }
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_deriver_derive_host_abi_profile(
    options: *const MocktailRustDeriverOptionsView,
    open_disasm: MocktailDeriverOpenX86Fn,
    decode_x86: MocktailDeriverDecodeX86Fn,
    disasm_ctx: *mut c_void,
    on_result: MocktailDeriverResultCallback,
    on_error: MocktailHostAbiErrorCallback,
    ctx: *mut c_void,
) -> c_int {
    let emit_err = |msg: &str| {
        if let Some(cb) = on_error {
            unsafe { cb(ctx, to_slice(msg)) };
        }
    };
    if options.is_null() {
        emit_err("null HostAbi derivation options");
        return -1;
    }
    let opts = unsafe { &*options };
    let reference_library = unsafe { slice_to_pathbuf(opts.reference_library) };
    let reference_profile = unsafe { slice_to_pathbuf(opts.reference_profile) };
    let candidate_payload_directory = unsafe { slice_to_pathbuf(opts.candidate_payload_directory) };
    let output_directory = unsafe { slice_to_pathbuf(opts.output_directory) };

    let mut manifests = Vec::with_capacity(opts.reference_compatibility_manifests_len);
    if opts.reference_compatibility_manifests_len > 0 {
        if opts.reference_compatibility_manifests_ptr.is_null() {
            emit_err("invalid compatibility manifest list");
            return -1;
        }
        let manifest_slices = unsafe {
            std::slice::from_raw_parts(
                opts.reference_compatibility_manifests_ptr,
                opts.reference_compatibility_manifests_len,
            )
        };
        for &m in manifest_slices {
            manifests.push(unsafe { slice_to_pathbuf(m) });
        }
    }

    let mut disassembler = CallbackX86Disassembler {
        ctx: disasm_ctx,
        open_cb: open_disasm,
        decode_cb: decode_x86,
    };

    match derive_host_abi_profile_rs(
        &reference_library,
        &reference_profile,
        &manifests,
        &candidate_payload_directory,
        &output_directory,
        &mut disassembler,
    ) {
        Ok((profile_path, compat_path)) => {
            if let Some(cb) = on_result {
                let p_str = profile_path.to_string_lossy();
                let c_str = compat_path.to_string_lossy();
                unsafe { cb(ctx, to_slice(&p_str), to_slice(&c_str)) };
            }
            0
        }
        Err(err) => {
            emit_err(&err);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DERIVER_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn encode_sleb(mut value: i64, out: &mut Vec<u8>) {
        loop {
            let byte = (value as u8) & 0x7f;
            value >>= 7;
            let done = (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0);
            out.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
    }

    #[test]
    fn aps2_relocation_stream_decodes_grouped_and_signed_deltas() {
        let mut encoded = b"APS2".to_vec();
        // count = 2, first_offset = 0x1000
        encode_sleb(2, &mut encoded);
        encode_sleb(0x1000, &mut encoded);
        // 1 group of 2 relocations: GROUPED_BY_INFO | GROUPED_BY_OFFSET_DELTA | GROUP_HAS_ADDEND
        encode_sleb(2, &mut encoded);
        encode_sleb(K_GROUPED_BY_INFO | K_GROUPED_BY_OFFSET_DELTA | K_GROUP_HAS_ADDEND, &mut encoded);
        encode_sleb(8, &mut encoded); // offset delta
        encode_sleb(K_RELATIVE_RELOCATION as i64, &mut encoded); // info
        encode_sleb(0x2000, &mut encoded); // addend delta 1
        encode_sleb(0x10, &mut encoded); // addend delta 2 -> 0x2010

        let relocs = decode_aps2(&encoded).unwrap();
        assert_eq!(
            relocs,
            vec![
                Relocation {
                    offset: 0x1008,
                    info: 8,
                    addend: 0x2000,
                },
                Relocation {
                    offset: 0x1010,
                    info: 8,
                    addend: 0x2010,
                },
            ]
        );
        assert!(decode_aps2(b"BAD!").unwrap_err().contains("APS2"));
    }

    struct MockDisasm {
        entries: BTreeMap<(u64, usize), Vec<Instruction>>,
    }

    impl X86Disassembler for MockDisasm {
        fn open(&mut self) -> Result<(), String> {
            Ok(())
        }

        fn decode_raw(&self, rva: u64, _code: &[u8], count: usize) -> Result<Vec<Instruction>, String> {
            self.entries
                .get(&(rva, count))
                .cloned()
                .ok_or_else(|| "cannot decode normalized instruction signature".to_string())
        }
    }

    #[test]
    fn signature_mask_and_singleton_checks_work_without_capstone() {
        let mut mask = vec![true; 7];
        // simulate rip-relative disp at [3..7]
        for b in &mut mask[3..7] {
            *b = false;
        }
        let code = [0x48, 0x8d, 0x05, 0x11, 0x22, 0x33, 0x44];
        let text = [0x90, 0x48, 0x8d, 0x05, 0x99, 0x88, 0x77, 0x66, 0x90];
        let pos = find_subslice(&text, &code[..3]).unwrap();
        assert_eq!(pos, 1);

        let reg = |name: &str, size: u8| Operand {
            kind: OperandKind::Reg,
            reg_name: name.to_string(),
            seg_name: String::new(),
            base_name: String::new(),
            index_name: String::new(),
            scale: 0,
            value: 0,
            size,
            rip_relative: false,
        };
        let rip_mem = |disp: i64| Operand {
            kind: OperandKind::Mem,
            reg_name: String::new(),
            seg_name: String::new(),
            base_name: "rip".to_string(),
            index_name: String::new(),
            scale: 1,
            value: disp,
            size: 8,
            rip_relative: true,
        };
        let singleton_insns = vec![
            Instruction {
                address: 0x1000,
                size: 7,
                mnemonic: "lea".to_string(),
                operands: vec![reg("rax", 8), rip_mem(0x3009)],
                imm_offset: 0,
                imm_size: 0,
                disp_offset: 3,
                disp_size: 4,
                control_flow: false,
                returns: false,
            },
            Instruction {
                address: 0x1007,
                size: 7,
                mnemonic: "xchg".to_string(),
                operands: vec![rip_mem(0x2ffa), reg("rax", 8)],
                imm_offset: 0,
                imm_size: 0,
                disp_offset: 3,
                disp_size: 4,
                control_flow: false,
                returns: false,
            },
            Instruction {
                address: 0x100e,
                size: 7,
                mnemonic: "mov".to_string(),
                operands: vec![rip_mem(0x2ffb), reg("rax", 8)],
                imm_offset: 0,
                imm_size: 0,
                disp_offset: 3,
                disp_size: 4,
                control_flow: false,
                returns: false,
            },
        ];
        // slot = 0x100e + 0x2ffa = 0x4008, head = 0x4010, next = 0x1015 + 0x2ffb = 0x4010
        assert!(has_singleton_links(&singleton_insns));

        let mut mock = MockDisasm {
            entries: BTreeMap::new(),
        };
        mock.entries.insert((0x1000, 3), singleton_insns);
        let decoded = mock.decode_raw(0x1000, &[], 3).unwrap();
        assert_eq!(decoded.len(), 3);
        let uniq = DERIVER_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let _ = uniq;
    }

    #[test]
    fn sidecar_identity_file_rejects_missing_file() {
        let uniq = DERIVER_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let missing = std::env::temp_dir().join(format!("mocktail-missing-sidecar-{uniq}.json"));
        let err = read_host_abi_sidecar_identity_file(&missing).unwrap_err();
        assert!(err.contains("cannot open JSON input"));
    }
}
