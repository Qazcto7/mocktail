pub(crate) const ELFCLASS64: u8 = 2;
pub(crate) const ELFDATA2LSB: u8 = 1;
pub(crate) const EV_CURRENT: u8 = 1;
pub(crate) const ET_DYN: u16 = 3;

pub(crate) const PT_LOAD: u32 = 1;
pub(crate) const PT_GNU_RELRO: u32 = 0x6474_e552;
pub(crate) const PF_X: u32 = 1;
pub(crate) const PF_W: u32 = 2;
pub(crate) const PF_R: u32 = 4;

pub(crate) const SHT_PROGBITS: u32 = 1;
pub(crate) const SHT_STRTAB: u32 = 3;
pub(crate) const SHT_NOTE: u32 = 7;
pub(crate) const SHT_NOBITS: u32 = 8;
pub(crate) const SHT_DYNSYM: u32 = 11;
pub(crate) const SHT_INIT_ARRAY: u32 = 14;
pub(crate) const SHT_ANDROID_RELA: u32 = 0x6000_0002;

pub(crate) const SHF_WRITE: u64 = 1;
pub(crate) const SHF_ALLOC: u64 = 2;
pub(crate) const SHF_EXECINSTR: u64 = 4;

pub(crate) const SHN_UNDEF: u16 = 0;
pub(crate) const SHN_XINDEX: u16 = 0xffff;
pub(crate) const PN_XNUM: u16 = 0xffff;

pub(crate) const STB_GLOBAL: u8 = 1;
pub(crate) const STB_WEAK: u8 = 2;
pub(crate) const STT_FUNC: u8 = 2;

pub(crate) fn read_u8(bytes: &[u8], off: usize) -> Option<u8> {
    bytes.get(off).copied()
}

pub(crate) fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let slice = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

pub(crate) fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(crate) fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let slice = bytes.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub(crate) fn cstr_slice_at(table: &[u8], off: usize) -> Option<&[u8]> {
    let tail = table.get(off..)?;
    let nul = tail.iter().position(|&b| b == 0)?;
    Some(&tail[..nul])
}

pub(crate) fn checked_range(offset: u64, size: u64, limit: u64) -> bool {
    offset <= limit && size <= limit - offset
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Elf64Header {
    pub ei_class: u8,
    pub ei_data: u8,
    pub ei_version: u8,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_phoff: usize,
    pub e_shoff: usize,
    pub e_phentsize: usize,
    pub raw_phnum: u16,
    pub e_shentsize: usize,
    pub raw_shnum: u16,
    pub raw_shstrndx: u16,
}

pub(crate) fn parse_elf64_header(bytes: &[u8]) -> Option<Elf64Header> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return None;
    }
    let e_phoff = usize::try_from(read_u64_le(bytes, 32)?).ok()?;
    let e_shoff = usize::try_from(read_u64_le(bytes, 40)?).ok()?;
    Some(Elf64Header {
        ei_class: bytes[4],
        ei_data: bytes[5],
        ei_version: bytes[6],
        e_type: read_u16_le(bytes, 16)?,
        e_machine: read_u16_le(bytes, 18)?,
        e_version: read_u32_le(bytes, 20)?,
        e_phoff,
        e_shoff,
        e_phentsize: read_u16_le(bytes, 54)? as usize,
        raw_phnum: read_u16_le(bytes, 56)?,
        e_shentsize: read_u16_le(bytes, 58)? as usize,
        raw_shnum: read_u16_le(bytes, 60)?,
        raw_shstrndx: read_u16_le(bytes, 62)?,
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
}

impl Elf64Phdr {
    pub(crate) fn contains_memory(&self, rva: u64, size: u64) -> bool {
        rva >= self.p_vaddr && checked_range(rva - self.p_vaddr, size, self.p_memsz)
    }

    pub(crate) fn contains_file(&self, rva: u64, size: u64) -> bool {
        rva >= self.p_vaddr && checked_range(rva - self.p_vaddr, size, self.p_filesz)
    }
}

pub(crate) fn parse_elf64_phdrs(bytes: &[u8], hdr: &Elf64Header) -> Result<Vec<Elf64Phdr>, ()> {
    if hdr.raw_phnum == 0 {
        return Ok(Vec::new());
    }
    if hdr.e_phoff == 0 || hdr.e_phentsize < 56 {
        return Err(());
    }
    let phnum = if hdr.raw_phnum == PN_XNUM {
        if hdr.e_shoff == 0 || hdr.e_shentsize < 64 || hdr.e_shoff + 48 > bytes.len() {
            return Err(());
        }
        usize::try_from(read_u32_le(bytes, hdr.e_shoff + 44).ok_or(())?).map_err(|_| ())?
    } else {
        hdr.raw_phnum as usize
    };
    let end = phnum
        .checked_mul(hdr.e_phentsize)
        .and_then(|sz| hdr.e_phoff.checked_add(sz))
        .ok_or(())?;
    if end > bytes.len() {
        return Err(());
    }
    let mut out = Vec::with_capacity(phnum);
    for idx in 0..phnum {
        let base = hdr.e_phoff + idx * hdr.e_phentsize;
        out.push(Elf64Phdr {
            p_type: read_u32_le(bytes, base).ok_or(())?,
            p_flags: read_u32_le(bytes, base + 4).ok_or(())?,
            p_offset: read_u64_le(bytes, base + 8).ok_or(())?,
            p_vaddr: read_u64_le(bytes, base + 16).ok_or(())?,
            p_filesz: read_u64_le(bytes, base + 32).ok_or(())?,
            p_memsz: read_u64_le(bytes, base + 40).ok_or(())?,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub(crate) struct Elf64Shdr {
    pub index: usize,
    pub sh_name: u32,
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_entsize: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShdrError {
    TableInvalid,
    SectionOutOfBounds,
}

pub(crate) fn parse_elf64_shdrs(
    bytes: &[u8],
    hdr: &Elf64Header,
    resolve_names: bool,
) -> Result<Vec<Elf64Shdr>, ShdrError> {
    if !resolve_names && hdr.e_shoff == 0 && hdr.raw_shnum == 0 {
        return Ok(Vec::new());
    }
    if hdr.e_shoff == 0
        || hdr.e_shentsize < 64
        || hdr.e_shoff
            .checked_add(hdr.e_shentsize)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(ShdrError::TableInvalid);
    }
    let shnum: usize = if hdr.raw_shnum == 0 {
        usize::try_from(read_u64_le(bytes, hdr.e_shoff + 32).unwrap_or(0))
            .map_err(|_| ShdrError::TableInvalid)?
    } else {
        hdr.raw_shnum as usize
    };
    let shstrndx: usize = if hdr.raw_shstrndx == SHN_XINDEX {
        read_u32_le(bytes, hdr.e_shoff + 40).unwrap_or(u32::MAX) as usize
    } else {
        hdr.raw_shstrndx as usize
    };
    let table_end = shnum
        .checked_mul(hdr.e_shentsize)
        .and_then(|sz| hdr.e_shoff.checked_add(sz))
        .ok_or(ShdrError::TableInvalid)?;
    if shnum == 0 || table_end > bytes.len() || (resolve_names && shstrndx >= shnum) {
        return Err(ShdrError::TableInvalid);
    }

    let file_limit = bytes.len() as u64;
    let mut out = Vec::with_capacity(shnum);
    for idx in 0..shnum {
        let base = hdr.e_shoff + idx * hdr.e_shentsize;
        let sh_name = read_u32_le(bytes, base).ok_or(ShdrError::SectionOutOfBounds)?;
        let sh_type = read_u32_le(bytes, base + 4).ok_or(ShdrError::SectionOutOfBounds)?;
        let sh_flags = read_u64_le(bytes, base + 8).ok_or(ShdrError::SectionOutOfBounds)?;
        let sh_addr = read_u64_le(bytes, base + 16).ok_or(ShdrError::SectionOutOfBounds)?;
        let sh_offset = read_u64_le(bytes, base + 24).ok_or(ShdrError::SectionOutOfBounds)?;
        let sh_size = read_u64_le(bytes, base + 32).ok_or(ShdrError::SectionOutOfBounds)?;
        let sh_link = read_u32_le(bytes, base + 40).ok_or(ShdrError::SectionOutOfBounds)?;
        let sh_entsize = read_u64_le(bytes, base + 56).ok_or(ShdrError::SectionOutOfBounds)?;
        if sh_type != SHT_NOBITS && !checked_range(sh_offset, sh_size, file_limit) {
            return Err(ShdrError::SectionOutOfBounds);
        }
        out.push(Elf64Shdr {
            index: idx,
            sh_name,
            name: String::new(),
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_entsize,
        });
    }

    if resolve_names {
        let shstr = &out[shstrndx];
        if shstr.sh_type == SHT_NOBITS {
            return Err(ShdrError::SectionOutOfBounds);
        }
        let shstr_off = usize::try_from(shstr.sh_offset).map_err(|_| ShdrError::SectionOutOfBounds)?;
        let shstr_sz = usize::try_from(shstr.sh_size).map_err(|_| ShdrError::SectionOutOfBounds)?;
        let shstrtab = bytes
            .get(shstr_off..shstr_off + shstr_sz)
            .ok_or(ShdrError::SectionOutOfBounds)?;
        for sec in &mut out {
            let name_bytes = cstr_slice_at(shstrtab, sec.sh_name as usize)
                .ok_or(ShdrError::SectionOutOfBounds)?;
            sec.name = std::str::from_utf8(name_bytes)
                .map_err(|_| ShdrError::SectionOutOfBounds)?
                .to_string();
        }
    }
    Ok(out)
}

pub(crate) fn section_bytes<'a>(bytes: &'a [u8], sec: &Elf64Shdr) -> Option<&'a [u8]> {
    if sec.sh_type == SHT_NOBITS {
        return None;
    }
    let off = usize::try_from(sec.sh_offset).ok()?;
    let sz = usize::try_from(sec.sh_size).ok()?;
    bytes.get(off..off.checked_add(sz)?)
}
