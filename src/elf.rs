use anyhow::{Result, bail};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use crate::shellcode;

// --- ELF Header ---

pub struct ElfHeader {
	pub entry: u64,
	pub program_header_offset: u64,
	pub section_header_offset: u64,
	pub flags: u32,
	pub program_header_count: u16,
	pub section_header_count: u16,
	pub section_header_string_index: u16,
}

impl ElfHeader {
	fn parse<R: Read>(r: &mut R) -> Result<Self> {
		let mut magic = [0u8; 4];
		r.read_exact(&mut magic)?;
		if magic != [0x7F, b'E', b'L', b'F'] {
			bail!("Invalid ELF magic");
		}

		let ei_class = r.read_u8()?;
		if ei_class != 2 {
			bail!("Invalid ELF class (got {ei_class}, expected 2)");
		}

		let ei_data = r.read_u8()?;
		if ei_data != 2 {
			bail!("Invalid ELF data encoding (got {ei_data}, expected 2)");
		}

		let ver = r.read_u8()?;
		if ver != 1 {
			bail!("Invalid ELF version (got {ver}, expected 1)");
		}

		let os_abi = r.read_u8()?;
		if os_abi != 0x66 {
			bail!("Invalid ELF OS ABI (got {os_abi}, expected 0x66)");
		}

		let abi_version = r.read_u8()?;
		if abi_version != 0 {
			bail!("Invalid ELF ABI version (got {abi_version}, expected 0)");
		}

		let mut pad = [0u8; 7];
		r.read_exact(&mut pad)?;
		if pad.iter().any(|&b| b != 0) {
			bail!("Invalid ELF padding");
		}

		let ty = r.read_u16::<BigEndian>()?;
		if ty != 2 {
			bail!("Invalid ELF type (got {ty}, expected 2)");
		}

		let machine = r.read_u16::<BigEndian>()?;
		if machine != 0x15 {
			bail!("Invalid ELF machine (got {machine}, expected 0x15)");
		}

		let version = r.read_u32::<BigEndian>()?;
		if version != 1 {
			bail!("Invalid ELF version (got {version}, expected 1)");
		}

		let entry = r.read_u64::<BigEndian>()?;
		let program_header_offset = r.read_u64::<BigEndian>()?;
		let section_header_offset = r.read_u64::<BigEndian>()?;
		let flags = r.read_u32::<BigEndian>()?;

		let size = r.read_u16::<BigEndian>()?;
		if size != 0x40 {
			bail!("Invalid ELF header size (got {size}, expected 0x40)");
		}

		let ph_ent_size = r.read_u16::<BigEndian>()?;
		if ph_ent_size != 0x38 {
			bail!("Invalid ELF program header entry size (got {ph_ent_size}, expected 0x38)");
		}
		let program_header_count = r.read_u16::<BigEndian>()?;

		let sh_ent_size = r.read_u16::<BigEndian>()?;
		if sh_ent_size != 0x40 {
			bail!("Invalid ELF section header entry size (got {sh_ent_size}, expected 0x40)");
		}
		let section_header_count = r.read_u16::<BigEndian>()?;
		let section_header_string_index = r.read_u16::<BigEndian>()?;

		Ok(Self {
			entry,
			program_header_offset,
			section_header_offset,
			flags,
			program_header_count,
			section_header_count,
			section_header_string_index,
		})
	}

	fn write<W: Write>(&self, w: &mut W) -> Result<()> {
		w.write_all(&[0x7F, b'E', b'L', b'F'])?;
		w.write_u8(2)?; // 64-bit
		w.write_u8(2)?; // big endian
		w.write_u8(1)?; // version
		w.write_u8(0x66)?; // PS3 ABI
		w.write_u8(0)?; // ABI version
		w.write_all(&[0u8; 7])?; // padding
		w.write_u16::<BigEndian>(2)?; // executable
		w.write_u16::<BigEndian>(0x15)?; // PPC64
		w.write_u32::<BigEndian>(1)?; // version
		w.write_u64::<BigEndian>(self.entry)?;
		w.write_u64::<BigEndian>(self.program_header_offset)?;
		w.write_u64::<BigEndian>(self.section_header_offset)?;
		w.write_u32::<BigEndian>(self.flags)?;
		w.write_u16::<BigEndian>(0x40)?; // header size
		w.write_u16::<BigEndian>(0x38)?; // program header entry size
		w.write_u16::<BigEndian>(self.program_header_count)?;
		w.write_u16::<BigEndian>(0x40)?; // section header entry size
		w.write_u16::<BigEndian>(self.section_header_count)?;
		w.write_u16::<BigEndian>(self.section_header_string_index)?;
		Ok(())
	}
}

// --- Program Header ---

pub const PT_LOAD: u32 = 1;

pub struct ElfProgramHeader {
	pub ty: u32,
	pub flags: u32,
	pub offset: u64,
	pub virtual_address: u64,
	pub physical_address: u64,
	pub file_size: u64,
	pub memory_size: u64,
	pub alignment: u64,
}

impl ElfProgramHeader {
	fn parse<R: Read>(r: &mut R) -> Result<Self> {
		Ok(Self {
			ty: r.read_u32::<BigEndian>()?,
			flags: r.read_u32::<BigEndian>()?,
			offset: r.read_u64::<BigEndian>()?,
			virtual_address: r.read_u64::<BigEndian>()?,
			physical_address: r.read_u64::<BigEndian>()?,
			file_size: r.read_u64::<BigEndian>()?,
			memory_size: r.read_u64::<BigEndian>()?,
			alignment: r.read_u64::<BigEndian>()?,
		})
	}

	fn write<W: Write>(&self, w: &mut W) -> Result<()> {
		w.write_u32::<BigEndian>(self.ty)?;
		w.write_u32::<BigEndian>(self.flags)?;
		w.write_u64::<BigEndian>(self.offset)?;
		w.write_u64::<BigEndian>(self.virtual_address)?;
		w.write_u64::<BigEndian>(self.physical_address)?;
		w.write_u64::<BigEndian>(self.file_size)?;
		w.write_u64::<BigEndian>(self.memory_size)?;
		w.write_u64::<BigEndian>(self.alignment)?;
		Ok(())
	}
}

// --- Section Header ---

pub const SHT_PROGBITS: u32 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXEC_INSTR: u64 = 4;

pub struct ElfSectionHeader {
	pub name_offset: u32,
	pub ty: u32,
	pub flags: u64,
	pub virtual_address: u64,
	pub physical_address: u64,
	pub file_size: u64,
	pub link: u32,
	pub info: u32,
	pub alignment: u64,
	pub entry_size: u64,
	pub data: Vec<u8>,
}

impl ElfSectionHeader {
	fn parse<R: Read>(r: &mut R) -> Result<Self> {
		Ok(Self {
			name_offset: r.read_u32::<BigEndian>()?,
			ty: r.read_u32::<BigEndian>()?,
			flags: r.read_u64::<BigEndian>()?,
			virtual_address: r.read_u64::<BigEndian>()?,
			physical_address: r.read_u64::<BigEndian>()?,
			file_size: r.read_u64::<BigEndian>()?,
			link: r.read_u32::<BigEndian>()?,
			info: r.read_u32::<BigEndian>()?,
			alignment: r.read_u64::<BigEndian>()?,
			entry_size: r.read_u64::<BigEndian>()?,
			data: Vec::new(),
		})
	}

	fn write<W: Write>(&self, w: &mut W) -> Result<()> {
		w.write_u32::<BigEndian>(self.name_offset)?;
		w.write_u32::<BigEndian>(self.ty)?;
		w.write_u64::<BigEndian>(self.flags)?;
		w.write_u64::<BigEndian>(self.virtual_address)?;
		w.write_u64::<BigEndian>(self.physical_address)?;
		w.write_u64::<BigEndian>(self.file_size)?;
		w.write_u32::<BigEndian>(self.link)?;
		w.write_u32::<BigEndian>(self.info)?;
		w.write_u64::<BigEndian>(self.alignment)?;
		w.write_u64::<BigEndian>(self.entry_size)?;
		Ok(())
	}
}

// --- ELF File ---

pub struct ElfFile {
	pub header: ElfHeader,
	pub program_headers: Vec<ElfProgramHeader>,
	pub section_headers: Vec<ElfSectionHeader>,
	pub sprx_path: String,

	entrypoint_offset: u32,
	entrypoint_address: u32,
	entrypoint_instructions: [u32; 4],
	#[allow(dead_code)]
	section_header_lookup: HashMap<String, usize>,
}

impl ElfFile {
	pub fn parse(data: &[u8], patch_address: Option<u32>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let header = ElfHeader::parse(&mut cursor)?;

		// Read program headers
		cursor.seek(SeekFrom::Start(header.program_header_offset))?;
		let mut program_headers = Vec::with_capacity(header.program_header_count as usize);
		for _ in 0..header.program_header_count {
			program_headers.push(ElfProgramHeader::parse(&mut cursor)?);
		}

		// Read section headers
		cursor.seek(SeekFrom::Start(header.section_header_offset))?;
		let mut section_headers = Vec::with_capacity(header.section_header_count as usize);
		for _ in 0..header.section_header_count {
			section_headers.push(ElfSectionHeader::parse(&mut cursor)?);
		}

		// Read section data
		let data_len = data.len() as u64;
		for sh in &mut section_headers {
			if sh.file_size == 0 || sh.physical_address >= data_len {
				continue;
			}
			let available = (data_len - sh.physical_address).min(sh.file_size) as usize;
			cursor.seek(SeekFrom::Start(sh.physical_address))?;
			let mut buf = vec![0u8; available];
			cursor.read_exact(&mut buf)?;
			sh.data = buf;
		}

		// Build section name lookup
		let mut section_header_lookup = HashMap::new();
		let strtab_data = section_headers[header.section_header_string_index as usize].data.clone();
		for (i, sh) in section_headers.iter().enumerate() {
			let name_start = sh.name_offset as usize;
			let name_end = strtab_data[name_start..].iter().position(|&b| b == 0).map(|p| name_start + p).unwrap_or(strtab_data.len());
			let name = String::from_utf8_lossy(&strtab_data[name_start..name_end]).to_string();
			section_header_lookup.insert(name, i);
		}

		// Find patch address (either from TOC entry point or user-specified)
		let entrypoint_address = if let Some(addr) = patch_address {
			println!("Using custom patch address: 0x{addr:X}");
			addr
		} else {
			let toc_offset = virtual_address_to_offset(&section_headers, header.entry)?;
			cursor.seek(SeekFrom::Start(toc_offset as u64))?;
			println!("TOC entry offset: 0x{toc_offset:X}");
			let addr = cursor.read_u32::<BigEndian>()?;
			println!("Entrypoint: 0x{addr:X}");
			addr
		};

		let entrypoint_offset = virtual_address_to_offset(&section_headers, entrypoint_address as u64)?;
		println!("Patch offset: 0x{entrypoint_offset:X}");

		cursor.seek(SeekFrom::Start(entrypoint_offset as u64))?;
		let mut entrypoint_instructions = [0u32; 4];
		for insn in &mut entrypoint_instructions {
			*insn = cursor.read_u32::<BigEndian>()?;
		}
		println!("Entrypoint instructions: {}", entrypoint_instructions.iter().map(|i| format!("0x{i:X}")).collect::<Vec<_>>().join(", "));

		Ok(Self {
			header,
			program_headers,
			section_headers,
			sprx_path: "/dev_hdd0/tmp/plugin.sprx".to_string(),
			entrypoint_offset,
			entrypoint_address,
			entrypoint_instructions,
			section_header_lookup,
		})
	}

	pub fn write(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
		let mut buf = Vec::new();
		let mut cursor = Cursor::new(&mut buf);

		// Write header (placeholder, will rewrite later)
		self.header.write(&mut cursor)?;

		// Zero-fill up to end of original program headers
		{
			let ph_end = self.header.program_header_offset + (self.header.program_header_count as u64) * 0x38;
			let current = cursor.position();
			if ph_end > current {
				let zeroes = vec![0u8; (ph_end - current) as usize];
				cursor.write_all(&zeroes)?;
			}
		}

		// Write sections
		for sh in &self.section_headers {
			cursor.seek(SeekFrom::Start(sh.physical_address))?;
			cursor.write_all(&sh.data)?;
		}

		// Seek to end, align to 0x1000
		cursor.seek(SeekFrom::End(0))?;
		seek_to_alignment(&mut cursor, 0x1000)?;

		let custom_section_offset = cursor.position();
		let custom_section_va = 0x13370000u64;
		println!("Custom section VA: 0x{custom_section_va:X}, file offset: 0x{custom_section_offset:X}");

		let (shellcode_data, new_entrypoint) = shellcode::build(&self.sprx_path, &self.entrypoint_instructions, self.entrypoint_address, custom_section_va as u32);
		cursor.write_all(&shellcode_data)?;
		seek_to_alignment(&mut cursor, 0x1000)?;

		// Add custom section header
		self.section_headers.push(ElfSectionHeader {
			name_offset: 0,
			ty: SHT_PROGBITS,
			flags: SHF_ALLOC | SHF_EXEC_INSTR,
			virtual_address: custom_section_va,
			physical_address: custom_section_offset,
			file_size: shellcode_data.len() as u64,
			link: 0,
			info: 0,
			alignment: 1,
			entry_size: 0,
			data: Vec::new(),
		});

		// Add custom program header
		self.program_headers.push(ElfProgramHeader {
			ty: PT_LOAD,
			flags: 0x5,
			offset: custom_section_offset,
			virtual_address: custom_section_va,
			physical_address: custom_section_offset,
			file_size: shellcode_data.len() as u64,
			memory_size: shellcode_data.len() as u64,
			alignment: 0x1000,
		});

		// Write section headers
		let section_header_offset = cursor.position();
		for sh in &self.section_headers {
			sh.write(&mut cursor)?;
		}
		self.header.section_header_offset = section_header_offset;
		self.header.section_header_count = self.section_headers.len() as u16;

		// Write program headers
		let program_header_offset = cursor.position();
		for ph in &self.program_headers {
			ph.write(&mut cursor)?;
		}
		self.header.program_header_offset = program_header_offset;
		self.header.program_header_count = self.program_headers.len() as u16;

		// Patch entrypoint with jump to shellcode
		cursor.seek(SeekFrom::Start(self.entrypoint_offset as u64))?;
		for insn in &new_entrypoint {
			cursor.write_u32::<BigEndian>(*insn)?;
		}

		// Rewrite header
		cursor.seek(SeekFrom::Start(0))?;
		self.header.write(&mut cursor)?;

		// Calculate PPU hash (SHA1 over loadable segments)
		let mut hasher = Sha1::new();
		for ph in &self.program_headers {
			let mut type_bytes = [0u8; 4];
			let mut flags_bytes = [0u8; 4];
			BigEndian::write_u32(&mut type_bytes, ph.ty);
			BigEndian::write_u32(&mut flags_bytes, ph.flags);
			hasher.update(type_bytes);
			hasher.update(flags_bytes);

			if ph.ty == PT_LOAD && ph.memory_size != 0 {
				let mut vaddr_bytes = [0u8; 8];
				let mut memsz_bytes = [0u8; 8];
				BigEndian::write_u64(&mut vaddr_bytes, ph.virtual_address);
				BigEndian::write_u64(&mut memsz_bytes, ph.memory_size);
				hasher.update(vaddr_bytes);
				hasher.update(memsz_bytes);

				let start = ph.offset as usize;
				let end = start + ph.file_size as usize;
				hasher.update(&buf[start..end]);
			}
		}

		let ppu_hash = hasher.finalize().to_vec();

		Ok((buf, ppu_hash))
	}
}

fn virtual_address_to_offset(sections: &[ElfSectionHeader], vaddr: u64) -> Result<u32> {
	for s in sections {
		if s.virtual_address <= vaddr && vaddr < s.virtual_address + s.file_size {
			let offset = vaddr - s.virtual_address;
			return Ok((s.physical_address + offset) as u32);
		}
	}
	bail!("Virtual address 0x{vaddr:X} not found in any section");
}

fn seek_to_alignment(cursor: &mut Cursor<&mut Vec<u8>>, alignment: u64) -> Result<()> {
	let current = cursor.position();
	let aligned = (current + alignment - 1) & !(alignment - 1);
	if aligned > current {
		let zeroes = vec![0u8; (aligned - current) as usize];
		cursor.write_all(&zeroes)?;
	}
	Ok(())
}
