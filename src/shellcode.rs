use byteorder::{BigEndian, ByteOrder};

const PRX_LOADER: &[u8] = include_bytes!("../prx_loader_fixed.bin");

pub fn build_jump(address: u32) -> [u32; 4] {
	let upper = address >> 16;
	let lower = address & 0xFFFF;
	[
		0x3D600000 | upper, // lis r11, upper
		0x616B0000 | lower, // ori r11, r11, lower
		0x7D6903A6,         // mtctr r11
		0x4E800420,         // bctr
	]
}

pub fn build(sprx_path: &str, entrypoint_instructions: &[u32; 4], entrypoint_address: u32, payload_address: u32) -> (Vec<u8>, [u32; 4]) {
	let sprx_path_bytes = sprx_path.as_bytes();
	let payload_size = PRX_LOADER.len() + entrypoint_instructions.len() * 4;
	let mut buffer = vec![0u8; payload_size + sprx_path_bytes.len() + 1];

	// Copy base shellcode
	buffer[..PRX_LOADER.len()].copy_from_slice(PRX_LOADER);

	// Copy SPRX path (null terminator already zero from vec initialization)
	buffer[payload_size..payload_size + sprx_path_bytes.len()].copy_from_slice(sprx_path_bytes);

	// Write entrypoint instructions into the tail of the shellcode
	let entrypoint_offset = PRX_LOADER.len() - entrypoint_instructions.len() * 4;
	for (i, &insn) in entrypoint_instructions.iter().enumerate() {
		let off = entrypoint_offset + i * 4;
		BigEndian::write_u32(&mut buffer[off..off + 4], insn);
	}

	// Write jump back to original code (after the 4 relocated instructions)
	let jump = build_jump(entrypoint_address + (entrypoint_instructions.len() as u32) * 4);
	let jump_offset = entrypoint_offset + entrypoint_instructions.len() * 4;
	for (i, &insn) in jump.iter().enumerate() {
		let off = jump_offset + i * 4;
		BigEndian::write_u32(&mut buffer[off..off + 4], insn);
	}

	// Find and patch SPRX path address into the lis/ori pair that loads PRX_NAME_STRING (0x12345678)
	let sprx_path_address = payload_address + payload_size as u32;
	let upper = (sprx_path_address >> 16) as u16;
	let lower = (sprx_path_address & 0xFFFF) as u16;

	// Search for lis r3, 0x1234 (0x3C601234)
	let lis_target = 0x3C601234u32;
	let pos = (0..PRX_LOADER.len() - 3)
		.step_by(4)
		.find(|&i| BigEndian::read_u32(&buffer[i..i + 4]) & 0xFFFF0000 == lis_target & 0xFFFF0000
			&& BigEndian::read_u16(&buffer[i + 2..i + 4]) == 0x1234)
		.expect("Could not find PRX_NAME_STRING lis instruction in prx_loader");

	BigEndian::write_u16(&mut buffer[pos + 2..pos + 4], upper);
	BigEndian::write_u16(&mut buffer[pos + 4 + 2..pos + 4 + 4], lower);

	let new_entrypoint = build_jump(payload_address);
	(buffer, new_entrypoint)
}
