mod elf;
mod shellcode;

use anyhow::Result;
use std::env;
use std::fs;

fn main() -> Result<()> {
	let args: Vec<String> = env::args().collect();
	if args.len() < 4 || args.len() > 5 {
		eprintln!("Usage: sprx_patcher <input.elf> </path/to/sprx> <output.elf> [patch_address]");
		eprintln!("Example: sprx_patcher input.elf /dev_hdd0/tmp/plugin.sprx output.elf");
		eprintln!("Example: sprx_patcher input.elf /dev_hdd0/tmp/plugin.sprx output.elf 0x10000");
		std::process::exit(1);
	}

	let input = &args[1];
	let sprx = &args[2];
	let output = &args[3];

	let patch_address = if let Some(addr_str) = args.get(4) {
		let addr_str = addr_str.strip_prefix("0x").or(addr_str.strip_prefix("0X")).unwrap_or(addr_str);
		Some(u32::from_str_radix(addr_str, 16)?)
	} else {
		None
	};

	println!("Patching ELF to load SPRX at {sprx}");

	let input_data = fs::read(input)?;
	let mut elf = elf::ElfFile::parse(&input_data, patch_address)?;
	elf.sprx_path = sprx.clone();

	let (output_data, ppu_hash) = elf.write()?;
	fs::write(output, output_data)?;

	println!("Wrote patched ELF to {output}");

	let ppu_hash_hex: String = ppu_hash.iter().map(|b| format!("{b:02x}")).collect();
	println!("PPU hash: {ppu_hash_hex}");

	Ok(())
}
