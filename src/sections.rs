/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use std::fs::File;
use std::io::Write;
use goblin::container::{Container};
use goblin::elf::{Elf, SectionHeader};
use goblin::elf::section_header::sht_to_str;
use goblin::elf32::section_header::SHT_STRTAB;
use goblin::strtab::Strtab;
use anyhow::{anyhow, Context, Result};

use crate::{PairTable, print_header, SizePrint};
use crate::args::SectionArgs;
use crate::eh::{eh_frame, eh_frame_hdr};
use crate::print::{BinSize, hexdump};

pub fn all_sections(elf: &Elf) {
    let container = elf.header.container().unwrap_or(Container::Big);
    let sp = SizePrint::new(container);

    print_header(
        &format!("SECTIONS ({})", elf.section_headers.len())
    );

    let colw = match container {
        Container::Big => 19,
        Container::Little => 11,
    };
    println!(
        "\x1b[97m{:2} │ {:20} │ {:12} │ {:colw$} │ {:22} │\x1b[0m",
        "No", "Name", "Type", "Virt. addr.", "Size",
    );
    println!(
        "\x1b[97m{0:─<3}┼{0:─<22}┼{0:─<14}┼{0:─<w$}┼{0:─<24}┤\x1b[0m",
        "", w = colw + 2,
    );

    for (i, sh) in elf.section_headers.iter().enumerate() {
        let (type_c, type_n) = section_type(sh.sh_type);
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap(); // TODO
        print!("{i:2} \x1b[97m│\x1b[0m {name:20} \x1b[97m│\x1b[0m ");
        print!("\x1b[{type_c}{type_n:12} \x1b[97m│\x1b[0m ");

        if sh.sh_addr == 0 {
            print!("\x1b[90m");
        }
        print!("{} \x1b[97m│\x1b[0m ", sp.hex(sh.sh_addr));

        if sh.sh_size == 0 {
            print!("\x1b[90m");
        }
        if sh.sh_size < u32::MAX as u64 {
            print!("{}", SizePrint::new(Container::Little).hex(sh.sh_size));
        } else {
            print!("{}", sp.hex(sh.sh_size));
        }
        print!(" {:>10} \x1b[97m│\x1b[0m", BinSize(sh.sh_size));

        println!();
    }
}

pub fn one_section(elf: &Elf, bytes: &[u8], opts: &SectionArgs) -> Result<()> {
    if opts.name.is_none() {
        return Ok(all_sections(elf));
    }

    let name = opts.name.as_ref().unwrap();
    let sh = find_section(elf, name)
        .ok_or_else(|| anyhow!("couldn't find section {name:?}"))?;

    let mut index_range = sh.file_range();
    if let Some(ref mut index_range) = index_range {
        if let Some(skip) = opts.skip {
            if skip >= index_range.len() {
                println!("\x1b[93mWarning: skipping more bytes than in section\x1b[0m");
            }
            index_range.start += skip;
        }
        if let Some(maxlen) = opts.size {
            if index_range.len() > maxlen {
                index_range.end -= index_range.len() - maxlen;
            }
        }
        if index_range.len() == 0 {
            *index_range = 0..0;
        }
    } else {
        if opts.skip.is_some() {
            println!("\x1b[93mWarning: byte skipping specified on a NOBITS section\x1b[0m");
        }
        if opts.size.is_some() {
            println!("\x1b[93mWarning: number of bytes specified on a NOBITS section\x1b[0m");
        }
    }

    if let Some(ref output) = opts.output {
        let index_range = index_range.ok_or_else(||
            anyhow!("section {name:?} is NOBITS and, therefor, has no content to export.")
        )?;

        let mut fh = File::create(output).with_context(||
            format!("couldn't export content to file '{}'", output.display())
        )?;
        fh.write_all(&bytes[index_range]).with_context(||
            format!("couldn't write content to file '{}'", output.display())
        )?;

        println!("Section {name:?} has been saved to \"{}\"", output.display());

        return Ok(());
    }

    print_header(&format!("SECTION {name:?}"));

    let table = PairTable(18);
    let (type_c, type_n) = section_type(sh.sh_type);
    let container = elf.header.container().unwrap_or(Container::Big);
    let sp = SizePrint::new(container);

    table.field("Name");
    println!("{name}");

    table.field("Type");
    println!("\x1b[{type_c}{type_n}\x1b[0m ({:#010x})", sh.sh_type);

    table.field("Virtual address");
    if sh.sh_addr == 0 {
        print!("\x1b[90m");
    }
    println!("{}", sp.hex(sh.sh_addr));

    table.field("Offset in ELF");
    println!("{} B", sp.hex(sh.sh_offset));

    table.field("Size");
    println!("{} B ({})", sp.hex(sh.sh_size), BinSize(sh.sh_size));

    table.field("Alignment");
    println!("{} B", sp.hex(sh.sh_addralign));

    table.field("Entry size");
    if sh.sh_entsize == 0 {
        print!("\x1b[90m");
    }
    println!("{} B\x1b[0m", sp.hex(sh.sh_entsize));

    if let Some(index_range) = index_range {
        println!();
        let content = &bytes[index_range];

        if opts.hexdump {
            hexdump(content);
        } else {
            if sh.sh_type == SHT_STRTAB {
                strtab(content)?;
            } else if name == ".eh_frame_hdr" {
                eh_frame_hdr(elf, sh.sh_addr, content);
            } else if name == ".eh_frame" {
                eh_frame(elf, sh.sh_addr, content, &Default::default())?;
            } else {
                hexdump(content);
            }
        }
    }

    Ok(())
}

pub fn find_section<'a>(elf: &'a Elf, name: &str) -> Option<&'a SectionHeader> {
    elf.section_headers
        .iter()
        .find(|&s| {
            elf.shdr_strtab.get_at(s.sh_name)
                .map(|n| n == name)
                .unwrap_or(false)
        })
}

fn section_type(typ: u32) -> (&'static str, &'static str) {
    match sht_to_str(typ) {
        "UNKNOWN_SHT" => ("93m", "[unknown]"),
        "SHT_PROGBITS" => ("34m", "PROGBITS"),
        "SHT_NULL" => ("90m", "NULL"),
        "SHT_NOBITS" => ("90m", "NOBITS"),
        "SHT_STRTAB" => ("32m", "STRTAB"),
        "SHT_DYNAMIC" => ("35m", "DYNAMIC"),
        "SHT_DYNSYM" => ("95m", "DYNSYM"),
        "SHT_RELA" => ("33m", "RELA"),
        "SHT_SYMTAB" => ("31m", "SYMTAB"),
        "SHT_NOTE" => ("36m", "NOTE"),
        s => ("0m", s.strip_prefix("SHT_").unwrap_or(s)),
    }
}

fn strtab(content: &[u8]) -> Result<()> {
    let strtab = Strtab::new(content, 0).to_vec()?;
    for (i, s) in strtab.into_iter().enumerate() {
        println!("{i:4} {s:?}");
    }

    Ok(())
}
