/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use goblin::container::{Container, Endian};
use goblin::elf::Elf;
use goblin::elf::program_header::pt_to_str;

use crate::{PairTable, print_header, SizePrint};

pub fn header(elf: &Elf) {
    let h = &elf.header;
    let container = elf.header.container().unwrap_or(Container::Big);
    let sp = SizePrint::new(container);
    let table = PairTable(22);

    print_header("ELF HEADER");

    table.field("Version");
    println!("{}", h.e_version);

    table.field("Type");
    use goblin::elf::header::*;
    match h.e_type {
        ET_NONE => println!("None"),
        ET_REL => println!("Relocatable"),
        ET_EXEC => println!("Executable"),
        ET_DYN => println!("Shared object"),
        ET_CORE => println!("Core file"),
        n if (ET_LOOS..ET_HIOS).contains(&n) =>
            println!("OS-specific ({n:#06x})"),
        n if (ET_LOPROC..ET_HIPROC).contains(&n) =>
            println!("Processor-specific ({n:#06x})"),
        n => println!("Unknown ({n:#06x})"),
    }

    table.field("Ident's class");
    match h.container() {
        Ok(Container::Little) => println!("ELF32"),
        Ok(Container::Big) => println!("ELF64"),
        Err(_) => println!("\x1b[93m[warning: invalid ident class]\x1b[0m"),
    }

    table.field("Ident's data");
    match h.endianness() {
        Ok(Endian::Little) => println!("Little-endian"),
        Ok(Endian::Big) => println!("Big-endian"),
        Err(_) => println!("\x1b[93m[warning: invalid ident data]\x1b[0m"),
    }

    table.field("Machine");
    println!("{}", machine_to_str(h.e_machine));

    table.field("Entry point address");
    if h.e_entry == 0 {
        print!("\x1b[90m");
    }
    println!("{}", sp.hex(h.e_entry));

    table.field("Flags");
    println!("{:#010x}", h.e_flags);

    if let Some(interpreter) = elf.interpreter {
        table.field("Interpreter");
        println!("{interpreter}");
    }

    if let Some(soname) = elf.soname {
        table.field("SO name");
        println!("{soname}");
    }

    table.field("");
    println!();

    table.field("Nr. prog. headers");
    println!("{:>16}", h.e_phnum);

    table.field("Prog. headers offset");
    println!("{:>16} B", h.e_phoff);

    table.field("Prog. header size");
    println!("{:>16} B", h.e_phentsize);

    table.field("Nr. section headers");
    println!("{:>16}", h.e_shnum);

    table.field("Section headers offset");
    println!("{:>16} B", h.e_shoff);

    table.field("Section header size");
    println!("{:>16} B", h.e_shentsize);
}

pub fn program_headers(elf: &Elf) {
    let container = elf.header.container().unwrap_or(Container::Big);
    let sp = SizePrint::new(container);

    print_header(
        &format!("PROGRAM HEADERS ({})", elf.program_headers.len())
    );

    let colw = match container {
        Container::Big => 19,
        Container::Little => 11,
    };

    println!(
        "\x1b[37m{:>12} \x1b[97m│ \x1b[37m{:<w1$} \x1b[97m│ \x1b[37m{:<w1$} \x1b[97m│ \x1b[37m{:<8}\x1b[0m",
        "Type", "Virt. addr.", "Phys. addr.", "Flags",
        w1 = colw + 1,
    );
    println!(
        "\x1b[37m{:<12} \x1b[97m│ \x1b[37m{:<w1$} \x1b[97m│ \x1b[37m{:<w1$}\x1b[0m \x1b[97m│ \x1b[37m{:<w1$}",
        "", "Memory size", "In-ELF size", "In-ELF off.",
        w1 = colw + 1,
    );
    println!("\x1b[97m{0:─<13}┼{0:─<w$}┼{0:─<w$}┼\x1b[0m", "", w = colw + 3);

    for ph in elf.program_headers.iter() {
        let typ = match pt_to_str(ph.p_type) {
            "UNKNOWN_PT" => "\x1b[93m[unknown]\x1b[0m",
            s => s.strip_prefix("PT_").unwrap_or(s),
        };

        println!(
            "{typ:>12} \x1b[97m│\x1b[0m {vaddr} \x1b[97m╶┼>\x1b[0m {paddr}",
            vaddr = sp.hex(ph.p_vaddr),
            paddr = sp.hex(ph.p_paddr),
        );
        println!(
            "\x1b[4m{:>12} \x1b[97m│\x1b[0;4m {msize}  \x1b[97m│\x1b[0;4m  {fsize}\x1b[0m",
            "",
            msize = sp.hex(ph.p_memsz),
            fsize = sp.hex(ph.p_filesz),
        );
    }
}
