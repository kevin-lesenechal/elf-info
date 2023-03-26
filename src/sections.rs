/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use std::collections::HashMap;
use std::default::Default;
use std::fs::File;
use std::io::Write;
use goblin::container::{Container};
use goblin::elf::Elf;
use goblin::elf::section_header::sht_to_str;
use goblin::elf32::section_header::SHT_STRTAB;
use goblin::strtab::Strtab;
use anyhow::{anyhow, Context, Result};
use byteorder::ReadBytesExt;
use gimli::{BaseAddresses, CallFrameInstruction, CieOrFde, EhFrame,
            LittleEndian, Reader, Register, SectionBaseAddresses, UnwindSection,
            X86_64};

use crate::{PairTable, print_header, SizePrint};
use crate::args::SectionArgs;
use crate::print::{BinSize, hexdump};
use crate::sym::addr_to_sym;

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
    let name = &opts.name;
    let sh = elf.section_headers
        .iter()
        .find(|&s| {
            elf.shdr_strtab.get_at(s.sh_name)
                .map(|n| n == name)
                .unwrap_or(false)
        })
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
                eh_frame(elf, sh.sh_offset, content);
            } else {
                hexdump(content);
            }
        }
    }

    Ok(())
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

fn eh_frame_hdr(elf: &Elf, pc: u64, content: &[u8]) {
    let container = elf.header.container().unwrap_or(Container::Big);
    let sp = SizePrint::new(container);

    println!("\x1b[1;96m─── Header ───\x1b[0m");
    let table = PairTable(22);

    table.field("Version");
    println!("{}", content[0]);

    table.field("eh_frame_ptr encoding");
    encoding(content[1]);

    table.field("fde_count encoding");
    encoding(content[2]);

    table.field("Table encoding");
    encoding(content[3]);

    let mut off = 4;
    table.field(".eh_frame pointer");
    let (size, val) = value(content[1], &content[off..]);
    match val {
        Value::Signed(n) => print!("{n}"),
        Value::Unsigned(n) => print!("{n}"),
    }
    println!("  (-> {})", sp.hex(value_abs(content[1], val, pc + off as u64, pc)));
    off += size;

    table.field("Nr entries");
    let (size, val) = value(content[2], &content[off..]);
    let nr_entries;
    match val {
        Value::Signed(n) => { nr_entries = n as usize; println!("{n}"); },
        Value::Unsigned(n) => { nr_entries = n as usize; println!("{n}"); },
    }
    off += size;

    println!("\n\x1b[1;96m─── Table content ───\x1b[0m");

    for _ in 0..nr_entries {
        print!("\t");

        let (size, val) = value(content[3], &content[off..]);
        print!("\x1b[90m(");
        match val {
            Value::Signed(n) => print!("{n:10}"),
            Value::Unsigned(n) => print!("{n:10}"),
        }
        off += size;
        print!(")\x1b[0m");

        print!("  {}", sp.hex(value_abs(content[3], val, pc + off as u64, pc)));
        print!("  ->  ");

        let (size, val) = value(content[3], &content[off..]);
        print!("{}  ", sp.hex(value_abs(content[3], val, pc + off as u64, pc)));
        print!("\x1b[90m(");
        match val {
            Value::Signed(n) => print!("{n:10}"),
            Value::Unsigned(n) => print!("{n:10}"),
        }
        off += size;
        print!(")\x1b[0m");

        println!();
    }

    fn encoding(n: u8) {
        print!("{n:#04x} ");
        if n == 0xff {
            println!("(no value)");
            return;
        }

        let size = match n & 0x0f {
            0x01 => "unsigned LEB128",
            0x02 => "u16",
            0x03 => "u32",
            0x04 => "u64",
            0x09 => "signed LEB128",
            0x0a => "i16",
            0x0b => "i32",
            0x0c => "i64",
            _ => "???",
        };
        let app = match n & 0xf0 {
            0x00 => "as is",
            0x10 => "relative to program counter",
            0x30 => "relative to .eh_frame_hdr start",
            _ => "???",
        };

        println!("({size}, {app})");
    }

    fn value(enc: u8, mut d: &[u8]) -> (usize, Value) {
        use byteorder::LittleEndian;

        match enc & 0x0f {
            0x01 => unimplemented!("unsigned LEB128"), // TODO: implement
            0x02 => (2, Value::Unsigned(d.read_u16::<LittleEndian>().unwrap() as u64)),
            0x03 => (4, Value::Unsigned(d.read_u32::<LittleEndian>().unwrap() as u64)),
            0x04 => (8, Value::Unsigned(d.read_u64::<LittleEndian>().unwrap())),
            0x09 => unimplemented!("signed LEB128"), // TODO: implement
            0x0a => (2, Value::Signed(d.read_i16::<LittleEndian>().unwrap() as i64)),
            0x0b => (4, Value::Signed(d.read_i32::<LittleEndian>().unwrap() as i64)),
            0x0c => (8, Value::Signed(d.read_i64::<LittleEndian>().unwrap())),
            _ => panic!("invalid encoding"), // TODO: don't panic
        }
    }

    fn value_abs(enc: u8, v: Value, pc: u64, ehhdr: u64) -> u64 {
        let base = match enc & 0xf0 {
            0x00 => 0,
            0x10 => pc,
            0x30 => ehhdr,
            _ => panic!("invalid encoding"), // TODO: don't panic
        };

        match v {
            Value::Signed(n) => (base as i64 + n) as u64,
            Value::Unsigned(n) => base + n,
        }
    }

    #[derive(Copy, Clone)]
    enum Value {
        Signed(i64),
        Unsigned(u64),
    }
}

fn eh_frame(elf: &Elf, off: u64, content: &[u8]) {
    let container = elf.header.container().unwrap_or(Container::Big);
    let sp = SizePrint::new(container);
    let eh = EhFrame::new(content, LittleEndian); // TODO: endianness

    let mut cies = HashMap::new();
    let mut instr_ctx = EhInstrContext {
        cfa_reg: Register(0),
        cfa_off: 0,
        loc: 0,
        data_align: 1,
        sp,
    };

    let base_addrs = BaseAddresses {
        eh_frame_hdr: SectionBaseAddresses::default(),
        eh_frame: SectionBaseAddresses {
            section: Some(off),
            text: None,
            data: None,
        },
    };
    let mut entries = eh.entries(&base_addrs);
    while let Some(entry) = entries.next().unwrap() {
        match entry {
            CieOrFde::Cie(cie) => {
                let table = PairTable(20);

                println!("│");
                println!("├╴ \x1b[97mCIE\x1b[0m  offset={}", sp.hex(cie.offset() as u64));
                print!("│  ├╴");
                table.field("Version");
                println!("{}", cie.version());

                print!("│  ├╴");
                table.field("Length");
                println!("{}", cie.entry_len());

                print!("│  ├╴");
                table.field("Augmentation");
                println!();

                print!("│  ├╴");
                table.field("Code alignment");
                println!("{}", cie.code_alignment_factor());

                print!("│  ├╴");
                table.field("Data alignment");
                println!("{}", cie.data_alignment_factor());

                print!("│  ├╴");
                table.field("Return addr register");
                println!("{} (%{})", cie.return_address_register().0,
                         register_name(cie.return_address_register()));

                let mut instr_iter = cie.instructions(&eh, &base_addrs);
                instr_ctx.data_align = cie.data_alignment_factor();
                while let Some(instr) = instr_iter.next().unwrap_or(None) {
                    print!("│  ├──⮞ ");
                    instr_ctx.print(instr);
                }

                cies.insert(cie.offset(), cie);
            },
            CieOrFde::Fde(fde_unparsed) => {
                let fde = fde_unparsed.parse(|_, _, offset| {
                    Ok(cies[&offset.0].clone())
                }).unwrap();
                let table = PairTable(10);

                println!("│  │");
                println!(
                    "│  ├╴ \x1b[97mFDE\x1b[0m  offset={}  CIE={}",
                    sp.hex(fde.offset() as u64), sp.hex(fde.cie().offset() as u64)
                );
                print!("│  │  ├╴");
                table.field("PC range");
                println!(
                    "{}..{}",
                    sp.hex(fde.initial_address()),
                    sp.hex(fde.initial_address() + fde.len())
                );

                if let Some(sym) = addr_to_sym(&elf.syms, fde.initial_address()) {
                    print!("│  │  ├╴");
                    table.field("Symbol");
                    let name = elf.strtab.get_at(sym.st_name).unwrap_or("???");
                    println!("{name} + {:#x}", fde.initial_address() - sym.st_value);
                }

                instr_ctx.loc = fde.initial_address();
                let mut instr_iter = fde.instructions(&eh, &base_addrs);
                while let Some(instr) = instr_iter.next().unwrap_or(None) {
                    print!("│  │  ├──⮞ ");
                    instr_ctx.print(instr);
                }
            },
        }
    }
}

struct EhInstrContext {
    cfa_reg: Register,
    cfa_off: u64,
    loc: u64,
    data_align: i64,
    sp: SizePrint,
}

impl EhInstrContext {
    fn print<R: Reader>(&mut self, instr: CallFrameInstruction<R>) {
        use CallFrameInstruction::*;

        match instr {
            SetLoc { address } => {
                println!(
                    "DW_CFA_set_loc({address})\tloc = {address}",
                );
            },
            AdvanceLoc { delta } => {
                self.loc += delta as u64;
                println!(
                    "DW_CFA_advance_loc({delta})\tloc += {delta}\tloc = {}",
                    self.sp.hex(self.loc),
                );
            },
            DefCfa { register, offset } => {
                println!(
                    "DW_CFA_def_cfa({}, {offset})\t\tcfa = %{} + {offset}",
                    register.0, register_name(register),
                );
                self.cfa_reg = register;
                self.cfa_off = offset;
            },
            DefCfaSf { register, factored_offset } => {
                println!(
                    "DW_CFA_def_cfa_sf({}, {factored_offset})", register.0
                );
            },
            DefCfaRegister { register } => {
                println!(
                    "DW_CFA_def_cfa_register({})\tcfa = %{} + \x1b[90m{}\x1b[0m",
                    register.0, register_name(register), self.cfa_off,
                );
                self.cfa_reg = register;
            },
            DefCfaOffset { offset } => {
                println!(
                    "DW_CFA_def_cfa_offset({offset})\tcfa = \x1b[90m%{}\x1b[0m + {offset}",
                    register_name(self.cfa_reg),
                );
                self.cfa_off = offset;
            },
            DefCfaOffsetSf { factored_offset } => {
                println!("DW_CFA_def_cfa_offset_sf({factored_offset})");
            },
            DefCfaExpression { expression } => {
                println!("DW_CFA_def_cfa_expression({:02x?})", expression.0.to_slice().unwrap());
            },
            Undefined { register } => {
                println!(
                    "DW_CFA_undefined({})\t\t%{} @ ??? (unrecoverable)",
                    register.0, register_name(register),
                );
            },
            SameValue { register } => {
                println!(
                    "DW_CFA_same_value({})\t\t%{} untouched",
                    register.0, register_name(register),
                );
            },
            Offset { register, factored_offset } => {
                let off = factored_offset as i64 * self.data_align;
                println!(
                    "DW_CFA_offset({}, {factored_offset})\t\t%{} @ cfa {} {}",
                    register.0, register_name(register),
                    if off < 0 { "−" } else { "+" },
                    off.abs()
                );
            },
            OffsetExtendedSf { register, factored_offset } => {
                println!(
                    "DW_CFA_offset_extended_sf({}, {factored_offset})", register.0
                );
            },
            ValOffset { register, factored_offset } => {
                println!(
                    "DW_CFA_val_offset({}, {factored_offset})", register.0
                );
            },
            ValOffsetSf { register, factored_offset } => {
                println!(
                    "DW_CFA_val_offset_sf({}, {factored_offset})", register.0
                );
            },
            Register { dest_register, src_register } => {
                println!(
                    "DW_CFA_register({}, {})\t%{} = %{}",
                    dest_register.0, src_register.0,
                    register_name(dest_register), register_name(src_register),
                );
            },
            Expression { register, expression } => {
                println!(
                    "DW_CFA_expression({}, {:02x?})\t\t%{} = ...",
                    register.0, expression.0.to_slice().unwrap(),
                    register_name(register),
                );
            },
            ValExpression { register, expression } => {
                println!(
                    "DW_CFA_val_expression({}, {:02x?})",
                    register.0, expression.0.to_slice().unwrap(),
                );
            },
            Restore { register } => {
                println!(
                    "DW_CFA_restore({})\t\t%{} @ (initial rule)",
                    register.0, register_name(register),
                );
            },
            RememberState => println!("DW_CFA_remember_state()"),
            RestoreState => println!("DW_CFA_restore_state()"),
            ArgsSize { size } => println!("DW_CFA_GNU_args_size({size})"),
            Nop => println!("\x1b[90mDW_CFA_nop()\x1b[0m"),
        }
    }
}

fn register_name(r: Register) -> &'static str {
    X86_64::register_name(r).unwrap_or("???") // TODO: handle other archs
}
