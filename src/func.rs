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
use goblin::elf::Elf;
use anyhow::{anyhow, Context, Result};
use goblin::container::Container;
use goblin::elf::sym::STT_FUNC;
use iced_x86::{Decoder, DecoderOptions, Formatter, FormatterOutput,
               FormatterTextKind, GasFormatter, Instruction, IntelFormatter,
               SymbolResolver, SymbolResult};
use rustc_demangle::demangle;

use crate::args::FnArgs;
use crate::elf::{find_symbol, find_symbol_by_addr, symbol_file_offset};
use crate::print::SizePrint;
use crate::sym::sym_type;

pub fn do_fn(elf: &Elf, bytes: &[u8], args: &FnArgs) -> Result<()> {
    let sym = if args.address {
        let addr = u64::from_str_radix(args.name.trim_start_matches("0x"), 16)
            .context(anyhow!("couldn't parse memory address '{}'", args.name))?;
        find_symbol_by_addr(&elf.syms, addr)
    } else {
        find_symbol(&elf.syms, &elf.strtab, &args.name)
            .or_else(|| find_symbol(&elf.dynsyms, &elf.dynstrtab, &args.name))
    }.ok_or_else(||
        anyhow!("couldn't find any symbol matching {:?}", args.name)
    )?;

    let sym_name = elf.strtab.get_at(sym.st_name).unwrap();

    if sym.st_type() != STT_FUNC {
        println!(
            "\x1b[93mwarning\x1b[0m: Symbol {sym_name:?} has type {}", sym_type(sym.st_type())
        );
    }

    let file_off = symbol_file_offset(elf, sym_name).ok_or_else(||
        anyhow!("couldn't find the file offset")
    )? as usize;
    if sym.st_size == 0 {
        unimplemented!("symbol is required");
    }

    let content = &bytes[file_off..(file_off + sym.st_size as usize)];

    println!("\x1b[97m{sym_name}:\x1b[0m");
    disassemble(elf, sym.st_value, content);

    Ok(())
}

struct SymResolver {
    syms: HashMap<u64, String>,
    demangle: bool,
    sym_name: String,
}

impl SymbolResolver for SymResolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        if let Some(name) = self.syms.get(&address) {
            if self.demangle {
                self.sym_name = demangle(&name).to_string();
            } else {
                self.sym_name = name.clone();
            };
            Some(SymbolResult::with_str(address, &self.sym_name))
        } else {
            None
        }
    }
}

struct ColorOutput;

impl FormatterOutput for ColorOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        use FormatterTextKind::*;

        match kind {
            Number => print!("\x1b[36m"),
            Register => print!("\x1b[32m"),
            Mnemonic => print!("\x1b[33m"),
            FunctionAddress => print!("\x1b[94m"),
            LabelAddress => print!("\x1b[34m"),
            _=> print!("\x1b[0m"),
        }

        print!("{text}");
    }
}

fn disassemble(elf: &Elf, ip: u64, content: &[u8]) {
    let container = elf.header.container().unwrap_or(Container::Big);
    let bitness = match container {
        Container::Big => 64,
        Container::Little => 32,
    };
    let sp = SizePrint::new(container);

    let mut decoder = Decoder::with_ip(
        bitness,
        content,
        ip,
        DecoderOptions::NONE
    );

    let syms: HashMap<u64, String> = elf.syms.iter()
        .filter_map(|sym|
            elf.strtab.get_at(sym.st_name)
                .map(|name| (sym.st_value, name.to_owned()))
        ).collect();

    let sym_resolver: Box<dyn SymbolResolver> = Box::new(SymResolver {
        syms,
        demangle: true,
        sym_name: String::new(),
    });

    let mut output = ColorOutput;
    let mut formatter: Box<dyn Formatter> = if false {
        Box::new(IntelFormatter::with_options(
            Some(sym_resolver),
            None,
        ))
    } else {
        Box::new(GasFormatter::with_options(
            Some(sym_resolver),
            None,
        ))
    };
    formatter.options_mut().set_first_operand_char_index(8);
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_space_after_operand_separator(true);
    formatter.options_mut().set_space_between_memory_add_operators(true);
    formatter.options_mut().set_gas_space_after_memory_operand_comma(true);

    while decoder.can_decode() {
        let instr = decoder.decode();
        let start_index = (instr.ip() - ip) as usize;
        let bytes = &content[start_index..(start_index + instr.len())];

        print!("{} \x1b[97m│\x1b[0m  ", sp.hex(instr.ip()));

        let col_w;

        if bytes.len() > 12 {
            for &byte in bytes {
                print!("{byte:02x}");
            }
            col_w = bytes.len() * 2;
        } else {
            for &byte in bytes {
                print!("{byte:02x} ");
            }
            col_w = bytes.len() * 3;
        }

        print!(
            "{:w$} \x1b[97m│\x1b[0m  ", "",
            w = 24usize.saturating_sub(col_w)
        );

        formatter.format(&instr, &mut output);
        println!("\x1b[0m");
    }
}
