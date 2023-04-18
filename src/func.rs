/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use std::cell::RefCell;
use std::collections::HashMap;
use goblin::elf::Elf;
use anyhow::{anyhow, Context, Result};
use gimli::{BaseAddresses, CallFrameInstruction, EhFrame, EndianSlice,
            FrameDescriptionEntry, LittleEndian, Register, SectionBaseAddresses,
            UnwindSection};
use goblin::container::Container;
use goblin::elf::sym::STT_FUNC;
use iced_x86::{Decoder, DecoderOptions, Formatter, FormatterOutput,
               FormatterTextKind, GasFormatter, Instruction, IntelFormatter,
               SymbolResolver, SymbolResult};
use rustc_demangle::demangle;

use crate::args::{FnArgs, Syntax};
use crate::eh::EhInstrContext;
use crate::elf::{find_symbol, find_symbol_by_addr, symbol_file_offset};
use crate::print::SizePrint;
use crate::sections::find_section;
use crate::sym::sym_type;

pub fn do_fn(elf: &Elf, bytes: &[u8], args: &FnArgs) -> Result<()> {
    let (sym, strtab) = if args.address {
        let addr = u64::from_str_radix(args.name.trim_start_matches("0x"), 16)
            .context(anyhow!("couldn't parse memory address '{}'", args.name))?;
        find_symbol_by_addr(&elf.syms, addr).zip(Some(&elf.strtab))
    } else {
        find_symbol(&elf.syms, &elf.strtab, &args.name).zip(Some(&elf.strtab))
            .or_else(|| find_symbol(&elf.dynsyms, &elf.dynstrtab, &args.name).zip(Some(&elf.dynstrtab)))
    }.ok_or_else(||
        anyhow!("couldn't find any symbol matching {:?}", args.name)
    )?;

    let sym_name = strtab.get_at(sym.st_name).unwrap();

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

    let opts = DisassOptions {
        cfi: args.cfi,
        syntax: args.syntax,
    };
    disassemble(elf, bytes, sym.st_value, content, opts);

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

#[derive(Default)]
struct DisassOptions {
    syntax: Syntax,
    cfi: bool,
}

fn disassemble(elf: &Elf, bytes: &[u8], ip: u64, content: &[u8], opts: DisassOptions) {
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
    let mut formatter: Box<dyn Formatter> = match opts.syntax {
        Syntax::Intel => Box::new(IntelFormatter::with_options(Some(sym_resolver), None)),
        Syntax::Att => Box::new(GasFormatter::with_options(Some(sym_resolver), None)),
    };
    formatter.options_mut().set_first_operand_char_index(8);
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_space_after_operand_separator(true);
    formatter.options_mut().set_space_between_memory_add_operators(true);
    formatter.options_mut().set_gas_space_after_memory_operand_comma(true);

    let mut eh = opts.cfi.then(|| EhFnCtx::new(elf, bytes, ip)).flatten();

    while decoder.can_decode() {
        let instr = decoder.decode();
        let start_index = (instr.ip() - ip) as usize;
        let bytes = &content[start_index..(start_index + instr.len())];

        if let Some(ref mut eh) = eh {
            eh.at_ip(instr.ip());
        }

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

struct EhFnCtx<'a> {
    base_addrs: &'static BaseAddresses,
    eh: EhFrame<EndianSlice<'a, LittleEndian>>,
    fde: FrameDescriptionEntry<EndianSlice<'a, LittleEndian>>,
    instr_ctx: RefCell<EhInstrContext>,
    curr_loc: RefCell<u64>,
    cie_shown: bool,
    instr_index: usize,
}

impl<'a> EhFnCtx<'a> {
    fn new(elf: &Elf, bytes: &'a [u8], ip: u64) -> Option<Self> {
        let container = elf.header.container().unwrap_or(Container::Big);
        let sp = SizePrint::new(container);

        let eh_frame = find_section(elf, ".eh_frame")?;
        let eh = EhFrame::new(&bytes[eh_frame.file_range()?], LittleEndian);

        let base_addrs = Box::leak(Box::new(BaseAddresses {
            eh_frame_hdr: SectionBaseAddresses::default(),
            eh_frame: SectionBaseAddresses {
                section: Some(eh_frame.sh_addr),
                text: None,
                data: None,
            },
        }));

        let fde = eh.fde_for_address(
            &base_addrs,
            ip,
            |section, bases, offset| section.cie_from_offset(bases, offset),
        ).ok()?;

        let instr_ctx = EhInstrContext {
            cfa_reg: Register(0),
            cfa_off: 0,
            loc: fde.initial_address(),
            data_align: fde.cie().data_alignment_factor(),
            sp,
        };
        let curr_loc = instr_ctx.loc;

        Some(EhFnCtx {
            base_addrs,
            eh,
            fde,
            instr_ctx: RefCell::new(instr_ctx),
            curr_loc: RefCell::new(curr_loc),
            cie_shown: false,
            instr_index: 0,
        })
    }

    fn at_ip(&mut self, ip: u64) {
        if !self.cie_shown {
            let mut iter = self.fde.cie().instructions(&self.eh, self.base_addrs);
            while let Ok(Some(instr)) = iter.next() {
                self.print_instr(instr);
            }
            self.cie_shown = true;
        }

        let mut iter = self.fde.instructions(&self.eh, self.base_addrs);
        for _ in 0..self.instr_index {
            if iter.next().ok().flatten().is_none() {
                return;
            }
        }

        while let Ok(Some(instr)) = iter.next() {
            if ip < *self.curr_loc.borrow() {
                break;
            }
            self.print_instr(instr);
            self.instr_index += 1;
        }
    }

    fn print_instr(
        &self,
        instr: CallFrameInstruction<EndianSlice<'a, LittleEndian>>,
    ) {
        match instr {
            CallFrameInstruction::Nop => (),
            CallFrameInstruction::AdvanceLoc { delta } => {
                *self.curr_loc.borrow_mut() += delta as u64;
            },
            _ => {
                print!("\x1b[35m[CFI]\x1b[0m ");
                self.instr_ctx.borrow_mut().print(instr.clone());
            }
        }
    }
}
