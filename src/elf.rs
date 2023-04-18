/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use goblin::elf::{Elf, ProgramHeader, Sym, Symtab};
use goblin::strtab::Strtab;
use rustc_demangle::demangle;

pub fn symbol_file_offset(elf: &Elf, sym_name: &str) -> Option<u64> {
    // TODO: handle stripped binaries
    let sym = find_symbol(&elf.syms, &elf.strtab, sym_name)
        .or_else(|| find_symbol(&elf.dynsyms, &elf.dynstrtab, sym_name))?;
    let ph = ph_by_vaddr(elf, sym.st_value)?;

    Some(ph.p_offset + (sym.st_value - ph.p_vaddr))
}

pub fn find_symbol(tab: &Symtab, strtab: &Strtab, name: &str) -> Option<Sym> {
    tab.iter()
        .find(|sym| {
            strtab.get_at(sym.st_name).map(|n| n == name).unwrap_or(false)
        })
        .or_else(|| tab.iter().find(|sym| {
            strtab.get_at(sym.st_name)
                .map(|n| demangle(n).to_string() == name)
                .unwrap_or(false)
        }))
}

pub fn find_symbol_by_addr(tab: &Symtab, addr: u64) -> Option<Sym> {
    tab.iter()
        .find(|sym| {
            (sym.st_value..(sym.st_value + sym.st_size)).contains(&addr)
        })
}

pub fn ph_by_vaddr<'a>(elf: &'a Elf, vaddr: u64) -> Option<&'a ProgramHeader> {
    elf.program_headers.iter()
        .find(|&ph| (ph.p_vaddr..(ph.p_vaddr + ph.p_memsz)).contains(&vaddr))
}
