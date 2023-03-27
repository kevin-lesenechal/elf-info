/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use goblin::container::Container;
use goblin::elf::{Elf, Sym, Symtab};
use regex::Regex;
use rustc_demangle::demangle;

use crate::{print_header, SizePrint, SymbolsArgs};

pub fn all_symbols(elf: &Elf, opts: &SymbolsArgs) {
    let (syms, strtab) = if opts.dynamic {
        (&elf.dynsyms, &elf.dynstrtab)
    } else {
        (&elf.syms, &elf.strtab)
    };
    let container = elf.header.container().unwrap_or(Container::Big);
    let sp = SizePrint::new(container);

    print_header(
        &format!(
            "{} ({})",
            if opts.dynamic { "DYNAMIC SYMBOLS" } else { "SYMBOLS" },
            syms.len()
        )
    );

    let colw = match container {
        Container::Big => 19,
        Container::Little => 11,
    };
    println!(
        "\x1b[97m{:>colw$} │ {:7} │ {:10} │ {}\x1b[0m",
        "Value", "Type VB", "Size", "Name",
    );
    println!(
        "\x1b[97m{0:─<w$}┼{0:─<9}┼{0:─<12}┼{0:─<60}\x1b[0m",
        "", w = colw + 1,
    );

    for sym in syms.iter() {
        if (opts.global && sym.st_bind() != STB_GLOBAL)
            || (opts.local && sym.st_bind() != STB_LOCAL)
            || (opts.weak && sym.st_bind() != STB_WEAK)
            || (opts.visible && sym.st_visibility() != STV_DEFAULT){
            continue;
        } else if let Some(ref filt_type) = opts.r#type {
            if filt_type.to_st_type() != sym.st_type() {
                continue;
            }
        }

        let name = strtab.get_at(sym.st_name).unwrap(); // TODO
        let name = if !opts.no_demangle {
            let s = demangle(name).to_string();
            if opts.no_rust_std && is_std_sym(&s) {
                continue;
            }
            s
        } else {
            name.to_string()
        };
        let defined = sym.st_value > 0;

        if let Some(ref filter) = opts.filter {
            if !filter.is_match(&name) {
                continue;
            }
        }

        use goblin::elf::sym::*;
        let typ = match sym.st_type() {
            STT_NOTYPE => "\x1b[90mNONE\x1b[0m",
            STT_OBJECT => " \x1b[34mOBJ\x1b[0m",
            STT_FUNC => "\x1b[32mFUNC\x1b[0m",
            STT_SECTION => "\x1b[31mSECT\x1b[0m",
            STT_FILE => "\x1b[36mFILE\x1b[0m",
            STT_COMMON => "COMM",
            STT_TLS => " \x1b[35mTLS\x1b[0m",
            STT_NUM => " NUM",
            _ => "    ",
        };
        let vis = match sym.st_visibility() {
            STV_DEFAULT => "+",
            STV_INTERNAL => "i",
            STV_HIDDEN => "\x1b[31m−\x1b[0m",
            STV_PROTECTED => "\x1b[33m#\x1b[0m",
            STV_EXPORTED => "x",
            STV_SINGLETON => "s",
            STV_ELIMINATE => "e",
            _ => "?",
        };
        let bind = match sym.st_bind() {
            STB_LOCAL => "\x1b[90ml\x1b[0m",
            STB_GLOBAL => if defined { "\x1b[97mG\x1b[0m" }
            else { "\x1b[91mU\x1b[0m" },
            STB_WEAK => "\x1b[36mW\x1b[0m",
            STB_NUM => "\x1b[35mN\x1b[0m",
            STB_GNU_UNIQUE => "\x1b[31mu\x1b[0m",
            _ => "\x1b[93m?\x1b[0m",
        };
        let size = match sym.st_size {
            0 => "          ".to_string(),
            n => format!("{n:#010x}"),
        };

        if !defined {
            print!("\x1b[30m");
        }

        println!(
            "{v} \x1b[97m│\x1b[0m {typ} {vis}{bind} \x1b[97m│\x1b[0m {size} \x1b[97m│\x1b[0m {name}",
            v = sp.hex(sym.st_value),
        );
    }

    println!();
    println!("\x1b[97mVisibility [V]:        Binding [B]:\x1b[0m");
    println!("  +  Default             \x1b[90ml\x1b[0m  Local");
    println!("  \x1b[33m#\x1b[0m  Protected           \x1b[97mG\x1b[0m  Global");
    println!("  \x1b[31m−\x1b[0m  Hidden              \x1b[91mU\x1b[0m  Global (undefined)");
    println!("  i  Internal            \x1b[36mW\x1b[0m  Weak");
    println!("  x  Exported            \x1b[35mN\x1b[0m  Number of defined types");
    println!("  s  Singleton           \x1b[31mu\x1b[0m  GNU unique");
    println!("  e  Eliminate");
}

fn is_std_sym(sym: &str) -> bool {
    sym.starts_with("core::")
        || sym.starts_with("std::")
        || sym.starts_with("alloc::")
        || Regex::new("^<(std|core|alloc)::.+ as .+>").unwrap().is_match(sym)
        || Regex::new("^<.+ as (std|core|alloc)::.+>").unwrap().is_match(sym)
}

pub fn sym_type(typ: u8) -> &'static str {
    use goblin::elf::sym::*;
    match typ {
        STT_NOTYPE => "\x1b[90mNONE\x1b[0m",
        STT_OBJECT => "\x1b[34mOBJECT\x1b[0m",
        STT_FUNC => "\x1b[32mFUNCTION\x1b[0m",
        STT_SECTION => "\x1b[31mSECTION\x1b[0m",
        STT_FILE => "\x1b[36mFILE\x1b[0m",
        STT_COMMON => "COMMON",
        STT_TLS => "\x1b[35mTLS\x1b[0m",
        STT_NUM => "NUM",
        _ => "???",
    }
}

pub fn addr_to_sym(symtab: &Symtab, addr: u64) -> Option<Sym> {
    let mut iter = symtab.iter();
    let mut curr_sym = iter.next()?;

    for sym in iter {
        if sym.st_value <= addr && sym.st_value > curr_sym.st_value {
            curr_sym = sym;
        }
    }

    if curr_sym.st_value > addr {
        None
    } else {
        Some(curr_sym)
    }
}
