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
use clap::Parser;
use goblin::Object;
use goblin::elf::Elf;
use memmap2::Mmap;
use anyhow::{anyhow, bail, Context, Result};

use crate::args::{Options, Command, SymbolsArgs};
use crate::eh::eh;
use crate::func::do_fn;
use crate::header::{header, program_headers};
use crate::print::{PairTable, print_header, SizePrint};
use crate::sections::{all_sections, one_section};
use crate::sym::all_symbols;

mod args;
mod print;
mod sections;
mod func;
mod sym;
mod header;
mod elf;
mod eh;

fn main() {
    let args = Options::parse();

    if let Err(e) = run(&args) {
        eprintln!("\x1b[1;31merror\x1b[0m: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: &Options) -> Result<()> {
    let elf_path = args.elf.clone().or_else(
        || std::env::var_os("ELF").map(|s| s.into())
    ).ok_or_else(
        || anyhow!("No ELF file provided either from the command line nor via the `ELF` env variable.")
    )?;

    let f = File::open(&elf_path)
        .with_context(||
            format!("{}: couldn't open ELF", elf_path.display())
        )?;
    let map = unsafe { Mmap::map(&f) }
        .with_context(|| format!("{}: couldn't mmap ELF", elf_path.display()))?;
    let bytes = &*map;

    let obj = Object::parse(bytes)
        .with_context(||
            format!("{}: failed to parse ELF", elf_path.display())
        )?;
    let elf = match obj {
        Object::Elf(elf) => Box::new(elf),
        _ => bail!("{}: unsupported ELF format", elf_path.display()),
    };

    match args.command.as_ref().unwrap_or(&Command::Summary) {
        Command::Summary => summary(&elf),
        Command::Header => header(&elf),
        Command::ProgramHeader => program_headers(&elf),
        Command::Sections => all_sections(&elf),
        Command::Section(opts) => one_section(&elf, bytes, opts)?,
        Command::Symbols(opts) => all_symbols(&elf, opts),
        Command::Fn(opts) => do_fn(&elf, bytes, opts)?,
        Command::Eh(opts) => eh(&elf, bytes, opts.clone())?,
        _ => todo!(),
    }

    Ok(())
}

fn summary(elf: &Elf) {
    header(elf);
    println!();
    program_headers(elf);
    println!();
    all_sections(elf);
}
