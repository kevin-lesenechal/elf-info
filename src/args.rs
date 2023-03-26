/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};
use regex::Regex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Options {
    #[arg()]
    pub elf: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Give a brief summary of the ELF: file header, program headers, and
    /// sections' header.
    Summary,

    /// Display information in ELF's header.
    Header,

    /// List all program headers.
    ProgramHeader,

    /// List all sections.
    Sections,

    /// Display detailed information of one specific section, including its
    /// content. The formatting used depends on the type of section.
    Section(SectionArgs),

    /// List all symbols.
    Symbols(SymbolsArgs),

    /// Disassemble a function.
    Fn(FnArgs),

    /// List all relocation entries.
    Relocations,

    /// Display call frame information for exception handling.
    Eh(EhArgs),
}

#[derive(Args, Debug)]
pub struct SymbolsArgs {
    #[arg(long)]
    pub no_demangle: bool,

    /// Display dynamic symbols.
    #[arg(short = 'd', long)]
    pub dynamic: bool,

    /// Try to filter out symbols generated for the Rust's standard, core, and
    /// alloc libraries.
    #[arg(long)]
    pub no_rust_std: bool,

    /// Only show symbols that matches a PCRE regex.
    #[arg(short = 'f', long)]
    pub filter: Option<Regex>,
}

#[derive(Args, Debug)]
pub struct SectionArgs {
    /// The section name, starting with a period.
    #[arg()]
    pub name: String,

    /// Write the entire section's content into a file.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Always display the content has a hexdump, regardless of the section's
    /// type.
    #[arg(long, short = 'x')]
    pub hexdump: bool,

    /// The maximum number of bytes to export or dump as hexdump.
    #[arg(short = 'n', long)]
    pub size: Option<usize>,

    /// A number of bytes to skip for export or hexdump.
    #[arg(short = 's', long)]
    pub skip: Option<usize>,
}

#[derive(Args, Debug)]
pub struct FnArgs {
    #[arg()]
    pub name: String,
}

#[derive(Args, Debug, Clone, Default)]
pub struct EhArgs {
    /// A specific section name to parse for call frame information entries.
    /// If none is specified, elf-info will look for a `.eh_frame` section, or
    /// `.debug_frame` section.
    #[arg(long)]
    pub section: Option<String>,

    /// Only display FDEs that contains the address of this symbol.
    #[arg(long, short = 's')]
    pub symbol: Option<String>,

    /// Only display FDEs that contains this address.
    #[arg(long)]
    pub address: Option<u64>,
}
