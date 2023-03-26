/******************************************************************************
 * Copyright © 2023 Kévin Lesénéchal <kevin.lesenechal@gmail.com>             *
 * This file is part of the elf-info CLI tool.                                *
 *                                                                            *
 * elf-info is free software; you can redistribute it and/or modify it under  *
 * the terms of the GNU General Public License as published by the Free       *
 * Software Foundation; either version 3 of the License, or (at your option)  *
 * any later version. See LICENSE file for more information.                  *
 ******************************************************************************/

use std::fmt::{Display, Formatter};
use goblin::container::Container;

pub fn print_header(name: &str) {
    print!("\x1b[1;96m───┤ {name} ├");
    println!("{:─<w$}\x1b[0m", "", w = 70 - name.len());
}

pub struct PairTable(pub usize);

impl PairTable {
    pub fn field(&self, name: &str) {
        print!("\x1b[37m{name:>w$}\x1b[0m │ ", w = self.0);
    }
}

#[derive(Copy, Clone)]
pub struct SizePrint {
    size: Container,
}

impl SizePrint {
    pub fn new(size: Container) -> Self {
        Self { size }
    }

    pub fn hex(&self, value: u64) -> SizePrintHex {
        SizePrintHex { size: self.size, value }
    }
}

pub struct SizePrintHex {
    size: Container,
    value: u64,
}

impl Display for SizePrintHex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.size {
            Container::Little => {
                write!(f, "0x{:04x}", &(self.value >> 16))?;
                write!(f, "'")?;
                write!(f, "{:04x}", &(self.value & 0xffff))
            },
            Container::Big => {
                write!(f, "0x{:08x}", &(self.value >> 32))?;
                write!(f, "'")?;
                write!(f, "{:08x}", &(self.value & 0xffffffff))
            },
        }
    }
}

pub struct BinSize(pub u64);

impl Display for BinSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let size;
        let unit;

        if self.0 < 1024 {
            size = self.0 as f64;
            unit = "B";
        } else if self.0 < 1024 * 1024 {
            size = self.0 as f64 / 1024.0;
            unit = "KiB";
        } else if self.0 < 1024 * 1024 * 1024 {
            size = self.0 as f64 / 1024.0 / 1024.0;
            unit = "MiB";
        } else {
            size = self.0 as f64 / 1024.0 / 1024.0 / 1024.0;
            unit = "GiB";
        }

        let w = f.width().unwrap_or(0);
        let uw = if w == 0 { unit.len() } else { 3 };
        let nw = w.saturating_sub(uw + 1);

        if unit == "B" {
            write!(f, "{:nw$} {:<uw$}", size, unit)
        } else {
            write!(f, "{:nw$.2} {:<uw$}", size, unit)
        }
    }
}

pub fn hexdump(data: &[u8]) {
    hexdump_off(data, 0);
}

pub fn hexdump_off(data: &[u8], off: usize) {
    for start in (off..data.len()).into_iter().step_by(16) {
        print!("\x1b[97m{start:8x} │\x1b[0m ");

        for i in start..(start + 16) {
            if i % 8 == 0 && i % 16 != 0 {
                print!(" \x1b[97m│\x1b[0m");
            }
            if i < data.len() {
                print!(" {:02x}", data[i]);
            } else {
                print!("   ");
            }
        }

        print!("  \x1b[97m│\x1b[0m");

        for i in start..(start + 16) {
            if i % 8 == 0 && i % 16 != 0 {
                print!("\x1b[97m│\x1b[0m");
            }
            if i < data.len() {
                let b = data[i];
                if b >= b' ' && b <= b'~' {
                    print!("{}", b as char);
                } else {
                    print!("\x1b[90m╳\x1b[0m");
                }
            } else {
                print!("\x1b[90m─\x1b[0m");
            }
        }

        print!("\x1b[97m│\x1b[0m\n");
    }
}
