// SPDX-License-Identifier: Apache-2.0

use nu_ansi_term::Color::{Cyan, Green, Red, Yellow};
use std::io::IsTerminal;

fn color_enabled() -> bool {
    std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err()
}

pub fn ok(msg: &str) {
    if color_enabled() {
        println!("{} {}", Green.bold().paint("✓"), msg);
    } else {
        println!("[ok] {}", msg);
    }
}

pub fn warn(msg: &str) {
    if color_enabled() {
        println!("{} {}", Yellow.bold().paint("!"), msg);
    } else {
        println!("[warn] {}", msg);
    }
}

pub fn err(msg: &str) {
    if color_enabled() {
        eprintln!("{} {}", Red.bold().paint("✗"), msg);
    } else {
        eprintln!("[error] {}", msg);
    }
}

pub fn info(msg: &str) {
    if color_enabled() {
        println!("{} {}", Cyan.paint("→"), msg);
    } else {
        println!("[info] {}", msg);
    }
}

pub fn hint(msg: &str) {
    if color_enabled() {
        println!("  {}", nu_ansi_term::Style::new().dimmed().paint(msg));
    } else {
        println!("    {}", msg);
    }
}
