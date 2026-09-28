// SPDX-License-Identifier: Apache-2.0
//
// `lockshell mask check|apply|restore`: mask sensitive text locally.

use crate::cli::{MaskArgs, MaskCommand};
use crate::mask::{default_allowlist_path, default_terms_path, Mapping, Masker};
use anyhow::Result;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

fn read_input(file: &Option<String>) -> Result<String> {
    match file.as_deref() {
        None | Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s)
        }
        // Lossy on purpose: broken UTF-8 (common in ASR output) must still be scanned.
        Some(p) => Ok(String::from_utf8_lossy(&fs::read(p)?).into_owned()),
    }
}

pub fn run(args: MaskArgs) -> Result<()> {
    let masker = Masker::load(&default_terms_path(), &default_allowlist_path())?;
    match args.command {
        MaskCommand::Check { file } => {
            let found = masker.findings(&read_input(&file)?);
            if found.is_empty() {
                println!("clean");
            } else {
                println!("{}", serde_json::to_string(&found)?);
                std::process::exit(1);
            }
        }
        MaskCommand::Apply { file, map } => {
            let mut mapping = Mapping::default();
            let out = masker.mask(&read_input(&file)?, &mut mapping);
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&map)?;
            f.write_all(serde_json::to_string_pretty(&mapping.forward)?.as_bytes())?;
            print!("{out}");
        }
        MaskCommand::Restore { file, map } => {
            let mut mapping = Mapping::default();
            mapping.forward = serde_json::from_str(&fs::read_to_string(&map)?)?;
            print!("{}", Masker::unmask(&read_input(&file)?, &mapping));
        }
    }
    Ok(())
}
