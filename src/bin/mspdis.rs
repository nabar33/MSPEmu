use std::fs::{self, File};
use std::io::prelude::*;
use std::path::Path;
use std::convert::From;
use std::vec::Vec;
use log;

extern crate clap;
use clap::{Arg, App};

use mspemu::asm::disassemble_bytes;

fn main() {
    env_logger::init();
    let matches = App::new("MSP430 Disassembler")
                    .version("0.1")
                    .about("simple MSP430 disassembler for raw bytes")
                    .arg(Arg::with_name("file")
                        .short("f")
                        .long("file")
                        .help("disassemble the given file")
                        .value_name("FILE"))
                    .get_matches();
    
    if let Some(filename) = matches.value_of("file") {
        let path = Path::new(filename);
        let data = match fs::read(&path) {
            Ok(buffer) => buffer,
            Err(why) => panic!("could not open {}: {}", path.display(), why),
        };

        for insn in disassemble_bytes(&mut data.iter(), 0x1000_u16) {
            println!("0x{:04x} : {}", insn.addr, insn.insn);
        }
    } else {
        println!("you didn't give a file... :(");
    }
}
