use std::convert::TryFrom;
use log;

use mspemu::asm::{
    Instruction,
    Mnemonic, 
    Operand,
    OpForm,
    OpSize,
    Reg,
};


#[allow(unused)]
#[allow(dead_code)]
fn main() {
    env_logger::init();

    let insn = Instruction {
        mnem: Mnemonic::ADD,
        len: 2,
        width: OpSize::Word,
        ops: OpForm::Double(Operand::Register(Reg(8)), Operand::RegisterIndirect(Reg(4), true))
    };
    
    let buffer: &[u16] = &[0xf375];
    let buffer2: &[u16] = &[0x403f, 0x0008];
    let buffer3: &[u16] = &[0x12b0, 0x4558];
    let buffer4: &[u8] = &[0x3f, 0x40, 0x08, 0x00];
    if let Ok(insn2) = Instruction::try_from(buffer4) {
        println!("Hello, decoded insn: {}", insn2)
    };

}
