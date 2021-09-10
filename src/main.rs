use std::convert::TryFrom;

mod asm;

use asm::*;

#[allow(unused)]
#[allow(dead_code)]
fn main() {
    let insn = Instruction {
        mnem: Mnemonic::ADD,
        width: OpSize::Word,
        ops: OpForm::Double(Operand::Register(Reg(8)), Operand::RegisterIndirect(Reg(4), true))
    };
    
    let buffer: &[u16] = &[0xf375];
    let buffer2: &[u16] = &[0x403f, 0x0008];
    if let Ok(insn2) = Instruction::try_from(buffer2) {
        println!("Hello, decoded insn: {}", insn2)
    };

}
