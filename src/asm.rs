use std::fmt;
use std::string;
use std::convert;

#[derive(Debug)]
pub enum Mnemonic {
    MOV,
    ADD,
    ADDC,
    SUB,
    SUBC,
    CMP,
    DADD,
    BIT,
    BIC,
    BIS,
    XOR,
    AND,
    RRC,
    RRA,
    PUSH,
    SWPB,
    CALL,
    RETI,
    SXT,
    JEQ,
    JNE,
    JC,
    JNC,
    JN,
    JGE,
    JL,
    JMP
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnem = format!("{:?}", self);
        f.pad(mnem.as_str())
    }
}

#[derive(PartialEq, Eq)]
pub enum AddressMode {
    Register,
    Indexed,
    Indirect,
    IndirectWithIncrement,
}

#[derive(Debug)]
pub struct Reg(pub u8);

impl string::ToString for Reg {
    fn to_string(&self) -> string::String {
        match *self {
            Self(0)            => String::from("PC"),
            Self(1)            => String::from("SP"),
            Self(2)            => String::from("SR"),
            Self(n) if n < 16  => format!("R{}", n),
            _                  => String::from("_BADREG_")
        }
    }
}

#[derive(Debug)]
pub enum Operand {
    Register(Reg),
    RegisterOffset(Reg, u16),
    RegisterIndirect(Reg, bool),
    Immediate(u16),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op_repr = match *self {
            Self::Immediate(val) => format!("#0x{:04x}", val),
            Self::Register(ref reg)  => reg.to_string(),
            Self::RegisterOffset(ref reg, offset)  => format!("0x{:x}({})", offset, reg.to_string()),
            Self::RegisterIndirect(ref reg, update)  => format!("@{}{}", reg.to_string(), if update {"+"} else {""})
        };
        write!(f, "{}", op_repr.as_str())
    }
}

#[derive(Debug)]
pub enum OpSize {
    Byte = 1,
    Word = 2
}

#[derive(Debug)]
pub enum OpForm {
    Single(Operand),
    Double(Operand, Operand),
    Target(Operand),
}

#[derive(Debug)]
pub struct Instruction {
    pub mnem: Mnemonic,
    pub width: OpSize,
    pub ops: OpForm,
}

impl Instruction {
    fn fq_mnem(&self) -> String {
        let mut repr = String::from(self.mnem.to_string());
        if let OpSize::Byte = self.width {
            match self.mnem {
                Mnemonic::MOV
                | Mnemonic::ADD
                | Mnemonic::ADDC
                | Mnemonic::SUB
                | Mnemonic::SUBC
                | Mnemonic::CMP
                | Mnemonic::DADD
                | Mnemonic::BIT
                | Mnemonic::BIC
                | Mnemonic::BIS
                | Mnemonic::XOR
                | Mnemonic::AND
                | Mnemonic::RRC
                | Mnemonic::RRA
                | Mnemonic::PUSH => repr.push_str(".B"),
                _ => ()
            }
        }
        repr
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self{ops: OpForm::Double(src, dst), ..} => format!("{:8}{}, {}", self.fq_mnem(), src, dst),
            Self{ops: OpForm::Single(dst), ..}      => format!("{:8}{}", self.fq_mnem(), dst), 
            Self{ops: OpForm::Target(dst), ..}      => format!("{:8}{}", self.mnem, dst), 
        })
    }
}

fn decode_opsize_bit(insn_data: &u16) -> OpSize {
    if (insn_data >> 6) & 1 == 1 {
        OpSize::Byte
    } else {
        OpSize::Word
    }
}

fn decode_as_field(insn_data: &u16) -> u8 {
    let low_byte = *insn_data as u8;
    (low_byte >> 4) & 0b11
}

fn decode_ad_bit(insn_data: &u16) -> u8 {
    let low_byte = *insn_data as u8;
    low_byte >> 7
}

fn decode_dreg(insn_data: &u16) -> Reg {
    let low_byte = *insn_data as u8;
    Reg(low_byte & 0xf)
}

fn decode_sreg(insn_data: &u16) -> Reg {
    let high_byte = (*insn_data >> 8) as u8;
    Reg(high_byte & 0xf)
}

fn decode_dst_operand(insn_data: &u16, op_data: &[u16]) -> Option<Operand> {
    let reg = decode_dreg(insn_data);
    match decode_ad_bit(insn_data) {
        0 => Some(Operand::Register(reg)),
        1 => {
            if let Some(offset) = op_data.first() {
                Some(Operand::RegisterOffset(reg, *offset))
            } else {
                None
            }
        }
        _ => None
    }
}

fn decode_src_operand(insn_data: &u16, op_data: &[u16]) -> Option<Operand> {
    let reg = decode_sreg(insn_data);
    let as_bits = decode_as_field(insn_data);
    match reg {
        Reg(2) => {
            match as_bits {
                0b00 => Some(Operand::Register(reg)),
                0b01 => Some(Operand::Immediate(0)),  // Is this right?
                0b10 => Some(Operand::Immediate(4)),
                0b11 => Some(Operand::Immediate(8)),
                _    => None
            }
        }
        Reg(3) => {
            match as_bits {
                0b11      => Some(Operand::Immediate(0xffff_u16)),
                n @ 0..=2 => Some(Operand::Immediate(n.into())),
                _         => None
            }
        }
        _ => {
            match as_bits {
                0b00 => Some(Operand::Register(reg)),
                0b01 => {
                    if let Some(offset) = op_data.first() {
                        Some(Operand::RegisterOffset(reg, *offset))
                    } else {
                        None
                    }
                },
                _    => {
                    if let Reg(0) = reg {
                        if let Some(value) = op_data.first() {
                            Some(Operand::Immediate(*value))
                        } else {
                            None
                        }
                    } else { // as_bits == 0b10 || 0b11
                        Some(Operand::RegisterIndirect(reg, as_bits & 1 == 1))
                    }
                }
            }
        }
    }
}

fn decode_single_op_iform(insn_data: &u16, _op_data: &[u16]) -> Result<Instruction, &'static str> {
    let _opcode = insn_data >> 7;
    Err("Unimplemented")
}
fn decode_double_op_iform(insn_data: &u16, op_data: &[u16]) -> Result<Instruction, &'static str> {
    let opcode = insn_data >> 12;
    if opcode < 4 || opcode > 15 {
        return Err("attempted to decode non-double op iform as double op")
    };
    
    let mnem = match opcode {
        4  => Mnemonic::MOV,
        5  => Mnemonic::ADD,
        6  => Mnemonic::ADDC,
        7  => Mnemonic::SUBC,
        8  => Mnemonic::SUB,
        9  => Mnemonic::CMP,
        10 => Mnemonic::DADD,
        11 => Mnemonic::BIT,
        12 => Mnemonic::BIC,
        13 => Mnemonic::BIS,
        14 => Mnemonic::XOR,
        15 => Mnemonic::AND,
        _  => unreachable!()
    };

    if let Some(src_operand) = decode_src_operand(insn_data, op_data) {
        let dst_op_data = match src_operand {
            Operand::RegisterOffset(..) => {
                if let Some((_, tail)) = op_data.split_first() {
                    tail
                } else {
                    op_data
                }
            },
            _ => op_data
        };

        if let Some(dst_operand) = decode_dst_operand(insn_data, dst_op_data) {

            Ok(
                Instruction {
                    mnem: mnem,
                    width: decode_opsize_bit(insn_data),
                    ops: OpForm::Double(src_operand, dst_operand)
                }
            )

        } else {
            return Err("dst operand failed to decode")
        }
    } else {
        return Err("src operand failed to decode")
    }

}
fn decode_jump_iform(insn_data: &u16, _op_data: &[u16]) -> Result<Instruction, &'static str> {
    let _opcode = insn_data >> 10;
    Err("Unimplemented")
}

impl convert::TryFrom<&[u16]> for Instruction {
    type Error = &'static str;

    fn try_from(buf: &[u16]) -> Result<Self, Self::Error> {
        if let Some((idata, remainder)) = buf.split_first() {
            let iform_code = idata >> 13; // get top 3 bits to determine iform
            match iform_code {
                0 => decode_single_op_iform(idata, remainder),
                1 => decode_jump_iform(idata, remainder),
                _ => decode_double_op_iform(idata, remainder)
            }
        } else {
            Err("Not enough instruction data in buffer")
        }
    }
}