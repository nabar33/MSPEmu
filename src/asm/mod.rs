use std::fmt;
use std::string;
use std::convert;
use std::vec::Vec;
use std::iter::FromIterator;
use log::{info, warn};

#[allow(unused)]
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

/*
#[derive(PartialEq, Eq)]
pub enum AddressMode {
    Register,
    Indexed,
    Indirect,
    IndirectWithIncrement,
}
*/

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
    Address(u16),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op_repr = match *self {
            Self::Immediate(val)                    => format!("#0x{:04x}", val),
            Self::Address(val)                      => format!("&0x{:04x}", val),
            Self::Register(ref reg)                 => reg.to_string(),
            Self::RegisterOffset(ref reg, offset)   => format!("0x{:x}({})", offset, reg.to_string()),
            Self::RegisterIndirect(ref reg, update) => format!("@{}{}", reg.to_string(), if update {"+"} else {""})
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
    pub len: u8,
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

pub struct AddressedInstruction {
    pub addr: u16,
    pub insn: Instruction
}

type DecodeError = &'static str;

fn extract_opsize(insn_data: &u16) -> OpSize {
    if (insn_data >> 6) & 1 == 1 {
        OpSize::Byte
    } else {
        OpSize::Word
    }
}

fn extract_as_field(insn_data: &u16) -> u8 {
    let low_byte = *insn_data as u8;
    (low_byte >> 4) & 0b11
}

fn extract_ad_bit(insn_data: &u16) -> u8 {
    let low_byte = *insn_data as u8;
    low_byte >> 7
}

fn extract_dreg(insn_data: &u16) -> Reg {
    let low_byte = *insn_data as u8;
    Reg(low_byte & 0xf)
}

fn extract_sreg(insn_data: &u16) -> Reg {
    let high_byte = (*insn_data >> 8) as u8;
    Reg(high_byte & 0xf)
}

fn decode_reg_with_ad_bit<'a, T>(reg: Reg, bits: u8, op_data: &mut T) -> Result<(Operand, bool), DecodeError> where
    T: Iterator<Item=&'a u16>
{
    match bits {
        0 => Ok((Operand::Register(reg), false)),
        1 => {
            if let Some(&offset) = op_data.next() {
                if let Reg(2) = reg {
                    info!("consumed inline immediate for absolute address: 0x{:04x}", offset);
                    Ok((Operand::Address(offset), true))
                } else {
                    info!("consumed inline immediate for register+offset: 0x{:04x}", offset);
                    Ok((Operand::RegisterOffset(reg, offset), true))
                }
            } else {
                Err("dst operand decoded to RegisterOffset type but not enough data in buffer")
            }
        }
        _ => Err("bits argument other value besides 0 or 1")
    }
}

fn decode_reg_with_as_field<'a, T>(reg: Reg, bits: u8, op_data: &mut T) -> Result<(Operand, bool), DecodeError> where
    T: Iterator<Item=&'a u16>
{
    match reg {
        Reg(2) => {
            info!("SR reg operand with bits: {:02b}", bits);
            match bits {
                0b00 => Ok((Operand::Register(reg), false)),
                0b01 => {
                    if let Some(&addr) = op_data.next() {
                        info!("consumed inline immediate for absolute address: 0x{:04x}", addr);
                        Ok((Operand::Address(addr), true))
                    } else {
                        Err("src operand decoded to Address type but not enough data in buffer")
                    }
                },
                0b10 => Ok((Operand::Immediate(4), false)),
                0b11 => Ok((Operand::Immediate(8), false)),
                _    => Err("extract_as_field() no longer returning values in 0..4")
            }
        }
        Reg(3) => {
            info!("CG reg operand");
            match bits {
                0b11      => Ok((Operand::Immediate(0xffff_u16), false)),
                n @ 0..=2 => Ok((Operand::Immediate(n.into()), false)),
                _         => Err("extract_as_field() no longer returning values in 0..4")
            }
        }
        _ => {
            info!("{:?} operand", reg);
            match bits {
                0b00 => Ok((Operand::Register(reg), false)),
                0b01 => {
                    if let Some(&offset) = op_data.next() {
                        info!("consumed inline immediate for register+offset: 0x{:04x}", offset);
                        Ok((Operand::RegisterOffset(reg, offset), true))
                    } else {
                        Err("src operand decoded to RegisterOffset type but not enough data in buffer")
                    }
                },
                _    => {
                    if let Reg(0) = reg {
                        if let Some(&value) = op_data.next() {
                            info!("consumed inline immediate value by PC ref: 0x{:04x}", value);
                            Ok((Operand::Immediate(value), true))
                        } else {
                            Err("src operand decoded to RegisterOffset type but not enough data in buffer")
                        }
                    } else { // as_bits == 0b10 || 0b11
                        Ok((Operand::RegisterIndirect(reg, bits & 1 == 1), false))
                    }
                }
            }
        }
    }
}

fn decode_dst_operand<'a, T>(insn_data: &u16, op_data: &mut T) -> Result<(Operand, bool), DecodeError> where
    T: Iterator<Item=&'a u16> 
{
    info!("Decoding dest operand");
    let reg = extract_dreg(insn_data);
    decode_reg_with_ad_bit(reg, extract_ad_bit(insn_data), op_data)
}

fn decode_src_operand<'a, T>(insn_data: &u16, op_data: &mut T) -> Result<(Operand, bool), DecodeError> where
    T: Iterator<Item=&'a u16> 
{
    info!("Decoding src operand");
    let reg = extract_sreg(insn_data);
    decode_reg_with_as_field(reg, extract_as_field(insn_data), op_data)
}

fn decode_unary_operand<'a, T>(insn_data: &u16, op_data: &mut T) -> Result<(Operand, bool), DecodeError> where 
    T: Iterator<Item=&'a u16>
{
    info!("Decoding unary operand");
    let reg = extract_dreg(insn_data);
    decode_reg_with_as_field(reg, extract_as_field(insn_data), op_data)
}

fn decode_single_op_iform<'a, T>(insn_data: &u16, op_data: &mut T) -> Result<Instruction, DecodeError> where
    T: Iterator<Item=&'a u16>
{
    let mnem = match insn_data >> 7 {
        32 => Ok(Mnemonic::RRC),
        33 => Ok(Mnemonic::SWPB),
        34 => Ok(Mnemonic::RRA),
        35 => Ok(Mnemonic::SXT),
        36 => Ok(Mnemonic::PUSH),
        37 => Ok(Mnemonic::CALL),
        38 => Ok(Mnemonic::RETI),
        _ => Err("undefined single op iform instruction was decoded")
    }?;

    let (operand, extended) = decode_unary_operand(insn_data, op_data)?;

    Ok(
        Instruction{
            mnem: mnem,
            len: if extended {4} else {2},
            width: extract_opsize(insn_data),
            ops: OpForm::Single(operand),
        }
    )
}

fn decode_double_op_iform<'a, T>(insn_data: &u16, op_data: &mut T) -> Result<Instruction, DecodeError> where 
    T: Iterator<Item=&'a u16>
{
    let mut len: u8 = 2;
    
    let mnem = match insn_data >> 12 {
        4  => Ok(Mnemonic::MOV),
        5  => Ok(Mnemonic::ADD),
        6  => Ok(Mnemonic::ADDC),
        7  => Ok(Mnemonic::SUBC),
        8  => Ok(Mnemonic::SUB),
        9  => Ok(Mnemonic::CMP),
        10 => Ok(Mnemonic::DADD),
        11 => Ok(Mnemonic::BIT),
        12 => Ok(Mnemonic::BIC),
        13 => Ok(Mnemonic::BIS),
        14 => Ok(Mnemonic::XOR),
        15 => Ok(Mnemonic::AND),
        _  => Err("attempted to decode non-double op iform as double op")
    }?;

    let (src_operand, src_extended) = decode_src_operand(insn_data, op_data)?;
    let (dst_operand, dst_extended) = decode_dst_operand(insn_data, op_data)?;

    if src_extended { len += 2 };
    if dst_extended { len += 2 };

    Ok(
        Instruction {
            mnem: mnem,
            len: len,
            width: extract_opsize(insn_data),
            ops: OpForm::Double(src_operand, dst_operand)
        }
    )
}
fn decode_jump_iform(insn_data: &u16) -> Result<Instruction, DecodeError> {
    let mnem = match insn_data >> 10 {
        8  => Ok(Mnemonic::JNE),
        9  => Ok(Mnemonic::JEQ),
        10 => Ok(Mnemonic::JNC),
        11 => Ok(Mnemonic::JC),
        12 => Ok(Mnemonic::JN),
        13 => Ok(Mnemonic::JGE),
        14 => Ok(Mnemonic::JL),
        15 => Ok(Mnemonic::JMP),
        _ => Err("attempted to decode non-jump iform according to jump iform")
    }?;
    let offset = {
        let raw_offset = insn_data & 0x3ff;
        if raw_offset > 512 {
            (0x400 - raw_offset) * 2 
        } else {
            raw_offset * 2
        }
    };

    Ok(
        Instruction{
            mnem: mnem,
            len: 2,
            width: OpSize::Word,
            ops: OpForm::Target(Operand::Immediate(offset)),
        }
    )
}

fn decode_insn<'a, T>(data: &mut T) -> Result<Instruction, DecodeError> where 
    T: Iterator<Item=&'a u16>
{
    let insn_word = data.next().ok_or("Not enough instruction data in buffer")?;
    info!("Decoding instruction from buffer");
    match insn_word >> 13 {
        0 => decode_single_op_iform(&insn_word, data),
        1 => decode_jump_iform(&insn_word),
        _ => decode_double_op_iform(&insn_word, data),
    }
}

impl convert::TryFrom<&[u16]> for Instruction {
    type Error = DecodeError;

    fn try_from(buf: &[u16]) -> Result<Self, Self::Error> {
        let mut stream = buf.iter();
        decode_insn(&mut stream)
    }
}

impl convert::TryFrom<&[u8]> for Instruction {
    type Error = DecodeError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Instruction::try_from(
            Vec::<u16>::from_iter(
                buf.chunks_exact(2)
                   .map(|chunk| u16::from_le_bytes(<[u8; 2]>::try_from(chunk).unwrap()))
            ).as_slice()
        )
    }
}

pub fn disassemble<'a, T>(data: &mut T, base_addr: u16) -> Vec<AddressedInstruction> where
    T: Iterator<Item=&'a u16>
{
    let mut instructions = Vec::<AddressedInstruction>::new();
    let mut addr = base_addr;
    while let Ok(insn) = decode_insn(data) {
        info!("disassembled instruction at 0x{:04x}", addr);
        let shift = insn.len as u16;
        instructions.push(AddressedInstruction{addr: addr, insn: insn});
        addr += shift;
    }
    instructions
}

pub fn disassemble_bytes<'a, T>(data: &mut T, base_addr: u16) -> Vec<AddressedInstruction> where
    T: Iterator<Item=&'a u8>
{
    let mut insn_words = 
        data
            .fold(
                (Vec::new(), None), 
                |mut acc: (Vec<u16>, Option<&'a u8>), byte| 
                    if let Some(&low_byte) = acc.1 {
                        let high_byte: u16 = (*byte).into();
                        acc.0.push((high_byte << 8) | (low_byte as u16));
                        (acc.0, None)
                    } else {
                        (acc.0, Some(byte))
                    }
            ).0;
    disassemble(
        &mut insn_words.iter(),
        base_addr
    )
}