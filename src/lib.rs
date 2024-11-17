use std::collections::{BTreeSet, HashMap, HashSet};

use bstr::BString;
use byteorder::{BigEndian, ReadBytesExt};
use hex_literal::hex;
use winnow::{
    combinator::preceded,
    error::{AddContext, ContextError, ErrMode, ErrorKind, FromExternalError, StrContext},
    stream::Stream,
    token::{literal, take},
    PResult, Parser,
};

type ByteStream<'i> = &'i [u8];

fn magic_string(i: &mut ByteStream) -> PResult<()> {
    let _ = literal("REDIS").parse_next(i)?;
    Ok(())
}

fn rdb_version(i: &mut ByteStream) -> PResult<BString> {
    take(4usize).parse_next(i).map(BString::from)
}

fn header(i: &mut ByteStream) -> PResult<BString> {
    preceded(magic_string, rdb_version).parse_next(i)
}

fn auxiliary_field(i: &mut ByteStream) -> PResult<(BString, BString)> {
    preceded(literal(hex!("FA")), (string_encoded, string_encoded)).parse_next(i)
}

fn length_encoded_string_type(i: &mut ByteStream) -> PResult<StringType> {
    let first_byte = take(1usize).parse_next(i)?[0];
    let type_indicator = (0xC0 & first_byte) >> 6;

    match type_indicator {
        0 => {
            let six_bits = (0x3F & first_byte) as usize;
            Ok(StringType::Simple(six_bits))
        }
        1 => {
            let six_bits = (0x3F & first_byte) as usize;
            let second_byte = take(1usize).parse_next(i)?[0] as usize;
            let len = (six_bits << 8) | second_byte;
            Ok(StringType::Simple(len))
        }
        2 => {
            let mut four_bytes = take(4usize).parse_next(i)?;
            let sz: u32 = four_bytes
                .read_u32::<BigEndian>()
                .map_err(|e| ErrMode::from_external_error(i, ErrorKind::Verify, e))?;
            Ok(StringType::Simple(sz as usize))
        }
        3 => {
            let six_bits = 0x3F & first_byte;
            match six_bits {
                0 => Ok(StringType::I8),
                1 => Ok(StringType::I16),
                2 => Ok(StringType::I32),
                3 => Ok(StringType::LzfCompressed),
                _ => Err(ErrMode::Cut(ContextError::new()).add_context(
                    i,
                    &i.checkpoint(),
                    StrContext::Label("Unknown Special String Type"),
                )),
            }
        }
        _ => Err(ErrMode::Cut(ContextError::new()).add_context(
            i,
            &i.checkpoint(),
            StrContext::Label("Unknown Type Indicator"),
        )),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum StringType {
    Simple(usize),
    LzfCompressed,
    I8,
    I16,
    I32,
}

#[derive(Debug, Eq, PartialEq)]
enum Value {
    String(BString),
    Lists(Vec<BString>),
    Sets(HashSet<BString>),
    Hashes(HashMap<BString, Value>),
    SortedSets(BTreeSet<BString>),
    AuxiliaryField((BString, BString)),
    DatabaseSelector(BString),
}

fn string_encoded(i: &mut ByteStream) -> PResult<BString> {
    let string_type = length_encoded_string_type.parse_next(i)?;
    match string_type {
        StringType::Simple(sz) => take(sz).parse_next(i).map(BString::from),
        StringType::LzfCompressed => todo!(),
        StringType::I8 => take(1usize).parse_next(i).map(BString::from),
        StringType::I16 => take(2usize).parse_next(i).map(BString::from),
        StringType::I32 => take(4usize).parse_next(i).map(BString::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdb_magic_string_valid_success() {
        let header: [u8; 5] = hex!("52 45 44 49 53");
        let res = magic_string(&mut header.as_ref());
        assert!(res.is_ok());
    }

    #[test]
    fn rdb_version_valid_success() {
        let version_bytes: [u8; 4] = hex!("30 30 30 33");
        let res = rdb_version(&mut version_bytes.as_ref());
        assert_eq!(Ok(BString::from("0003")), res);
    }

    #[test]
    fn header_valid_returns_version() {
        let header_s = "REDIS0003";
        let res = header(&mut header_s.as_ref());
        assert_eq!(Ok(BString::from("0003")), res);
    }

    #[test]
    fn length_encoded_string_type_type_0_success() {
        let length_bytes: [u8; 1] = hex!("09");
        let res = length_encoded_string_type(&mut length_bytes.as_ref());
        assert_eq!(Ok(StringType::Simple(9)), res);
    }

    #[test]
    fn string_encoded_type_0_success() {
        let bytes = hex!("0972656469732d76657205362e322e36").to_vec();
        let mut input = bytes.as_ref(); 
        let res = string_encoded.parse_next(&mut input);
        assert_eq!(Ok(BString::from("redis-ver")), res);
        let res = string_encoded.parse_next(&mut input);
        assert_eq!(Ok(BString::from("6.2.6")), res);
    }

    #[test]
    fn auxiliary_field_string_encoded_0_success() {
        let bytes = hex!("fa0972656469732d76657205362e322e36").to_vec();
        let mut input = bytes.as_ref(); 
        let res = auxiliary_field(&mut input);
        assert_eq!(Ok((BString::from("redis-ver"), BString::from("6.2.6"))), res)
    }
}
