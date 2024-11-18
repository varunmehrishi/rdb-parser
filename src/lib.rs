use std::{
    collections::{BTreeSet, HashMap, HashSet},
    time::Duration,
};

use bstr::BString;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use hex_literal::hex;
use winnow::{
    binary::{le_i16, le_i32, le_i64, le_u32},
    combinator::{alt, preceded},
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

fn header(i: &mut ByteStream) -> PResult<Construct> {
    preceded(magic_string, rdb_version)
        .parse_next(i)
        .map(Construct::Header)
}

fn auxiliary_field(i: &mut ByteStream) -> PResult<Construct> {
    preceded(literal(hex!("FA")), (string_encoded, string_encoded))
        .parse_next(i)
        .map(|(k, v)| Construct::AuxiliaryField(k, v))
}

fn database_selector(i: &mut ByteStream) -> PResult<Construct> {
    preceded(literal(hex!("FE")), length_encoded_int)
        .parse_next(i)
        .map(Construct::DatabaseSelector)
}

fn resize_db(i: &mut ByteStream) -> PResult<Construct> {
    preceded(
        literal(hex!("FB")),
        (length_encoded_int, length_encoded_int),
    )
    .parse_next(i)
    .map(|(hash_table_size, expire_table_size)| {
        Construct::ResizeDbField(hash_table_size, expire_table_size)
    })
}

fn eof(i: &mut ByteStream) -> PResult<Construct> {
    literal(hex!("FF")).parse_next(i).map(|_| Construct::Eof)
}

fn constructs(i: &mut ByteStream) -> PResult<Construct> {
    alt((
        header,
        auxiliary_field,
        database_selector,
        resize_db,
        entry,
        eof,
    ))
    .parse_next(i)
}

pub fn parse(i: &mut ByteStream) -> anyhow::Result<Vec<Construct>> {
    let mut elements = Vec::new();

    while let Ok(construct) = constructs.parse_next(i) {
        println!("{construct:?}");
        elements.push(construct);
    }

    Ok(elements)
}

fn length_encoded_type(i: &mut ByteStream) -> PResult<LengthEncodedType> {
    let first_byte = take(1usize).parse_next(i)?[0];
    let type_indicator = (0xC0 & first_byte) >> 6;

    match type_indicator {
        0 => {
            let six_bits = (0x3F & first_byte) as usize;
            Ok(LengthEncodedType::Simple(six_bits))
        }
        1 => {
            let six_bits = (0x3F & first_byte) as usize;
            let second_byte = take(1usize).parse_next(i)?[0] as usize;
            let len = (six_bits << 8) | second_byte;
            Ok(LengthEncodedType::Simple(len))
        }
        2 => match first_byte & 0x0F {
            0 => {
                // 0x80
                let mut four_bytes = take(4usize).parse_next(i)?;
                let sz: u32 = four_bytes
                    .read_u32::<BigEndian>()
                    .map_err(|e| ErrMode::from_external_error(i, ErrorKind::Verify, e))?;
                Ok(LengthEncodedType::Simple(sz as usize))
            }
            1 => {
                // 0X81
                let mut eight_bytes = take(8usize).parse_next(i)?;
                let sz: u64 = eight_bytes
                    .read_u64::<BigEndian>()
                    .map_err(|e| ErrMode::from_external_error(i, ErrorKind::Verify, e))?;
                Ok(LengthEncodedType::Simple(sz as usize))
            }
            _ => Err(ErrMode::Cut(ContextError::new()).add_context(
                i,
                &i.checkpoint(),
                StrContext::Label("unknown int len format with type 2"),
            )),
        },
        3 => {
            let six_bits = 0x3F & first_byte;
            match six_bits {
                0 => Ok(LengthEncodedType::I8),
                1 => Ok(LengthEncodedType::I16),
                2 => Ok(LengthEncodedType::I32),
                3 => Ok(LengthEncodedType::LzfCompressed),
                _ => Err(ErrMode::Cut(ContextError::new()).add_context(
                    i,
                    &i.checkpoint(),
                    StrContext::Label("unkown special string type"),
                )),
            }
        }
        _ => Err(ErrMode::Cut(ContextError::new()).add_context(
            i,
            &i.checkpoint(),
            StrContext::Label("unknown type indicator"),
        )),
    }
}

fn length_encoded_int(i: &mut ByteStream) -> PResult<usize> {
    if let LengthEncodedType::Simple(sz) = length_encoded_type.parse_next(i)? {
        Ok(sz)
    } else {
        Err(ErrMode::Cut(ContextError::new()).add_context(
            i,
            &i.checkpoint(),
            StrContext::Label("length encoded int was not a simple type"),
        ))
    }
}

fn expiry_seconds(i: &mut ByteStream) -> PResult<Duration> {
    preceded(literal(hex!("FD")), take(4usize))
        .parse_next(i)
        .map(LittleEndian::read_u32) // Redis stores Timestamps as little endian.
        .map(|seconds| seconds as u64)
        .map(Duration::from_secs)
}

fn expiry_milliseconds(i: &mut ByteStream) -> PResult<Duration> {
    preceded(literal(hex!("FC")), take(8usize))
        .parse_next(i)
        .map(LittleEndian::read_u64) // Redis stores Timestamps as little endian.
        .map(Duration::from_millis)
}

fn value_type(i: &mut ByteStream) -> PResult<ValueEncoding> {
    use ValueEncoding::*;
    let first_byte = take(1usize).parse_next(i)?[0];
    match first_byte {
        0 => Ok(String),
        1 => Ok(List),
        2 => Ok(Set),
        3 => Ok(SortedSet),
        4 => Ok(Hash),
        9 => Ok(ZipMap),
        10 => Ok(ZipList),
        11 => Ok(IntSet),
        12 => Ok(SortedSetInZipList),
        13 => Ok(HashMapInZipList),
        14 => Ok(ListInQuickList),
        _ => Err(ErrMode::Cut(ContextError::new()).add_context(
            i,
            &i.checkpoint(),
            StrContext::Label("length encoded int was not a simple type"),
        )),
    }
}

fn int_set(i: &mut ByteStream) -> PResult<Vec<BString>> {
    let string_encoded_int_set = string_encoded.parse_next(i)?;
    let mut bytes: &[u8] = string_encoded_int_set.as_ref();

    let (encoding, size) = (le_u32, le_u32).parse_next(&mut bytes)?;
    let mut v = Vec::with_capacity(size as usize);

    match encoding {
        2 => {
            for _ in 0..size {
                let num = le_i16.parse_next(&mut bytes)?;
                v.push(BString::from(format!("{num}")));
            }
        }
        4 => {
            for _ in 0..size {
                let num = le_i32.parse_next(&mut bytes)?;
                v.push(BString::from(format!("{num}")));
            }
        }
        8 => {
            for _ in 0..size {
                let num = le_i64.parse_next(&mut bytes)?;
                v.push(BString::from(format!("{num}")));
            }
        }
        _ => {
            return Err(ErrMode::Cut(ContextError::new()).add_context(
                i,
                &i.checkpoint(),
                StrContext::Label("Unknown intset encoding"),
            ))
        }
    };

    Ok(v)
}

#[derive(Debug, Eq, PartialEq)]
enum ValueEncoding {
    String,
    List,
    Set,
    SortedSet,
    Hash,
    ZipMap,
    ZipList,
    IntSet,
    SortedSetInZipList,
    HashMapInZipList,
    ListInQuickList,
}

#[derive(Debug, Eq, PartialEq)]
enum LengthEncodedType {
    Simple(usize),
    LzfCompressed,
    I8,
    I16,
    I32,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Value {
    String(BString),
    List(Vec<BString>),
    Set(HashSet<BString>),
    Hash(HashMap<BString, BString>),
    SortedSet(BTreeSet<BString>),
}

#[derive(Debug, Eq, PartialEq)]
pub enum Construct {
    Header(BString),
    AuxiliaryField(BString, BString),
    DatabaseSelector(usize),
    ResizeDbField(usize, usize),
    Entry(BString, Value, Option<Duration>),
    Eof,
}

fn string_encoded(i: &mut ByteStream) -> PResult<BString> {
    let string_type = length_encoded_type.parse_next(i)?;
    match string_type {
        LengthEncodedType::Simple(sz) => take(sz).parse_next(i).map(BString::from),
        LengthEncodedType::LzfCompressed => todo!("LZFCompressed"),
        LengthEncodedType::I8 => take(1usize).parse_next(i).map(BString::from),
        LengthEncodedType::I16 => take(2usize).parse_next(i).map(BString::from),
        LengthEncodedType::I32 => take(4usize).parse_next(i).map(BString::from),
    }
}

fn entry(i: &mut ByteStream) -> PResult<Construct> {
    alt((milliseconds_ttl_entry, seconds_ttl_entry, simple_entry)).parse_next(i)
}

fn simple_entry(i: &mut ByteStream) -> PResult<Construct> {
    key_value
        .parse_next(i)
        .map(|(k, v)| Construct::Entry(k, v, None))
}

fn seconds_ttl_entry(i: &mut ByteStream) -> PResult<Construct> {
    (expiry_seconds, key_value)
        .parse_next(i)
        .map(|(ttl, (k, v))| Construct::Entry(k, v, Some(ttl)))
}

fn milliseconds_ttl_entry(i: &mut ByteStream) -> PResult<Construct> {
    (expiry_milliseconds, key_value)
        .parse_next(i)
        .map(|(ttl, (k, v))| Construct::Entry(k, v, Some(ttl)))
}

fn key_value(i: &mut ByteStream) -> PResult<(BString, Value)> {
    use ValueEncoding::*;
    let value_encoding = value_type.parse_next(i)?;
    let key = string_encoded.parse_next(i)?;

    let value = match value_encoding {
        String => Value::String(string_encoded.parse_next(i)?),
        List => Value::List(list_encoding.parse_next(i)?),
        Set => Value::Set(list_encoding.parse_next(i)?.into_iter().collect()),
        Hash => Value::Hash(hash_encoding.parse_next(i)?),
        IntSet => Value::Set(int_set.parse_next(i)?.into_iter().collect()),
        e => todo!("Unknown value encoding: {e:?}"),
    };

    Ok((key, value))
}

fn list_encoding(i: &mut ByteStream) -> PResult<Vec<BString>> {
    let len = length_encoded_int.parse_next(i)?;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        let s = string_encoded.parse_next(i)?;
        v.push(s);
    }
    Ok(v)
}

fn hash_encoding(i: &mut ByteStream) -> PResult<HashMap<BString, BString>> {
    let len = length_encoded_int.parse_next(i)?;
    let mut map = HashMap::with_capacity(len);
    for _ in 0..len {
        let k = string_encoded.parse_next(i)?;
        let v = string_encoded.parse_next(i)?;
        map.insert(k, v);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdb_magic_string_valid_success() {
        let header: [u8; 5] = hex!("52 45 44 49 53");
        let res = magic_string.parse_next(&mut header.as_ref());
        assert!(res.is_ok());
    }

    #[test]
    fn rdb_version_valid_success() {
        let version_bytes: [u8; 4] = hex!("30 30 30 33");
        let res = rdb_version.parse_next(&mut version_bytes.as_ref());
        assert_eq!(Ok(BString::from("0003")), res);
    }

    #[test]
    fn header_valid_returns_version() {
        let header_s = "REDIS0003";
        let res = header.parse_next(&mut header_s.as_ref());
        assert_eq!(Ok(Construct::Header(BString::from("0003"))), res);
    }

    #[test]
    fn length_encoded_string_type_type_0_success() {
        let length_bytes: [u8; 1] = hex!("09");
        let res = length_encoded_type.parse_next(&mut length_bytes.as_ref());
        assert_eq!(Ok(LengthEncodedType::Simple(9)), res);
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
        let res = auxiliary_field.parse_next(&mut input);
        assert_eq!(
            Ok(Construct::AuxiliaryField(
                BString::from("redis-ver"),
                BString::from("6.2.6")
            )),
            res
        );
    }

    #[test]
    fn int_encoded_success() {
        let bytes = hex!("02000b096963").to_vec();
        let mut input = bytes.as_ref();
        let res = length_encoded_type.parse_next(&mut input);
        println!("{:?}", res);
        let res = length_encoded_type.parse_next(&mut input);
        println!("{:?}", res);
    }

    #[test]
    fn test_main() -> anyhow::Result<()> {
        let bytes = hex!("524544495330303039fa0972656469732d76657205362e322e36fa0a72656469732d62697473c040fa056374696d65c2d828f866fa08757365642d6d656dc278610c00fa0c616f662d707265616d626c65c000fe01fb02000b096963795f62726f6f6b0c020000000200000080000002000f68696464656e5f6861745f68617368206361313630303963636437623564373030313732373133393335626430383835fe02fb03000004f09f989b4080306365333961613734373134396431393634323761323162336239333632373535656163653961663938383131613537626436313363653236383034393938363963646432363737393166333864643335346265643933653535616533383230313532363138323035636161636662643333333966363538333761633933393900166c696e676572696e675f76696f6c65745f636f756e74c1550200106d6f726e696e675f6261725f68617368206139336235353362356461343931633838353938643731366139356365306364fe03fb01000012666c6f72616c5f74727574685f636f756e74c14502fe04fb0200001063616c6d5f666c6f7765725f686173682035373733633536346234373663393934616364313930326163326132353037330010666c6f72616c5f6465775f636f756e74c12302fe06fb0200001066616e63795f647265616d5f68617368203637393733646430616666376666616530656639346531653666326161333632000d6472795f7365615f636f756e74c14602fe08fb0200001462696c6c6f77696e675f6c616b655f636f756e74c19803001273756d6d65725f66726f73745f636f756e74c18102fe09fb0201001166726f7374795f626c6f636b5f68617368203663633531343031306337346164633732653736386166653266313434633261fc20905f399201000000107368696e795f6d6f6f6e5f636f756e74c1af02fe0bfb010000116f72616e67655f737461725f636f756e74c1ac03ffe5c7593646c6f761 ").to_vec();
        let mut input = bytes.as_ref();
        let cs = parse(&mut input)?;
        for e in cs {
            println!("{e:?}")
        }
        // let header = header.parse_next(&mut input).unwrap();
        // for _ in 0..5 {
        //     let aux = auxiliary_field.parse_next(&mut input).unwrap();
        // }
        // let db_selector = database_selector.parse_next(&mut input).unwrap();
        // println!("{db_selector:?}");
        // let resizedb = resize_db.parse_next(&mut input).unwrap();
        // println!("{}", hex::encode(input));
        Ok(())
    }
}
