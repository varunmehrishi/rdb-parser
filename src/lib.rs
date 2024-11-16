use winnow::{error::{ErrMode, ErrorKind, FromExternalError}, token::{literal, take}, PResult, Parser};

type Stream<'i> = &'i [u8];

pub fn magic_string(i: &mut Stream) -> PResult<()> {
    let _ = literal("REDIS").parse_next(i)?;
    Ok(())  
}

pub fn rdb_version(i: &mut Stream) -> PResult<String> {
    let versions_bytes = take(4usize).parse_next(i)?;
    String::from_utf8(versions_bytes.to_owned())
        .map_err(|e| ErrMode::from_external_error(i, ErrorKind::Verify, e))
}

pub fn header(i: &mut Stream) -> PResult<String> {
    Ok((magic_string, rdb_version).parse_next(i)?.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdb_magic_string_valid_success() {
        let header: [u8; 5] = [0x52, 0x45, 0x44, 0x49, 0x53];
        let res = magic_string(&mut header.as_ref());
        assert!(res.is_ok())
    }

    #[test]
    fn rdb_version_valid_success() {
        let version_bytes: [u8; 4] = [0x30, 0x30, 0x30, 0x33];
        let res = rdb_version(&mut version_bytes.as_ref());
        assert_eq!(Ok("0003".to_owned()), res)
    }

    #[test]
    fn header_valid_returns_version() {
        let header_s = "REDIS0003";
        let res = header(&mut header_s.as_ref());
        assert_eq!(Ok("0003".to_owned()), res)
    }
}
