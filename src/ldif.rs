use base64::{engine::general_purpose, DecodeError, Engine as _};
use ldap3::SearchEntry;
use regex::Regex;
use core::convert::AsRef;
use std::ops::Deref;
use std::collections::HashMap;
use std::iter::Enumerate;
use std::str;
use std::str::Lines;
use std::str::Utf8Error;

/// If an attribute value is provided in clear text, it's definitely text.
/// If it is provided base64-encoded and it can be parsed as UTF8, its probably text, otherwise binary.
/// If you know the specific attribute definitions in the LDAP schema, you know for sure.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum AttributeValue {
    Text(String),
    Binary(Vec<u8>),
}

impl AttributeValue {
    fn as_text(&self) -> Result<&str, Utf8Error> {
        match self {
            Self::Binary(b) => str::from_utf8(&b),
            Self::Text(t) => Ok(t),
        }
    }

    fn as_binary(&self) -> Vec<u8> {
        match self {
            Self::Binary(b) => b.clone(),
            Self::Text(t) => t.as_bytes().to_vec(),
        }
    }
}

impl AsRef<[u8]> for AttributeValue {
    fn as_ref(&self) -> &[u8]{
        match self {
            AttributeValue::Binary ( b ) => {
                 b.deref().as_ref()
            },
            AttributeValue::Text ( t ) => {
                 t.deref().as_ref()
            }
        }
    }
}

#[derive(Debug)]
pub struct DirectoryEntry {
    dn: String,
    attrs: HashMap<String, Vec<AttributeValue>>,
}

impl DirectoryEntry {
    pub fn as_search_entry(&self) -> SearchEntry {
        let mut search_entry = SearchEntry {
            dn: self.dn.clone(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::new(),
        };
        for (attr_name, attr_values) in self.attrs.iter() {
            if is_any_binary(&attr_values) {
                let binary_values = map_values_to_bytes(&attr_values);
                search_entry
                    .bin_attrs
                    .insert(attr_name.clone(), binary_values);
            } else {
                let text_values = map_values_to_strings(&attr_values);
                search_entry.attrs.insert(attr_name.clone(), text_values);
            }
        }
        search_entry
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseLdifErrorType {
    LineNotMatched,
    MissingDN,
    SecondDN,
    Base64DecodeErr { decode_error: DecodeError },
    BinaryDnNotAllowed, //{ utf8_error: Utf8Error}
}

#[derive(Debug, PartialEq)]
pub struct ParseLdifError {
    pub line_num: usize,
    pub quote: String,
    pub error_type: ParseLdifErrorType,
}

/// A LDIF parser using stream processing,
/// reading input lines and emitting SearchEntries.
/// Only for ldif-content (imports), not ldif-changes ("changetype: modify").
/// see: RfC 2849
pub struct LdifParser<'a> {
    ldif_lines_iter: Enumerate<Lines<'a>>,
    dn_line_regex: Regex,
    encoded_dn_line_regex: Regex,
    attr_line_regex: Regex,
    encoded_attr_line_regex: Regex,
    empty_line_regex: Regex,
    comment_line_regex: Regex,
}

impl LdifParser<'_> {
    pub fn from_lines(ldif_lines_iter: Lines) -> LdifParser {
        let parser = LdifParser {
            ldif_lines_iter: ldif_lines_iter.enumerate(),

            dn_line_regex: Regex::new("^dn: (.*)$").unwrap(),
            encoded_dn_line_regex: Regex::new("^dn:: (.*)$").unwrap(),
            attr_line_regex: Regex::new("^([a-zA-Z0-9]+): (.*)$").unwrap(),
            encoded_attr_line_regex: Regex::new("^([a-zA-Z0-9]+):: (.*)$").unwrap(),
            empty_line_regex: Regex::new("^$").unwrap(),
            comment_line_regex: Regex::new("^#").unwrap(),
        };
        parser
    }

    pub fn from_str(s: &str) -> LdifParser {
        Self::from_lines(s.lines())
    }

    pub fn collect_to_vec(&mut self) -> Result<Vec<DirectoryEntry>, ParseLdifError> {
        let mut v: Vec<DirectoryEntry> = Vec::new();
        for result in self {
            match result {
                Ok(entry) => {
                    v.push(entry);
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(v)
    }

    fn add_attr_value(
        attrs: &mut HashMap<String, Vec<AttributeValue>>,
        name: &str,
        value: AttributeValue,
    ) {
        // Does the attribute already exist?
        let attr = attrs.get_mut(name);
        match attr {
            Some(a) => {
                // additional value
                a.push(value);
            }
            None => {
                // first value
                attrs.insert(name.to_string(), vec![value]);
            }
        }
    }

    fn decode_value(
        encoded_value: &str,
        line_num: usize,
    ) -> Result<AttributeValue, ParseLdifError> {
        let decode_result = &general_purpose::STANDARD.decode(encoded_value);
        match decode_result {
            Ok(vec_u8) => {
                let result = str::from_utf8(vec_u8);
                match result {
                    Ok(decoded_value) => {
                        // if it can be decoded as UTF-8 it's probably a String
                        return Ok(AttributeValue::Text(decoded_value.to_string()));
                    }
                    Err(_) => {
                        // if it can't be decoded as UTF-8 it's a binary attribute value (or some previous encoding mistake)
                        return Ok(AttributeValue::Binary(vec_u8.clone()));
                    }
                }
            }
            Err(err) => {
                return Err(ParseLdifError {
                    line_num: line_num,
                    quote: encoded_value.to_string(),
                    error_type: ParseLdifErrorType::Base64DecodeErr {
                        decode_error: err.clone(),
                    },
                });
            }
        }
    }
}

impl Iterator for LdifParser<'_> {
    type Item = Result<DirectoryEntry, ParseLdifError>;

    /// LdifParser parses input lines like an AWK script.
    /// Currently line wraps are not supported.
    ///
    /// TODO line wraps
    /// TODO extract into an own crate
    /// TODO multiple cases of attribute names
    /// TODO first line with version number
    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = DirectoryEntry {
            dn: "".to_string(),
            attrs: HashMap::new(),
        };

        // state: inside entry (list of attributes) or between entries (empty lines)
        let mut inside_entry = false;

        loop {
            let ldif_line = self.ldif_lines_iter.next();
            match ldif_line {
                Some((line_num, line)) => {
                    let dn_line_captures = self.dn_line_regex.captures(line);
                    match dn_line_captures {
                        Some(caps) => {
                            if inside_entry {
                                return Some(Err(ParseLdifError {
                                    line_num: line_num,
                                    quote: line.to_string(),
                                    error_type: ParseLdifErrorType::SecondDN,
                                }));
                            } else {
                                entry.dn = caps.get(1).unwrap().as_str().to_string();
                                inside_entry = true;
                                continue;
                            }
                        }
                        None => {}
                    };

                    let encoded_dn_line_captures = self.encoded_dn_line_regex.captures(line);
                    match encoded_dn_line_captures {
                        Some(caps) => {
                            if inside_entry {
                                return Some(Err(ParseLdifError {
                                    line_num: line_num,
                                    quote: line.to_string(),
                                    error_type: ParseLdifErrorType::SecondDN,
                                }));
                            } else {
                                let encoded_dn = caps.get(1).unwrap().as_str().to_string();
                                let decode_result = LdifParser::decode_value(&encoded_dn, line_num);
                                match decode_result {
                                    Ok(dn) => match dn {
                                        AttributeValue::Binary(_) => {
                                            return Some(Err(ParseLdifError {
                                                line_num: line_num,
                                                quote: encoded_dn,
                                                error_type: ParseLdifErrorType::BinaryDnNotAllowed,
                                            }));
                                        }
                                        AttributeValue::Text(t) => {
                                            entry.dn = t;
                                            inside_entry = true;
                                            continue;
                                        }
                                    },
                                    Err(err) => {
                                        return Some(Err(err));
                                    }
                                }
                            }
                        }
                        None => {}
                    };

                    let attr_line_captures = self.attr_line_regex.captures(line);
                    match attr_line_captures {
                        Some(caps) => {
                            if inside_entry {
                                let attr_name = caps.get(1).unwrap().as_str().to_lowercase();
                                let attr_value = caps.get(2).unwrap().as_str().to_string();
                                LdifParser::add_attr_value(
                                    &mut entry.attrs,
                                    &attr_name,
                                    AttributeValue::Text(attr_value),
                                );
                                continue;
                            } else {
                                return Some(Err(ParseLdifError {
                                    line_num: line_num,
                                    quote: line.to_string(),
                                    error_type: ParseLdifErrorType::MissingDN,
                                }));
                            }
                        }
                        None => {}
                    };

                    let encoded_attr_line_captures = self.encoded_attr_line_regex.captures(line);
                    match encoded_attr_line_captures {
                        Some(caps) => {
                            if inside_entry {
                                let attr_name = caps.get(1).unwrap().as_str().to_lowercase();
                                let encoded_attr_value = caps.get(2).unwrap().as_str().to_string();
                                let decode_result =
                                    LdifParser::decode_value(&encoded_attr_value, line_num);
                                match decode_result {
                                    Ok(attr_value) => {
                                        LdifParser::add_attr_value(
                                            &mut entry.attrs,
                                            &attr_name,
                                            attr_value,
                                        );
                                        continue;
                                    }
                                    Err(err) => {
                                        return Some(Err(err));
                                    }
                                }
                            } else {
                                return Some(Err(ParseLdifError {
                                    line_num: line_num,
                                    quote: line.to_string(),
                                    error_type: ParseLdifErrorType::SecondDN,
                                }));
                            }
                        }
                        None => {}
                    };

                    let empty_line_captures = self.empty_line_regex.captures(line);
                    match empty_line_captures {
                        Some(_) => {
                            if inside_entry {
                                // Ende eines Eintrages erreicht
                                return Some(Ok(entry));
                            } else {
                                continue;
                            }
                        }
                        None => {}
                    };

                    let comment_line_captures = self.comment_line_regex.captures(line);
                    match comment_line_captures {
                        Some(_) => {
                            continue;
                        }
                        None => {}
                    };

                    return Some(Err(ParseLdifError {
                        line_num: line_num,
                        quote: line.to_string(),
                        error_type: ParseLdifErrorType::LineNotMatched,
                    }));
                }
                None => {
                    // end of file
                    if inside_entry {
                        // return last entry
                        return Some(Ok(entry));
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}

pub fn parse_ldif(ldif_str: &str) -> Result<Vec<DirectoryEntry>, ParseLdifError> {
    let parser = LdifParser::from_lines(ldif_str.lines());
    let result = parser.collect();
    result
}

/// assuming that there is no binary attribute value
pub fn map_values_to_strings(attr_values: &Vec<AttributeValue>) -> Vec<String> {
    attr_values
        .iter()
        .map(|value| value.as_text().unwrap().to_string())
        .collect()
}

/// assuming that there is at least one binary attribute value
pub fn map_values_to_bytes(attr_values: &Vec<AttributeValue>) -> Vec<Vec<u8>> {
    attr_values.iter().map(|value| value.as_binary()).collect()
}

pub fn is_any_binary(attr: &Vec<AttributeValue>) -> bool {
    attr.iter()
        .find(|attr_value| matches!(attr_value, AttributeValue::Binary { .. }))
        .is_some()
}

pub fn parse_ldif_as_search_entries(ldif_str: &str) -> Result<Vec<SearchEntry>, ParseLdifError> {
    let parser = LdifParser::from_lines(ldif_str.lines());
    let result = parser
        .map(|dir_entry| match dir_entry {
            Ok(entry) => Ok(entry.as_search_entry()),
            Err(err) => Err(err),
        })
        .collect();
    result
}

#[cfg(test)]
pub mod test {
    use super::*;
    use indoc::*;
    use log::debug;

    #[test]
    fn parse_bytes_as_utf8_ok() {
        let bytes = vec![72, 105];
        let result = std::str::from_utf8(&bytes);
        assert_eq!(result, Ok("Hi"));
    }

    #[test]
    fn parse_bytes_as_utf8_err() {
        let _ = env_logger::try_init();
        //let bytes = vec![0]; // ist ok
        let bytes = vec![126, 190];
        let result = std::str::from_utf8(&bytes);
        debug!("{:?}", result);
        assert!(result.is_err());
    }

    #[test]
    fn encode_bytes() {
        let _ = env_logger::try_init();
        //let orig = b"data";
        let orig = vec![126, 190]; // not utf8
        let encoded: String = general_purpose::STANDARD.encode(orig);
        debug!("{:?}", encoded);
    }

    #[test]
    fn test_parse_1_ldif_entry() {
        let _ = env_logger::try_init();
        let ldif_str = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test"
        };
        let entries = parse_ldif(ldif_str).unwrap();
        debug!("entries: {:?}", entries);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.dn, "dc=test");
        let attrs = &entry.attrs;
        assert_eq!(attrs.len(), 3);
        let obj_class = attrs.get("objectclass").unwrap();
        let o = attrs.get("o").unwrap();
        let dc = attrs.get("dc").unwrap();
        assert_eq!(obj_class.len(), 2);
        assert_eq!(o.len(), 1);
        assert_eq!(dc.len(), 1);
        assert!(obj_class.contains(&AttributeValue::Text("dcObject".to_string())));
        assert!(obj_class.contains(&AttributeValue::Text("organization".to_string())));
        assert!(o.contains(&AttributeValue::Text("Test Org".to_string())));
        assert!(dc.contains(&&AttributeValue::Text("test".to_string())));
    }

    #[test]
    fn test_parse_2_ldif_entries() {
        let _ = env_logger::try_init();
        let ldif_str = indoc! { "
            dn: o=test
            objectclass: organization
            o: test

            dn: ou=unit,o=test
            objectclass: organizationalUnit
            ou: unit
            "
        };
        let entries = parse_ldif(ldif_str).unwrap();
        debug!("entries: {:?}", entries);
        assert_eq!(entries.len(), 2);
        {
            let entry = &entries[0];
            assert_eq!(entry.dn, "o=test");
            let attrs = &entry.attrs;
            assert_eq!(attrs.len(), 2);
            let obj_class = attrs.get("objectclass").unwrap();
            let o = attrs.get("o").unwrap();
            assert_eq!(obj_class.len(), 1);
            assert_eq!(o.len(), 1);
            assert!(obj_class.contains(&AttributeValue::Text("organization".to_string())));
            assert!(o.contains(&AttributeValue::Text("test".to_string())));
        }
        {
            let entry = &entries[1];
            assert_eq!(entry.dn, "ou=unit,o=test");
            let attrs = &entry.attrs;
            assert_eq!(attrs.len(), 2);
            let obj_class = attrs.get("objectclass").unwrap();
            let ou = attrs.get("ou").unwrap();
            assert_eq!(obj_class.len(), 1);
            assert_eq!(ou.len(), 1);
            assert!(obj_class.contains(&AttributeValue::Text("organizationalUnit".to_string())));
            assert!(ou.contains(&&AttributeValue::Text("unit".to_string())));
        }
    }

    #[test]
    fn test_parse_ldif_with_comments() {
        let _ = env_logger::try_init();
        let ldif_str = indoc! { "
            # This is a comment
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            #this line should also be ignored
            o: Test Org
            dc: test"
        };
        let entries = parse_ldif(ldif_str).unwrap();
        debug!("entries: {:?}", entries);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.dn, "dc=test");
        let attrs = &entry.attrs;
        assert_eq!(attrs.len(), 3);
        let obj_class = attrs.get("objectclass").unwrap();
        let o = attrs.get("o").unwrap();
        let dc = attrs.get("dc").unwrap();
        assert_eq!(obj_class.len(), 2);
        assert_eq!(o.len(), 1);
        assert_eq!(dc.len(), 1);
        assert!(obj_class.contains(&AttributeValue::Text("dcObject".to_string())));
        assert!(obj_class.contains(&AttributeValue::Text("organization".to_string())));
        assert!(o.contains(&AttributeValue::Text("Test Org".to_string())));
        assert!(dc.contains(&&AttributeValue::Text("test".to_string())));
    }

    #[test]
    fn test_parse_ldif_without_dn() {
        let ldif_str = indoc! { "
            objectclass: organization
            o: Test Org"
        };
        let expected_err = ParseLdifError {
            line_num: 0,
            quote: "objectclass: organization".to_string(),
            error_type: ParseLdifErrorType::MissingDN,
        };
        let err_result = parse_ldif(ldif_str).err().unwrap();
        assert_eq!(err_result, expected_err);
    }

    #[test]
    fn test_parse_ldif_second_dn() {
        let ldif_str = indoc! { "
            dn: o=Test Org
            objectclass: organization
            o: Test Org
            dn: wrong"
        };
        let expected_err = ParseLdifError {
            line_num: 3,
            quote: "dn: wrong".to_string(),
            error_type: ParseLdifErrorType::SecondDN,
        };
        let err_result = parse_ldif(ldif_str).err().unwrap();
        assert_eq!(err_result, expected_err);
    }

    #[test]
    fn test_parse_ldif_binary_dn() {
        let ldif_str = indoc! { "
            # The DN can't be parsed as valid UTF8
            dn:: fr4=
            objectclass: organization"
        };
        let expected_err = ParseLdifError {
            line_num: 1,
            quote: "fr4=".to_string(),
            error_type: ParseLdifErrorType::BinaryDnNotAllowed,
        };
        let err_result = parse_ldif(ldif_str).err().unwrap();
        assert_eq!(err_result, expected_err);
    }

    #[test]
    fn test_parse_ldif_line_not_matched() {
        let ldif_str = indoc! { "
            dn: o=Test Org
            objectclass: organization
            # missing space after colon
            o:Test Org"
        };
        let expected_err = ParseLdifError {
            line_num: 3,
            quote: "o:Test Org".to_string(),
            error_type: ParseLdifErrorType::LineNotMatched,
        };
        let err_result = parse_ldif(ldif_str).err().unwrap();
        assert_eq!(err_result, expected_err);
    }

    #[test]
    fn test_parse_ldif_encoded_dn() {
        let _ = env_logger::try_init();
        let ldif_str = indoc! { "
            # Base64-UTF8-decoded 'o=test'
            dn:: bz10ZXN0
            objectclass: organization
            o: test"
        };
        let entries = parse_ldif(ldif_str).unwrap();
        debug!("entries: {:?}", entries);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.dn, "o=test");
        let attrs = &entry.attrs;
        assert_eq!(attrs.len(), 2);
        let obj_class = attrs.get("objectclass").unwrap();
        let o = attrs.get("o").unwrap();
        assert_eq!(obj_class.len(), 1);
        assert_eq!(o.len(), 1);
        assert!(obj_class.contains(&AttributeValue::Text("organization".to_string())));
        assert!(o.contains(&AttributeValue::Text("test".to_string())));
    }

    #[test]
    fn test_parse_ldif_encoded_attr_value() {
        let _ = env_logger::try_init();
        let ldif_str = indoc! { "
            dn: o=test
            objectclass: organization
            # Base64-UTF8-decoded 'test'
            o:: dGVzdA=="
        };
        let entries = parse_ldif(ldif_str).unwrap();
        debug!("entries: {:?}", entries);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.dn, "o=test");
        let attrs = &entry.attrs;
        assert_eq!(attrs.len(), 2);
        let obj_class = attrs.get("objectclass").unwrap();
        let o = attrs.get("o").unwrap();
        assert_eq!(obj_class.len(), 1);
        assert_eq!(o.len(), 1);
        assert!(obj_class.contains(&AttributeValue::Text("organization".to_string())));
        assert!(o.contains(&AttributeValue::Text("test".to_string())));
    }

    #[test]
    fn test_parse_ldif_binary_attr_value() {
        let _ = env_logger::try_init();
        let ldif_str = indoc! { "
            dn: o=test
            objectClass: organization
            o: test
            # vec![126, 190] is not valid UTF-8, means binary
            jpegPhoto:: fr4="
        };
        let entries = parse_ldif(ldif_str).unwrap();
        debug!("entries: {:?}", entries);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.dn, "o=test");
        let attrs = &entry.attrs;
        assert_eq!(attrs.len(), 3);
        let obj_class = attrs.get("objectclass").unwrap();
        let o = attrs.get("o").unwrap();
        let jpeg_photo = attrs.get("jpegphoto").unwrap();
        assert_eq!(obj_class.len(), 1);
        assert_eq!(o.len(), 1);
        assert_eq!(jpeg_photo.len(), 1);
        assert!(obj_class.contains(&AttributeValue::Text("organization".to_string())));
        assert!(o.contains(&AttributeValue::Text("test".to_string())));
        assert!(jpeg_photo.contains(&AttributeValue::Binary(vec![126, 190])));
    }
}
