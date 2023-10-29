use ldap3::SearchEntry;
use regex::Regex;
use std::collections::HashMap;
use std::str::Lines;

#[derive(Debug)]
pub enum ParseLdifError {
    LineNotMatched, // todo add line number and line as string
    MissingDN, // todo add line number and line as string
    // todo SecondDN
}

/// A LDIF parser using stream processing,
/// reading input lines and emitting SearchEntries.
pub struct LdifParser<'a> {
    ldif_lines_iter: Lines<'a>,
    empty_line_regex: Regex,
    attr_line_regex: Regex,
    // todo comment_line_regex
}

impl LdifParser<'_> {
    pub fn from_lines(ldif_lines_iter: Lines) -> LdifParser {
        let parser = LdifParser {
            ldif_lines_iter: ldif_lines_iter,
            empty_line_regex: Regex::new("^[ ]*$").unwrap(),
            attr_line_regex: Regex::new("^([a-zA-Z0-9]+): (.*)$").unwrap(),
        };
        parser
    }
}

impl Iterator for LdifParser<'_> {
    type Item = Result<SearchEntry, ParseLdifError>;

    /// parses input lines like an AWK script.
    /// todo line wraps
    /// todo base64 encoded dns and values
    /// todo binary (not valid utf8) values
    /// todo comment lines starting with '#'
    /// todo extract into an own crate
    /// todo case of attribute names
    /// todo maybe check if DN attribute exists
    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = SearchEntry {
            dn: "".to_string(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::new(),
        };
        
        // state: inside entry (list of attributes) or between entries (empty lines)
        let mut inside_entry = false;

        loop {
            let ldif_line = self.ldif_lines_iter.next();
            match ldif_line {
                Some(line) => {
                    let empty_line_captures = self.empty_line_regex.captures(line);
                    match empty_line_captures {
                        Some(_) => {
                            if inside_entry {
                                // Ende eines Eintrages erreicht
                                return Some(Ok(entry));
                            };
                            continue;
                        }
                        None => {}
                    };
                    let attr_line_captures = self.attr_line_regex.captures(line);
                    match attr_line_captures {
                        Some(caps) => {
                            let attr_name = caps.get(1).unwrap().as_str();
                            let attr_value = caps.get(2).unwrap().as_str().to_string();
                            if inside_entry {
                                // ein weiteres Attribut
                                let attr = entry.attrs.get_mut(attr_name);
                                match attr {
                                    Some(a) => {
                                        // weiterer Wert
                                        a.push(attr_value);
                                    }
                                    None => {
                                        // erster Wert
                                        entry.attrs.insert(attr_name.to_string(), vec![attr_value]);
                                    }
                                }
                            } else {
                                // erstes Attribut = DN
                                if attr_name == "dn" {
                                    entry.dn = attr_value;
                                } else {
                                    return Some(Err(ParseLdifError::MissingDN))
                                }
                                inside_entry = true
                            }
                            continue;
                        }
                        None => {}
                    };

                }
                None => {
                    // end of file
                    if inside_entry {
                        // return last entry
                        return Some(Ok(entry));
                    } else {
                        return None
                    }
                }
            }
        }
    }
}


pub fn parse_ldif(ldif_str: &str) -> Result<Vec<SearchEntry>, ParseLdifError> {
    let parser = LdifParser::from_lines(ldif_str.lines());
    let result = parser.collect();
    result
}

#[cfg(test)]
pub mod test {
    use super::*;
    use indoc::*;

    #[test]
    fn parse_bytes_as_utf8_ok() {
        let bytes = vec![72, 105];
        let result = std::str::from_utf8(&bytes);
        assert_eq!(result, Ok("Hi"));
    }

    #[test]
    fn parse_bytes_as_utf8_err() {
        //let bytes = vec![0]; // ist ok
        let bytes = vec![126, 190];
        let result = std::str::from_utf8(&bytes);
        print!("{:?}", result);
        assert!(result.is_err());
    }

    #[test]
    fn encode_bytes() {        
        use base64::{Engine as _, engine::general_purpose};
        //let orig = b"data";
        let orig = vec![126, 190]; // not utf8
        let encoded: String = general_purpose::STANDARD.encode(orig);
        print!("{:?}", encoded);
    }

    #[test]
    fn test_parse_1_ldif_entry() {
        let ldif_str = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test"
        };
        let entries = parse_ldif(ldif_str).unwrap();
        print!("entries: {:?}", entries);
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
        assert!(obj_class.contains(&"dcObject".to_string()));
        assert!(obj_class.contains(&"organization".to_string()));
        assert!(o.contains(&"Test Org".to_string()));
        assert!(dc.contains(&"test".to_string()));
    }

    #[test]
    fn test_parse_2_ldif_entries() {
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
        print!("entries: {:?}", entries);
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
            assert!(obj_class.contains(&"organization".to_string()));
            assert!(o.contains(&"test".to_string()));
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
            assert!(obj_class.contains(&"organizationalUnit".to_string()));
            assert!(ou.contains(&"unit".to_string()));
        }
    }
}
