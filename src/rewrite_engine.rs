//use regex::Regex;
use ldap3::SearchEntry;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// A rule consists of an optional condition and a list of actions, which will be executed.
/// Only text attributes can be manipulated.
/// Maybe add support for jpegImage manipulation, etc. later.
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
   //condition: Option<Condition>,  TODO booolean expressions
   //and(a, b), not(a), or(a, b), xor(a, b)
   //matches(attr, regex),
   //single_value(attr), multi_value(attr), present(attr)
   //number_of_values(attr, compare, number) with compare "=", "<", ">", "<=", ">=", "!="
   //length(attr, compare, number) only for single value attributes
   actions: Vec<Action>,
}

/// attr is the attribute name and must be given in lowercase
#[derive(Debug, Serialize, Deserialize)]
pub enum Action {
    /// set values of an attribute (deleting all existing values, if there are any)
    Set { attr: String, values: Vec<String>},

    /// add some values (if attribute exists, or insert a new attribute with some values)
    Add { attr: String, values: Vec<String>},

    /// delete listed values of an attribute
    Remove {attr: String, values: Vec<String>},

    /// clears all values of an attribute = remove the attribute completely
    Clear {attr: String},

    /// only for single values: concatenate value of 2nd attr to 1st one
    Append {attr: String, attr2: String},

    /// copy all values of one attribute to another attribute (replacing existing values)
    Copy {from_attr: String, to_attr: String},

    /// for all values: replace matching groups using back-references
    // TODO Replace {attr: String, regex: Regex, replacement: String},

    /// split all values of an attribute to a maybe longer list of values
    Split {attr: String, separator: String},

    /// concatenate multiple values of an attribute to one
    Join {attr: String, separator: String},

    /// append all values of 2nd attribute to the values of 1st one
    Union {attr: String, attr2: String},
}

impl Action {
    fn insert_all(existing_vec: &mut Vec<String>, new_values: &Vec<String>) {
        for v in new_values {
            existing_vec.push(v.clone());
        }
    }

    fn remove_all(existing_vec: &mut Vec<String>, garbage_values: &Vec<String>) {
        existing_vec.retain(|value| !garbage_values.contains(value));
    }

    pub fn apply(&self, entry: &mut SearchEntry) {
        match self {
            Action::Set{attr, values} => {
                match entry.attrs.get_mut(attr) {
                    Some(mut existing_values) => {
                        existing_values.clear();
                        Self::insert_all(&mut existing_values, values);
                    },
                    None => {
                        let mut new_values = Vec::new();
                        Self::insert_all(&mut new_values, values);
                        entry.attrs.insert(attr.clone(), new_values);
                    },
                }
            },
            Action::Add{attr, values} => {
                match entry.attrs.get_mut(attr) {
                    Some(mut existing_values) => {
                        Self::insert_all(&mut existing_values, values);
                    },
                    None => {
                        let mut new_values = Vec::new();
                        Self::insert_all(&mut new_values, values);
                        entry.attrs.insert(attr.clone(), new_values);
                    },
                }
            },
            Action::Remove{attr, values} => {
                match entry.attrs.get_mut(attr) {
                    Some(mut existing_values) => {
                        Self::remove_all(&mut existing_values, values);
                    },
                    None => {},
                }
            },
            Action::Clear{attr } => {
                entry.attrs.remove(attr);
            },
            _ => panic!("not implemented yet"),
        }
    }


    
}

impl Rule {
    pub fn apply_actions(&self, entry: &mut SearchEntry) {
        for action in self.actions.iter() {
            action.apply(entry);
        }
    } 

    pub fn apply_rules(entry: &mut SearchEntry, rules: &Vec<Rule>) {
        for rule in rules.iter() {
            // TODO: check condition if there is Some
            rule.apply_actions(entry);
        }
    }

    pub fn parse_rules(json_str: &str) -> Result<Vec<Rule>, serde_json::Error> {
        serde_json::from_str(json_str)
    }

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_action_set() {
        let mut entry = SearchEntry {
             dn: "cn=test".to_string(),
             attrs: HashMap::from([
                ("objectclass".to_string(), vec!["top".to_string(), "person".to_string()]),
                ("givenname".to_string(), vec!["Karl".to_string(), "Heinz".to_string()]),
                ("sn".to_string(), vec!["Müller".to_string()])
             ]),
             bin_attrs: HashMap::new()
        };
        let rules = vec![
            Rule { actions: vec![Action::Set{ attr: "givenname".to_string(), values: vec!["André".to_string(), "Adrian".to_string()] }]},
            Rule { actions: vec![Action::Set{ attr: "description".to_string(), values: vec!["A wonderful person".to_string()] }]}
        ];
        
        Rule::apply_rules(&mut entry, &rules);

        assert_eq!(entry.attrs.len(), 4);
        let obj_class = entry.attrs.get("objectclass").unwrap();
        assert_eq!(obj_class.len(), 2);
        assert!(obj_class.contains(&"top".to_string()));
        assert!(obj_class.contains(&"person".to_string()));
        let sn = entry.attrs.get("sn").unwrap();
        assert!(sn.contains(&"Müller".to_string()));
        assert_eq!(sn.len(), 1);
        let given_name = entry.attrs.get("givenname").unwrap();
        assert_eq!(given_name.len(), 2);
        assert!(given_name.contains(&"André".to_string()));
        assert!(given_name.contains(&"Adrian".to_string()));
        let description = entry.attrs.get("description").unwrap();
        assert_eq!(description.len(), 1);
        assert!(description.contains(&"A wonderful person".to_string()));
    }
}