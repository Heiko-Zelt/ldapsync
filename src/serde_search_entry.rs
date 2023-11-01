/// LDIF ist ein kompakteres Format als JSON.
/// Deswegen wird diese Funktion nicht mehr verwendet. (deprecated)

#[cfg(test)]
mod test {
    use serde::Deserialize;
    use std::collections::HashMap;
    use ldap3::SearchEntry;

    /// ldap3::SearchEntry does not implement the Deserialize trait.
    /// So I define my own struct, which can easily be mapped to SearchEntry.
    #[derive(Deserialize)]
    struct SerdeSearchEntry {
        pub dn: String,
        pub attrs: HashMap<String, Vec<String>>,
        pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
    }

    pub fn parse_search_entries(json_str: &str) -> Vec<SearchEntry> {
        let serde_search_entries = serde_json::from_str::<Vec<SerdeSearchEntry>>(json_str).unwrap();
        let search_entries = serde_search_entries
            .into_iter()
            .map(|serde_entry| SearchEntry {
                dn: serde_entry.dn,
                attrs: serde_entry.attrs,
                bin_attrs: serde_entry.bin_attrs,
            })
            .collect();
        search_entries
    }
}
