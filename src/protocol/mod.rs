pub mod deserialise;
pub mod serialise;
pub mod types;

use self::types::*;

impl Message {
    pub fn make_response(&self) -> Self {
        Self {
            header: Header {
                id: self.header.id,
                is_response: true,
                opcode: self.header.opcode,
                is_authoritative: false,
                is_truncated: false,
                recursion_desired: self.header.recursion_desired,
                recursion_available: true,
                rcode: Rcode::NoError,
            },
            questions: self.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn make_format_error_response(id: u16) -> Self {
        Self {
            header: Header {
                id,
                is_response: true,
                opcode: Opcode::Standard,
                is_authoritative: false,
                is_truncated: false,
                recursion_desired: false,
                recursion_available: true,
                rcode: Rcode::FormatError,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn from_question(id: u16, question: Question) -> Self {
        Self {
            header: Header {
                id,
                is_response: false,
                opcode: Opcode::Standard,
                is_authoritative: false,
                is_truncated: false,
                recursion_desired: false,
                recursion_available: true,
                rcode: Rcode::NoError,
            },
            questions: vec![question],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}

impl DomainName {
    pub fn to_dotted_string(&self) -> String {
        if self.octets == vec![0] {
            return ".".to_string();
        }

        let mut out = String::with_capacity(self.octets.len());
        let mut first = true;
        for label in &self.labels {
            if first {
                first = false;
            } else {
                out.push('.');
            }
            for octet in label {
                out.push(*octet as char);
            }
        }

        out
    }

    pub fn from_relative_dotted_string(origin: &Self, s: &str) -> Option<Self> {
        if s.is_empty() {
            Some(origin.clone())
        } else if s.to_string().ends_with('.') {
            Self::from_dotted_string(s)
        } else {
            let suffix = origin.to_dotted_string();
            if suffix.starts_with('.') {
                Self::from_dotted_string(&format!("{}{}", s, suffix))
            } else {
                Self::from_dotted_string(&format!("{}.{}", s, suffix))
            }
        }
    }

    pub fn from_dotted_string(s: &str) -> Option<Self> {
        if s == "." {
            return Some(DomainName::root_domain());
        }

        let chunks = s.split('.').collect::<Vec<_>>();
        let mut labels = Vec::with_capacity(chunks.len());

        for (i, label) in chunks.iter().enumerate() {
            if label.is_empty() && i != chunks.len() - 1 {
                return None;
            }

            labels.push(label.as_bytes().into());
        }

        Self::from_labels(labels)
    }

    pub fn from_labels(mixed_case_labels: Vec<Vec<u8>>) -> Option<Self> {
        if mixed_case_labels.is_empty() {
            return None;
        }

        let mut labels = Vec::<Vec<u8>>::with_capacity(mixed_case_labels.len());
        let mut octets = Vec::<u8>::with_capacity(255);
        let mut blank_label = false;

        for mc_label in &mixed_case_labels {
            if blank_label {
                return None;
            }

            blank_label = mc_label.is_empty();

            match mc_label.len().try_into() {
                Ok(n) if n <= 63 => {
                    octets.push(n);
                    let mut label = Vec::<u8>::with_capacity(mc_label.len());
                    for octet in mc_label {
                        if !octet.is_ascii() {
                            return None;
                        }

                        let octet = octet.to_ascii_lowercase();
                        label.push(octet);
                        octets.push(octet);
                    }
                    labels.push(label);
                }
                _ => return None,
            }
        }

        if blank_label && octets.len() <= 255 {
            Some(Self { octets, labels })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use fake::Fake;

    use super::*;

    #[test]
    fn domainname_root_conversions() {
        assert_eq!(
            Some(DomainName::root_domain()),
            DomainName::from_dotted_string(".")
        );

        assert_eq!(
            Some(DomainName::root_domain()),
            DomainName::from_labels(vec![Vec::new()])
        );

        assert_eq!(".", DomainName::root_domain().to_dotted_string())
    }

    #[test]
    fn from_relative_dotted_string_empty() {
        let origin = DomainName::from_dotted_string("com.").unwrap();
        assert_eq!(
            Some(DomainName::from_dotted_string("com.").unwrap()),
            DomainName::from_relative_dotted_string(&origin, "")
        );
    }

    #[test]
    fn from_relative_dotted_string_absolute() {
        let origin = DomainName::from_dotted_string("com.").unwrap();
        assert_eq!(
            Some(DomainName::from_dotted_string("www.example.com.").unwrap()),
            DomainName::from_relative_dotted_string(&origin, "www.example.com.")
        );
    }

    #[test]
    fn from_relative_dotted_string_relative() {
        let origin = DomainName::from_dotted_string("com.").unwrap();
        assert_eq!(
            Some(DomainName::from_dotted_string("www.example.com.").unwrap()),
            DomainName::from_relative_dotted_string(&origin, "www.example")
        );
    }

    #[test]
    fn domainname_conversions() {
        for _ in 0..100 {
            let labels_len = (0..5).fake::<usize>();

            let mut dotted_string_input = String::new();
            let mut labels_input = Vec::with_capacity(labels_len);
            let mut output = String::new();

            for i in 0..labels_len {
                let label_len = (1..10).fake::<usize>();

                if i > 0 {
                    dotted_string_input.push('.');
                    output.push('.');
                }

                let mut label = Vec::with_capacity(label_len);
                for _ in 0..label_len {
                    let mut chr = (32..126).fake::<u8>();

                    // turn '.' to 'X'
                    if chr == 46 {
                        chr = 88;
                    }

                    label.push(chr);
                    dotted_string_input.push(chr as char);
                    output.push(chr.to_ascii_lowercase() as char);
                }
                labels_input.push(label);
            }

            labels_input.push(Vec::new());
            dotted_string_input.push('.');
            output.push('.');

            assert_eq!(
                Some(output.clone()),
                DomainName::from_dotted_string(&dotted_string_input).map(|d| d.to_dotted_string())
            );

            assert_eq!(
                Some(output),
                DomainName::from_labels(labels_input.clone()).map(|d| d.to_dotted_string())
            );

            assert_eq!(
                DomainName::from_dotted_string(&dotted_string_input).map(|d| d.to_dotted_string()),
                DomainName::from_labels(labels_input).map(|d| d.to_dotted_string())
            );
        }
    }
}
