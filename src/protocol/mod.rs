pub mod deserialise;
pub mod serialise;
pub mod wire_types;

use self::wire_types::*;

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
        let mut out = String::with_capacity(self.octets.len());
        let mut dot = false;
        for label in &self.labels {
            for octet in label {
                out.push(*octet as char);
            }
            if !label.is_empty() {
                out.push('.');
                dot = true;
            }
        }
        if !dot {
            out.push('.');
        }

        out
    }

    pub fn from_dotted_string(s: &str) -> Option<Self> {
        let mut labels = Vec::<Vec<u8>>::with_capacity(5);
        let mut blank_label = false;

        for label in s.split('.') {
            if blank_label {
                return None;
            }

            let label = label.as_bytes();
            blank_label = label.is_empty();
            labels.push(label.into());
        }

        if !blank_label {
            labels.push(Vec::new());
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
    use fake::{Fake, Faker};

    use super::*;

    #[test]
    fn domainname_root_conversions() {
        assert_eq!(
            Some(DomainName::root_domain()),
            DomainName::from_dotted_string("")
        );

        assert_eq!(
            Some(DomainName::root_domain()),
            DomainName::from_labels(vec![Vec::new()])
        );

        assert_eq!(".", DomainName::root_domain().to_dotted_string())
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
            if Faker.fake() && output.len() > 0 {
                dotted_string_input.push('.');
            }
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
