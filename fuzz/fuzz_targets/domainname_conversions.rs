#![no_main]
use libfuzzer_sys::fuzz_target;

use bytes::{BufMut, BytesMut};
use std::convert::TryFrom;

use dns_types::protocol::types::{DOMAINNAME_MAX_LEN, LABEL_MAX_LEN, DomainName, Label};

fn to_label_chr(octet: u8) -> u8 {
    // clamp it to the range [48, 122]
    let chr = octet % (123 - 48) + 48;
    if (chr >= 58 && chr <= 64) || (chr >= 91 && chr <= 96) {
        b'X'
    } else {
        chr
    }
}

fuzz_target!(|labels: Vec<Vec<u8>>| {
    let mut dotted_string_input = String::new();
    let mut labels_input = Vec::new();
    let mut output = String::new();

    let mut first_label = true;
    let mut len = 0;
    for label in labels {
        // if we're at the start of a new label we need at least 3 octets spare:
        // 1 octet label length + 1 octet label + 1 octet end marker; if we have
        // less space than that, we can't fit in a new label before the end
        if len >= DOMAINNAME_MAX_LEN - 3 {
            break;
        }

        len += 1;

        if first_label {
            first_label = false;
        } else {
            dotted_string_input.push('.');
            output.push('.');
        }

        let mut octets = BytesMut::new();
        if label.len() == 0 {
            let chr = b'A';
            octets.put_u8(chr);
            dotted_string_input.push(chr as char);
            output.push(chr.to_ascii_lowercase() as char);
            len += 1;
        } else {
            for octet in label {
                let chr = to_label_chr(octet);
                octets.put_u8(chr);
                dotted_string_input.push(chr as char);
                output.push(chr.to_ascii_lowercase() as char);
                len += 1;
                if octets.len() == LABEL_MAX_LEN || len == DOMAINNAME_MAX_LEN - 1 {
                    break;
                }
            }
        }
        labels_input.push(Label::try_from(&octets.freeze()[..]).unwrap());
    }

    labels_input.push(Label::new());
    dotted_string_input.push('.');
    output.push('.');

    if let Some(from_dotted_string) = DomainName::from_dotted_string(&dotted_string_input) {
        assert_eq!(output.clone(), from_dotted_string.to_dotted_string());
    } else {
        panic!("from_dotted_string failed: {}", &dotted_string_input);
    }

    if let Some(from_labels) = DomainName::from_labels(labels_input.clone()) {
        assert_eq!(output.clone(), from_labels.to_dotted_string());
    } else {
        panic!("from_labels failed");
    }

    assert_eq!(
        DomainName::from_dotted_string(&dotted_string_input).map(|d| d.to_dotted_string()),
        DomainName::from_labels(labels_input).map(|d| d.to_dotted_string())
    );
});
