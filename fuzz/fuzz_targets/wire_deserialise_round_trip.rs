#![no_main]
use libfuzzer_sys::fuzz_target;

use dns_types::protocol::types::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::from_octets(data) {
        let serialised = message.to_octets().unwrap();
        let deserialised = Message::from_octets(&serialised);
        assert_eq!(Ok(message), deserialised);
    }
});
