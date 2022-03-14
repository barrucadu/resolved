#![no_main]
use libfuzzer_sys::fuzz_target;

use resolved::protocol::types::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(deserialised) = Message::from_octets(data) {
        let serialised = deserialised.clone().to_octets().unwrap();
        let re_deserialised = Message::from_octets(&serialised);
        assert_eq!(Ok(deserialised), re_deserialised);
    }
});
