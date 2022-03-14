#![no_main]
use libfuzzer_sys::fuzz_target;

use resolved::protocol::types::Message;

fuzz_target!(|message: Message| {
    let serialised = message.clone().to_octets().unwrap();
    let deserialised = Message::from_octets(&serialised);
    assert_eq!(Ok(message), deserialised);
});
