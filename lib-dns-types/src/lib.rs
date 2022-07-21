#![warn(clippy::pedantic)]
// TODO: fix
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::semicolon_if_nothing_returned)]
// Don't care enough to fix
#![allow(clippy::match_same_arms)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::wildcard_imports)]

pub mod hosts;
pub mod protocol;
pub mod zones;
