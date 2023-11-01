// i need a macro to write these macros

#[allow(unused_macros)]
macro_rules! RC_SUCCESS {
    () => {
        0
    };
}
//pub(crate) use RC_SUCCESS;

#[allow(unused_macros)]
macro_rules! RC_OPERATIONS_ERROR {
    () => {
        1
    };
}
//pub(crate) use RC_OPERATIONS_ERROR;

#[allow(unused_macros)]
macro_rules! RC_PROTOCOL_ERROR {
    () => {
        2
    };
}
//pub(crate) use RC_PROTOCOL_ERROR;

#[allow(unused_macros)]
macro_rules! RC_TIME_LIMIT_EXCEEDED {
    () => {
        3
    };
}
//pub(crate) use RC_TIME_LIMIT_EXCEEDED;


#[allow(unused_macros)]
macro_rules! RC_NO_SUCH_OBJECT {
    () => {
        32
    };
}
pub(crate) use RC_NO_SUCH_OBJECT;

#[allow(unused_macros)]
macro_rules! RC_INVALID_CREDENTIALS {
    () => {
        49
    };
}
pub(crate) use RC_INVALID_CREDENTIALS;

#[allow(unused_macros)]
macro_rules! RC_INSUFFICIENT_ACCESS_RIGHTS {
    () => {
        50
    };
}
//pub(crate) use RC_INSUFFICIENT_ACCESS_RIGHTS;

// todo global static hash map?
pub fn result_text(result_code: u32) -> String {
    match result_code {
        0 => "success", // no error
        1 => "operations error",
        2 => "protocol error",
        3 => "time limit exceeded",
        4 => "size limit exceeded",
        5 => "compare false", // no error
        6 => "compare true", // no error
        7 => "auth method not supported",
        8 => "stronger auth required",
        10 => "referral", // no error
        11 => "admin limit exceeded",
        12 => "unavailable critical extension",
        13 => "confidentiality required",
        14 => "SASL bind in progress", // no error
        16 => "no such attribute",
        17 => "undefined attribute",
        18 => "inapproprate matching",
        19 => "constraint violation",
        20 => "attribute or value exists",
        21 => "invalid attribute syntax",
        32 => "no such object",
        33 => "alias problem",
        34 => "invalid DN syntax",
        36 => "alias dereferencing problem",
        48 => "inappropriate authentication",
        49 => "invalid_credentials",
        50 => "insufficient_access_rights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwilling to perform",
        54 => "loop detected",
        64 => "naming violation",
        65 => "object class violation",
        66 => "not allowed on non-leaf",
        67 => "not allowed on RDN",
        68 => "entry already exists",
        69 => "object class mods prohibited",
        71 => "affects multiple DSAs (servers)",
        80 => "other",
        _ => "unknown",
    }
    .to_string()
}