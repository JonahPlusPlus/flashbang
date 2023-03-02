//! Sample Request with Long-Term Authentication with MESSAGE-INTEGRITY-SHA256 and USERHASH
//!
//! Based off the test vector from RFC 8489 Appendix B.1 and Errata 6268
//!
//! https://datatracker.ietf.org/doc/html/rfc8489#appendix-B.1
//! https://www.rfc-editor.org/errata/eid6268

use flashbang::message::{
    attributes::*,
    methods::{Binding, MethodTy},
    *,
};

const MESSAGE: &[u8] = &[
    0x00, 0x01, 0x00, 0x90, //    Request type and message length
    0x21, 0x12, 0xa4, 0x42, //    Magic cookie
    0x78, 0xad, 0x34, 0x33, // }
    0xc6, 0xad, 0x72, 0xc0, // }  Transaction ID
    0x29, 0xda, 0x41, 0x2e, // }
    0x00, 0x1e, 0x00, 0x20, //    USERHASH attribute header
    0x4a, 0x3c, 0xf3, 0x8f, // }
    0xef, 0x69, 0x92, 0xbd, // }
    0xa9, 0x52, 0xc6, 0x78, // }
    0x04, 0x17, 0xda, 0x0f, // }  Userhash value (32  bytes)
    0x24, 0x81, 0x94, 0x15, // }
    0x56, 0x9e, 0x60, 0xb2, // }
    0x05, 0xc4, 0x6e, 0x41, // }
    0x40, 0x7f, 0x17, 0x04, // }
    0x00, 0x15, 0x00, 0x29, //    NONCE attribute header
    0x6f, 0x62, 0x4d, 0x61, // }
    0x74, 0x4a, 0x6f, 0x73, // }
    0x32, 0x41, 0x41, 0x41, // }
    0x43, 0x66, 0x2f, 0x2f, // }
    0x34, 0x39, 0x39, 0x6b, // }  Nonce value and padding (3 bytes)
    0x39, 0x35, 0x34, 0x64, // }
    0x36, 0x4f, 0x4c, 0x33, // }
    0x34, 0x6f, 0x4c, 0x39, // }
    0x46, 0x53, 0x54, 0x76, // }
    0x79, 0x36, 0x34, 0x73, // }
    0x41, 0x00, 0x00, 0x00, // }
    0x00, 0x14, 0x00, 0x0b, //    REALM attribute header
    0x65, 0x78, 0x61, 0x6d, // }
    0x70, 0x6c, 0x65, 0x2e, // }  Realm value (11  bytes) and padding (1 byte)
    0x6f, 0x72, 0x67, 0x00, // }
    0x00, 0x1d, 0x00, 0x04, //    PASSWORD-ALGORITHM attribute header
    0x00, 0x02, 0x00, 0x00, //    PASSWORD-ALGORITHM value (4 bytes)
    0x00, 0x1c, 0x00, 0x20, //    MESSAGE-INTEGRITY-SHA256 attribute header
    0xb5, 0xc7, 0xbf, 0x00, // }
    0x5b, 0x6c, 0x52, 0xa2, // }
    0x1c, 0x51, 0xc5, 0xe8, // }
    0x92, 0xf8, 0x19, 0x24, // }  HMAC-SHA256 value
    0x13, 0x62, 0x96, 0xcb, // }
    0x92, 0x7c, 0x43, 0x14, // }
    0x93, 0x09, 0x27, 0x8c, // }
    0xc6, 0x51, 0x8e, 0x65, // }
];

#[test]
fn encode() {
    let request = OutgoingMessage {
        transaction_id: TransactionId::new(0x78ad3433c6ad72c029da412e),
        body: Request {
            method: Binding {},
            authorization: Some(Authorization {
                credentials: Credentials::new_long_term(
                    Username::new("\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}"),
                    Nonce::new("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"),
                    Realm::new("example.org"),
                    "TheMatrIX",
                    true,
                    Some(SHA256_PASSWORD_ALGORITHM.clone()),
                ),
                integrity: Integrity::Sha256,
            }),
        },
        software: false,
        fingerprint: false,
    };

    let output = request.encode();

    assert_eq!(MESSAGE, &*output);
}

#[test]
fn decode() {
    let expected = IncomingMessage {
        transaction_id: TransactionId::new(0x78ad3433c6ad72c029da412e),
        body: ClassTy::Request {
            method: MethodTy::Binding(Binding),
            authorization: Some(Authorization {
                credentials: Credentials::new_long_term(
                    Username::new("\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}"),
                    Nonce::new("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"),
                    Realm::new("example.org"),
                    "TheMatrIX",
                    true,
                    Some(SHA256_PASSWORD_ALGORITHM.clone()),
                ),
                integrity: Integrity::Sha256,
            }),
        },
        software: None,
        fingerprint: None,
    };

    let output = IncomingMessage::decode(MESSAGE).expect("Failed to decode message");

    assert_eq!(expected, output, "{expected:#x?}\nvs\n{output:#x?}");
}
