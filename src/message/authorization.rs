use std::fmt::Debug;

use super::{attributes::*, meta::MessageMeta};

#[derive(Debug, PartialEq)]
pub struct Authorization {
    pub credentials: Credentials,
    pub integrity: Integrity,
}

impl Authorization {
    /// Encodes the authorization attributes.
    pub(crate) fn encode(&self, buf: &mut [u8], offset: &mut usize) {
        match &self.credentials {
            Credentials::LongTerm {
                username,
                nonce,
                realm,
                password,
                anonymity,
                algorithm,
            } => {
                match anonymity {
                    true => encode_attribute(
                        &Userhash::new(username.clone(), realm.clone()),
                        buf,
                        offset,
                    ),
                    false => encode_attribute(username, buf, offset),
                }

                encode_attribute(nonce, buf, offset);

                encode_attribute(realm, buf, offset);

                let default = MD5_PASSWORD_ALGORITHM;

                let alg = match algorithm {
                    Some(alg) => {
                        encode_attribute(alg, buf, offset);
                        &alg
                    }
                    None => &*default,
                };

                let key = format!("{username}:{realm}:{password}");

                let key = alg.hash(key.as_bytes());

                if (self.integrity == Integrity::Both) | (self.integrity == Integrity::Sha1) {
                    encode_attribute(&MessageIntegrity::new(&*key), buf, offset)
                }

                if (self.integrity == Integrity::Both) | (self.integrity == Integrity::Sha256) {
                    encode_attribute(&MessageIntegritySha256::new(&*key), buf, offset)
                }
            }
            Credentials::ShortTerm { username, password } => {
                encode_attribute(username, buf, offset);

                if (self.integrity == Integrity::Both) | (self.integrity == Integrity::Sha1) {
                    encode_attribute(&MessageIntegrity::new(password.as_bytes()), buf, offset);
                }

                if (self.integrity == Integrity::Both) | (self.integrity == Integrity::Sha256) {
                    encode_attribute(
                        &MessageIntegritySha256::new(password.as_bytes()),
                        buf,
                        offset,
                    );
                }
            }
        }
    }

    pub(crate) fn decode(buf: &[u8], meta: &MessageMeta) -> Option<Self> {
        let mut userhash = None;

        for attr in &meta.attributes {
            match attr.ty {
                Userhash::TY => {
                    userhash = Some(Userhash::decode(buf, attr));
                }
                _ => (),
            }
        }

        None
    }

    /// Calculates the size of the authorization attributes.
    pub(crate) fn size(&self) -> usize {
        let mut size = 0;

        match &self.credentials {
            Credentials::LongTerm {
                username,
                nonce,
                realm,
                anonymity,
                algorithm,
                ..
            } => {
                size += match anonymity {
                    true => attribute_size!(static Userhash),
                    false => attribute_size!(dyn username),
                };

                size += attribute_size!(dyn nonce);

                size += attribute_size!(dyn realm);

                if let Some(alg) = algorithm {
                    size += attribute_size!(dyn alg);
                }
            }
            Credentials::ShortTerm { username, .. } => {
                size += attribute_size!(dyn username);
            }
        }

        if (self.integrity == Integrity::Both) | (self.integrity == Integrity::Sha1) {
            size += attribute_size!(static MessageIntegrity);
        }

        if (self.integrity == Integrity::Both) | (self.integrity == Integrity::Sha256) {
            size += attribute_size!(static MessageIntegritySha256);
        }

        size
    }
}

#[derive(PartialEq)]
pub enum Credentials {
    /// Long-term credentials.
    LongTerm {
        username: Username,
        nonce: Nonce,
        realm: Realm,
        password: String,
        anonymity: bool,
        algorithm: Option<PasswordAlgorithm>,
    },
    /// Short-term credentials.
    ShortTerm {
        username: Username,
        password: String,
    },
}

// Implement Debug manually to prevent secret information from being leaked to logs.
impl Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials")
    }
}

impl Credentials {
    pub fn new_long_term(
        username: Username,
        nonce: Nonce,
        realm: Realm,
        password: impl ToString,
        anonymity: bool,
        algorithm: Option<PasswordAlgorithm>,
    ) -> Self {
        Self::LongTerm {
            username,
            nonce,
            realm,
            password: password.to_string(),
            anonymity,
            algorithm,
        }
    }

    pub fn new_short_term(username: Username, password: impl ToString) -> Self {
        Self::ShortTerm {
            username,
            password: password.to_string(),
        }
    }
}

#[derive(Default, PartialEq, Debug)]
pub enum Integrity {
    /// Both MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256 attributes.
    #[default]
    Both,
    /// The legacy MESSAGE-INTEGRITY attribute.
    Sha1,
    /// The MESSAGE-INTEGRITY-SHA256 attribute.
    Sha256,
}
