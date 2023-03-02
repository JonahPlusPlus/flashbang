/// A 96-bit transaction ID.
#[derive(Debug, PartialEq)]
pub struct TransactionId(pub [u8; 12]);

impl TransactionId {
    /// Creates a new transaction ID from a `u128`.
    ///
    /// The top 32 bits are discarded, leaving the bottom 96 bits.
    pub fn new(id: u128) -> Self {
        Self((id << 32).to_be_bytes()[0..12].try_into().unwrap())
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self(rand::random())
    }
}
