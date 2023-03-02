use super::*;

pub struct OutgoingMessage<T: Class> {
    pub transaction_id: TransactionId,
    pub body: T,
    pub software: bool,
    pub fingerprint: bool,
}

impl<T: Class> OutgoingMessage<T> {
    pub fn encode(&self) -> Bytes {
        let size = self.size();

        let mut buf = BytesMut::zeroed(size);

        // encode message type (and conduct sanity check for top two bits)
        let ty = ((T::METHOD & 0x1F80) << 2)
            | ((T::METHOD & 0x0070) << 1)
            | (T::METHOD & 0x000F)
            | ((T::CLASS & 0x0002) << 7)
            | ((T::CLASS & 0x0001) << 4);
        buf[0..2].copy_from_slice(&(ty & 0x3FFF).to_be_bytes());

        // skip encoding the message size
        // certain attributes require the size to only include up to the attribute
        // instead, the size is incremented as the message is encoded

        // encode the magic symbol
        buf[4..8].copy_from_slice(&MAGIC.to_be_bytes());

        // encode the transaction id
        buf[8..20].copy_from_slice(&self.transaction_id.0);

        // set initial offset to be the size of the header
        let mut offset = 20;

        // encode the message body
        self.body.encode(&mut buf, &mut offset);

        // encode the FINGERPRINT attribute, if desired
        if self.fingerprint {
            encode_attribute(&Fingerprint::Outgoing, &mut buf, &mut offset);
        }

        buf.into()
    }

    pub fn size(&self) -> usize {
        let mut size = 20 + self.body.size();

        if self.fingerprint {
            size += attribute_size!(static Fingerprint);
        }

        size
    }
}
