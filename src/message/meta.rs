use super::*;

pub struct MessageMeta {
    pub class: u16,
    pub method: u16,
    pub id: TransactionId,
    pub attributes: Vec<AttributeMeta>,
}

impl MessageMeta {
    pub fn decode(buf: &[u8]) -> Result<Self, IncomingError> {
        let buf_len = buf.len();

        if buf_len < 20 {
            return Err(IncomingError {
                ty: IncomingErrorTy::BadLength,
                reason: "Message length was too small for 20-byte header.".into(),
            });
        }

        if buf_len % 4 != 0 {
            return Err(IncomingError {
                ty: IncomingErrorTy::BadLength,
                reason: "Message length must be aligned to a 32-bit boundary.".into(),
            });
        }

        let ty = u16::from_be_bytes(buf[0..2].try_into().unwrap());

        if ty & 0xC000 != 0 {
            return Err(IncomingError {
                ty: IncomingErrorTy::BadFormat,
                reason: "The first two bits MUST be zero.".into(),
            });
        }

        let class = (ty & 0x0100) >> 7 | (ty & 0x0010) >> 4;

        let method = (ty & 0x3E00) >> 2 | (ty & 0x00E0) >> 1 | (ty & 0x000F);

        let len = u16::from_be_bytes(buf[2..4].try_into().unwrap());

        let magic = u32::from_be_bytes(buf[4..8].try_into().unwrap());

        if magic != MAGIC {
            return Err(IncomingError {
                ty: IncomingErrorTy::BadFormat,
                reason: "Magic number was incorrect.".into(),
            });
        }

        let id = TransactionId(buf[8..20].try_into().unwrap());

        let mut attributes = vec![];

        let mut idx = 0;

        while idx as u16 != len {
            let offset = idx + 20;
            let ty = u16::from_be_bytes(buf[offset..(offset + 2)].try_into().unwrap());
            let len =
                u16::from_be_bytes(buf[(offset + 2)..(offset + 4)].try_into().unwrap()) as usize;
            let offset = offset + 4;

            attributes.push(AttributeMeta { ty, offset, len });

            idx += (4 + len + 3) & !3;
        }

        Ok(Self {
            class,
            method,
            id,
            attributes,
        })
    }
}

pub struct AttributeMeta {
    pub ty: u16,
    pub offset: usize,
    pub len: usize,
}
