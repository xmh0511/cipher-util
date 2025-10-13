use bytes::BytesMut;
use rand::RngCore;
use ring::aead;
use ring::aead::{LessSafeKey, UnboundKey};
use std::io;

const ENCRYPTION_RESERVED: usize = 16 + 12;

#[derive(Clone)]
pub enum AesGcmCipher {
    AesGCM256(LessSafeKey, [u8; 32]),
}

impl AesGcmCipher {
    pub fn new_256(key: [u8; 32]) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        AesGcmCipher::AesGCM256(cipher, key)
    }
    pub fn reserved_len(&self) -> usize {
        ENCRYPTION_RESERVED
    }
    pub fn decrypt(&self, payload: &mut [u8]) -> io::Result<usize> {
        let data_len = payload.len();
        if data_len < ENCRYPTION_RESERVED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AesGcm decryption failed: data length too small",
            ));
        }
        let nonce_raw: [u8; 12] = payload[data_len - 12..].try_into().unwrap();

        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);

        let rs = match &self {
            AesGcmCipher::AesGCM256(cipher, _) => {
                cipher.open_in_place(nonce, aead::Aad::empty(), &mut payload[..data_len - 12])
            }
        };
        if let Err(e) = rs {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("AesGcm decryption failed: {e:?}"),
            ));
        }
        Ok(data_len - ENCRYPTION_RESERVED)
    }
    /// payload Sufficient length must be reserved
    pub fn encrypt(&self, payload: &mut [u8]) -> io::Result<()> {
        let data_len = payload.len();
        if data_len < ENCRYPTION_RESERVED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AesGcm encryption failed: data length too small",
            ));
        }
        let mut random = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut random);
        let nonce_raw = random;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);
        let rs = match &self {
            AesGcmCipher::AesGCM256(cipher, _) => cipher.seal_in_place_separate_tag(
                nonce,
                aead::Aad::empty(),
                &mut payload[..data_len - ENCRYPTION_RESERVED],
            ),
        };
        match rs {
            Ok(tag) => {
                let tag = tag.as_ref();
                if tag.len() != 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AesGcm encryption failed: tag length error",
                    ));
                }
                payload[data_len - ENCRYPTION_RESERVED..data_len - ENCRYPTION_RESERVED + 16]
                    .copy_from_slice(tag);
                payload[data_len - 12..].copy_from_slice(&random);
                Ok(())
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("AesGcm encryption failed: {e:?}"),
            )),
        }
    }
}
impl AesGcmCipher {
    pub fn decrypt_bytes(&self, payload: &mut BytesMut) -> io::Result<()> {
        let len = self.decrypt(payload)?;
        payload.truncate(len);
        Ok(())
    }
    pub fn encrypt_bytes(&self, payload: &[u8]) -> io::Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(payload.len() + self.reserved_len());
        buf.extend_from_slice(payload);
        buf.resize(payload.len() + self.reserved_len(), 0);
        self.encrypt(&mut buf)?;
        Ok(buf)
    }
}
#[test]
fn test_aes_gcm() {
    let d = AesGcmCipher::new_256([0; 32]);
    let src = [3; 100];
    let mut data = src;
    d.encrypt(&mut data).unwrap();
    println!("{data:?}");
    let len = d.decrypt(&mut data).unwrap();
    assert_eq!(&data[..len], &src[..len]);

    let src = "1234567890";
    let mut data = d.encrypt_bytes(src.as_bytes()).unwrap();
    println!("{data:?}");
    d.decrypt_bytes(&mut data).unwrap();
    assert_eq!(&data, src.as_bytes());
}
