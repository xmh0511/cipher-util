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

    /// 非原地加密，返回新的 BytesMut
    ///
    /// # 参数
    /// - `plaintext`: 明文数据
    ///
    /// # 返回
    /// - `Ok(BytesMut)`: 加密后的数据 [密文][tag(16字节)][nonce(12字节)]
    pub fn encrypt_copy(&self, plaintext: &[u8]) -> io::Result<BytesMut> {
        // 生成随机 nonce
        let mut nonce_raw = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_raw);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);

        // 准备输出缓冲区
        let mut output = BytesMut::with_capacity(plaintext.len() + ENCRYPTION_RESERVED);
        output.extend_from_slice(plaintext);
        output.resize(plaintext.len() + ENCRYPTION_RESERVED, 0);

        // 执行加密
        let tag = match &self {
            AesGcmCipher::AesGCM256(cipher, _) => {
                cipher.seal_in_place_separate_tag(
                    nonce,
                    aead::Aad::empty(),
                    &mut output[..plaintext.len()],
                )
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("AesGcm encryption failed: {e:?}"),
                        )
                    })?
            }
        };

        let tag = tag.as_ref();
        if tag.len() != 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AesGcm encryption failed: tag length error",
            ));
        }

        // 写入 tag 和 nonce
        output[plaintext.len()..plaintext.len() + 16].copy_from_slice(tag);
        output[plaintext.len() + 16..].copy_from_slice(&nonce_raw);

        Ok(output)
    }

    /// 非原地加密到已有的 BytesMut
    ///
    /// # 参数
    /// - `plaintext`: 明文数据
    /// - `output`: 输出缓冲区，会被清空并写入密文
    pub fn encrypt_copy_into(&self, plaintext: &[u8], output: &mut BytesMut) -> io::Result<()> {
        // 生成随机 nonce
        let mut nonce_raw = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_raw);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);

        // 准备输出缓冲区
        output.clear();
        output.reserve(plaintext.len() + ENCRYPTION_RESERVED);
        output.extend_from_slice(plaintext);
        output.resize(plaintext.len() + ENCRYPTION_RESERVED, 0);

        // 执行加密
        let tag = match &self {
            AesGcmCipher::AesGCM256(cipher, _) => {
                cipher.seal_in_place_separate_tag(
                    nonce,
                    aead::Aad::empty(),
                    &mut output[..plaintext.len()],
                )
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("AesGcm encryption failed: {e:?}"),
                        )
                    })?
            }
        };

        let tag = tag.as_ref();
        if tag.len() != 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AesGcm encryption failed: tag length error",
            ));
        }

        // 写入 tag 和 nonce
        output[plaintext.len()..plaintext.len() + 16].copy_from_slice(tag);
        output[plaintext.len() + 16..].copy_from_slice(&nonce_raw);

        Ok(())
    }

    /// 非原地解密，返回新的 BytesMut
    ///
    /// # 参数
    /// - `payload`: 加密数据 [密文][tag(16字节)][nonce(12字节)]
    ///
    /// # 返回
    /// - `Ok(BytesMut)`: 解密后的明文数据
    pub fn decrypt_copy(&self, payload: &[u8]) -> io::Result<BytesMut> {
        let data_len = payload.len();

        if data_len < ENCRYPTION_RESERVED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "AesGcm decryption failed: data length too small (expected at least {}, got {})",
                    ENCRYPTION_RESERVED, data_len
                ),
            ));
        }

        // 提取 nonce（最后 12 字节）
        let nonce_start = data_len - 12;
        let nonce_raw: [u8; 12] = payload[nonce_start..]
            .try_into()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to extract nonce from payload",
                )
            })?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);

        // 复制密文到输出缓冲区（包含 tag）
        let mut output = BytesMut::with_capacity(nonce_start);
        output.extend_from_slice(&payload[..nonce_start]);

        // 执行解密
        match &self {
            AesGcmCipher::AesGCM256(cipher, _) => {
                cipher
                    .open_in_place(nonce, aead::Aad::empty(), &mut output)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("AesGcm decryption failed: {e:?}"),
                        )
                    })?;
            }
        }

        // 移除 tag（解密成功后 ring 会自动移除 tag）
        output.truncate(data_len - ENCRYPTION_RESERVED);

        Ok(output)
    }

    /// 非原地解密到已有的 BytesMut
    ///
    /// # 参数
    /// - `payload`: 加密数据
    /// - `output`: 输出缓冲区，会被清空并写入明文
    pub fn decrypt_copy_into(&self, payload: &[u8], output: &mut BytesMut) -> io::Result<()> {
        let data_len = payload.len();

        if data_len < ENCRYPTION_RESERVED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "AesGcm decryption failed: data length too small (expected at least {}, got {})",
                    ENCRYPTION_RESERVED, data_len
                ),
            ));
        }

        let nonce_start = data_len - 12;
        let nonce_raw: [u8; 12] = payload[nonce_start..]
            .try_into()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to extract nonce from payload",
                )
            })?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);

        // 准备输出缓冲区
        output.clear();
        output.reserve(nonce_start);
        output.extend_from_slice(&payload[..nonce_start]);

        // 执行解密
        match &self {
            AesGcmCipher::AesGCM256(cipher, _) => {
                cipher
                    .open_in_place(nonce, aead::Aad::empty(), output)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("AesGcm decryption failed: {e:?}"),
                        )
                    })?;
            }
        }

        // 移除 tag
        output.truncate(data_len - ENCRYPTION_RESERVED);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_encrypt_decrypt_copy() {
        let cipher = AesGcmCipher::new_256([0; 32]);
        let plaintext = b"Hello, World! This is a test message.";

        // 非原地加密
        let encrypted = cipher.encrypt_copy(plaintext).unwrap();
        println!("Encrypted length: {}", encrypted.len());
        assert_eq!(encrypted.len(), plaintext.len() + ENCRYPTION_RESERVED);

        // 非原地解密
        let decrypted = cipher.decrypt_copy(&encrypted).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_copy_into() {
        let cipher = AesGcmCipher::new_256([1; 32]);
        let plaintext = b"Test message for copy_into methods";

        let mut encrypted = BytesMut::new();
        cipher.encrypt_copy_into(plaintext, &mut encrypted).unwrap();

        let mut decrypted = BytesMut::new();
        cipher.decrypt_copy_into(&encrypted, &mut decrypted).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_multiple_encryptions() {
        let cipher = AesGcmCipher::new_256([2; 32]);

        for i in 0..10 {
            let plaintext = format!("Message number {}", i);
            let encrypted = cipher.encrypt_copy(plaintext.as_bytes()).unwrap();
            let decrypted = cipher.decrypt_copy(&encrypted).unwrap();
            assert_eq!(&decrypted[..], plaintext.as_bytes());
        }
    }

    #[test]
    fn test_reuse_buffer() {
        let cipher = AesGcmCipher::new_256([3; 32]);
        let mut encrypted_buf = BytesMut::new();
        let mut decrypted_buf = BytesMut::new();

        for i in 0..5 {
            let plaintext = format!("Reuse buffer test {}", i);

            cipher.encrypt_copy_into(plaintext.as_bytes(), &mut encrypted_buf).unwrap();
            cipher.decrypt_copy_into(&encrypted_buf, &mut decrypted_buf).unwrap();

            assert_eq!(&decrypted_buf[..], plaintext.as_bytes());
        }
    }
}