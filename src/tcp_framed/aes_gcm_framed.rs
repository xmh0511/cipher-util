use crate::ring_aes_gcm_cipher::AesGcmCipher;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use std::io;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LengthDelimitedCodec};

pub struct AesGcmFramed {
    aes_gcm: AesGcmCipher,
    framed: Framed<TcpStream, LengthDelimitedCodec>,
}
impl AesGcmFramed {
    pub fn new(stream: TcpStream, key: [u8; 32]) -> Self {
        Self {
            aes_gcm: AesGcmCipher::new_256(key),
            framed: Framed::new(stream, LengthDelimitedCodec::new()),
        }
    }
    pub fn new_framed(framed: Framed<TcpStream, LengthDelimitedCodec>, key: [u8; 32]) -> Self {
        Self {
            aes_gcm: AesGcmCipher::new_256(key),
            framed,
        }
    }
}
impl AesGcmFramed {
    pub async fn next(&mut self) -> Option<io::Result<BytesMut>> {
        match self.framed.next().await {
            Some(Ok(mut buf)) => match self.aes_gcm.decrypt(&mut buf) {
                Ok(len) => {
                    buf.truncate(len);
                    Some(Ok(buf))
                }
                Err(e) => Some(Err(e)),
            },
            rs => rs,
        }
    }
    pub async fn send(&mut self, mut buf: BytesMut) -> io::Result<()> {
        buf.resize(buf.len() + self.aes_gcm.reserved_len(), 0);
        self.aes_gcm.encrypt(&mut buf)?;
        self.framed.send(buf.freeze()).await
    }
    pub fn into_inner(self) -> Framed<TcpStream, LengthDelimitedCodec> {
        self.framed
    }
}

pub struct AesGcmReadFramed {
    aes_gcm: AesGcmCipher,
    framed: FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
}

pub struct AesGcmWriteFramed {
    aes_gcm: AesGcmCipher,
    framed: FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
}

impl AesGcmReadFramed {
    pub fn new(read_half: OwnedReadHalf, key: [u8; 32]) -> Self {
        Self {
            aes_gcm: AesGcmCipher::new_256(key),
            framed: FramedRead::new(read_half, LengthDelimitedCodec::new()),
        }
    }
    pub fn new_framed(
        framed: FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
        key: [u8; 32],
    ) -> Self {
        Self {
            aes_gcm: AesGcmCipher::new_256(key),
            framed,
        }
    }

    pub async fn next(&mut self) -> Option<io::Result<BytesMut>> {
        match self.framed.next().await {
            Some(Ok(mut buf)) => match self.aes_gcm.decrypt(&mut buf) {
                Ok(len) => {
                    buf.truncate(len);
                    Some(Ok(buf))
                }
                Err(e) => Some(Err(e)),
            },
            rs => rs,
        }
    }
    pub fn into_inner(self) -> FramedRead<OwnedReadHalf, LengthDelimitedCodec> {
        self.framed
    }
}

impl AesGcmWriteFramed {
    pub fn new(write_half: OwnedWriteHalf, key: [u8; 32]) -> Self {
        Self {
            aes_gcm: AesGcmCipher::new_256(key),
            framed: FramedWrite::new(write_half, LengthDelimitedCodec::new()),
        }
    }
    pub fn new_framed(
        framed: FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
        key: [u8; 32],
    ) -> Self {
        Self {
            aes_gcm: AesGcmCipher::new_256(key),
            framed,
        }
    }

    pub async fn send(&mut self, mut buf: BytesMut) -> io::Result<()> {
        buf.resize(buf.len() + self.aes_gcm.reserved_len(), 0);
        self.aes_gcm.encrypt(&mut buf)?;
        self.framed.send(buf.freeze()).await
    }
    pub fn into_inner(self) -> FramedWrite<OwnedWriteHalf, LengthDelimitedCodec> {
        self.framed
    }
}
