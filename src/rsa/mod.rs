use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
pub const BITS: usize = 2048;

pub struct CertPem {
    pub priv_key: Vec<u8>,
    pub pub_key: Vec<u8>,
}

pub fn gen_cert() -> Result<CertPem, std::io::Error> {
    let mut rng = OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, BITS).map_err(|e| std::io::Error::other(e.to_string()))?;
    let public_key = RsaPublicKey::from(&private_key);
    let private_key_pem = private_key
        .to_pkcs8_pem(Default::default())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let public_key_pem = public_key
        .to_public_key_pem(Default::default())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(CertPem {
        priv_key: private_key_pem.as_bytes().to_owned(),
        pub_key: public_key_pem.as_bytes().to_owned(),
    })
}

pub struct CipherUtil {
    priv_key: RsaPrivateKey,
    pub_key: RsaPublicKey,
}

impl CipherUtil {
    pub fn from_pem_buf(cert_pem: CertPem) -> Result<Self, std::io::Error> {
        let priv_key =
            RsaPrivateKey::from_pkcs8_pem(String::from_utf8_lossy(&cert_pem.priv_key).as_ref())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        let pub_key =
            RsaPublicKey::from_public_key_pem(String::from_utf8_lossy(&cert_pem.pub_key).as_ref())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self { priv_key, pub_key })
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let padding = Oaep::new::<Sha256>();
        let mut rng = OsRng;
        let encrypted_data = self
            .pub_key
            .encrypt(&mut rng, padding, data)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(encrypted_data)
    }
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let padding = Oaep::new::<Sha256>();
        let decrypted_data = self
            .priv_key
            .decrypt(padding, &encrypted_data)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(decrypted_data)
    }
}
