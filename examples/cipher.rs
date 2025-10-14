use cipher_util::rsa::{CipherUtil, gen_cert};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem_buf = gen_cert()?;
    let cipher = CipherUtil::from_pem_buf(pem_buf)?;
    let data = b"hello world";
    let encrypted_data = cipher.encrypt(data)?;
    println!("encrypted_data: {}", hex::encode(&encrypted_data));
    println!(
        "decrypted_data: {}",
        String::from_utf8_lossy(&cipher.decrypt(&encrypted_data)?)
    );
    Ok(())
}
