use aes::Aes128;
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use zeroize::Zeroize;

/// Stateful AES-128/CFB8 stream used by the Minecraft Java protocol.
#[derive(Debug)]
pub struct MinecraftCipher {
    cipher: Aes128,
    encrypt_shift_register: [u8; 16],
    decrypt_shift_register: [u8; 16],
}

impl MinecraftCipher {
    #[must_use]
    pub fn new(shared_secret: [u8; 16]) -> Self {
        let key = GenericArray::from(shared_secret);
        Self {
            cipher: Aes128::new(&key),
            encrypt_shift_register: shared_secret,
            decrypt_shift_register: shared_secret,
        }
    }

    /// A stream with an independent IV, which is what published test vectors
    /// use; Minecraft itself always uses the shared secret as the IV.
    #[cfg(test)]
    fn with_iv(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(&GenericArray::from(key)),
            encrypt_shift_register: iv,
            decrypt_shift_register: iv,
        }
    }

    pub fn encrypt(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            let input = *byte;
            let mut block = GenericArray::from(self.encrypt_shift_register);
            self.cipher.encrypt_block(&mut block);
            let output = input ^ block[0];
            self.encrypt_shift_register.copy_within(1.., 0);
            self.encrypt_shift_register[15] = output;
            *byte = output;
        }
    }

    pub fn decrypt(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            let input = *byte;
            let mut block = GenericArray::from(self.decrypt_shift_register);
            self.cipher.encrypt_block(&mut block);
            let output = input ^ block[0];
            self.decrypt_shift_register.copy_within(1.., 0);
            self.decrypt_shift_register[15] = input;
            *byte = output;
        }
    }
}

impl Drop for MinecraftCipher {
    fn drop(&mut self) {
        self.encrypt_shift_register.zeroize();
        self.decrypt_shift_register.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_and_decrypt_streams_round_trip() {
        let key = [0x42; 16];
        let mut encryptor = MinecraftCipher::new(key);
        let mut decryptor = MinecraftCipher::new(key);
        let mut first = b"first packet".to_vec();
        let mut second = b"second packet after state".to_vec();
        let original_first = first.clone();
        let original_second = second.clone();
        encryptor.encrypt(&mut first);
        encryptor.encrypt(&mut second);
        decryptor.decrypt(&mut first);
        decryptor.decrypt(&mut second);
        assert_eq!(first, original_first);
        assert_eq!(second, original_second);
    }

    /// NIST SP 800-38A, F.3.7 (CFB8-AES128.Encrypt) and F.3.8 (Decrypt). A
    /// round trip alone cannot catch a mistake made the same way in both
    /// directions; a published vector can.
    #[test]
    fn matches_the_nist_cfb8_vectors() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d").unwrap();
        let ciphertext = hex::decode("3b79424c9c0dd436bace9e0ed4586a4f32b9").unwrap();
        let key: [u8; 16] = key.try_into().unwrap();
        let iv: [u8; 16] = iv.try_into().unwrap();

        let mut encrypted = plaintext.clone();
        let mut stream = MinecraftCipher::with_iv(key, iv);
        // Split the input so register state across calls is covered too.
        let (first, second) = encrypted.split_at_mut(7);
        stream.encrypt(first);
        stream.encrypt(second);
        assert_eq!(encrypted, ciphertext);

        let mut decrypted = ciphertext;
        MinecraftCipher::with_iv(key, iv).decrypt(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }
}
