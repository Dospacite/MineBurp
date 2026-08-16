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
}
