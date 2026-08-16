use std::fmt::Write as _;

use sha1::{Digest as _, Sha1};

/// Computes Minecraft's signed hexadecimal SHA-1 server identifier.
#[must_use]
pub fn minecraft_server_hash(server_id: &str, shared_secret: &[u8], public_key: &[u8]) -> String {
    let digest = Sha1::new()
        .chain_update(server_id.as_bytes())
        .chain_update(shared_secret)
        .chain_update(public_key)
        .finalize();
    let negative = digest[0] & 0x80 != 0;
    let mut magnitude = digest.to_vec();
    if negative {
        for byte in &mut magnitude {
            *byte = !*byte;
        }
        for byte in magnitude.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
    }
    let mut encoded = String::with_capacity(magnitude.len() * 2);
    for byte in magnitude.iter().skip_while(|byte| **byte == 0) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let encoded = encoded.trim_start_matches('0');
    let encoded = if encoded.is_empty() { "0" } else { encoded };
    if negative {
        format!("-{encoded}")
    } else {
        encoded.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::minecraft_server_hash;

    #[test]
    fn matches_notch_server_hash_vector() {
        assert_eq!(
            minecraft_server_hash("Notch", &[], &[]),
            "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
        );
    }

    #[test]
    fn matches_negative_server_hash_vector() {
        assert_eq!(
            minecraft_server_hash("jeb_", &[], &[]),
            "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1"
        );
    }
}
