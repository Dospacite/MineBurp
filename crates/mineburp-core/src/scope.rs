//! Target authorization patterns. DNS names are matched as names, never resolved.
use std::net::IpAddr;

use crate::Target;

pub fn validate(patterns: &[String]) -> Result<(), String> {
    if patterns.len() > 256 {
        return Err("scope permits at most 256 patterns".into());
    }
    for (index, pattern) in patterns.iter().enumerate() {
        parse(pattern)?;
        if patterns[..index].contains(pattern) {
            return Err(format!("duplicate scope pattern: {pattern}"));
        }
    }
    Ok(())
}

fn parse(pattern: &str) -> Result<(&str, Option<u16>), String> {
    if pattern.is_empty() || pattern.len() > 300 || pattern.trim() != pattern {
        return Err("invalid scope pattern".into());
    }
    let (host, port) = if let Some(rest) = pattern.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or("missing IPv6 bracket")?;
        (
            host,
            if rest.is_empty() {
                None
            } else {
                Some(
                    rest.strip_prefix(':')
                        .ok_or("invalid port")?
                        .parse::<u16>()
                        .map_err(|_| "invalid port")?,
                )
            },
        )
    } else if pattern.matches(':').count() == 1 {
        let (host, port) = pattern.rsplit_once(':').ok_or("invalid pattern")?;
        (host, Some(port.parse::<u16>().map_err(|_| "invalid port")?))
    } else {
        (pattern, None)
    };
    if port == Some(0) {
        return Err("port must be nonzero".into());
    }
    if let Some((ip, bits)) = host.split_once('/') {
        let ip: IpAddr = ip.parse().map_err(|_| "invalid CIDR address")?;
        let bits: u32 = bits.parse().map_err(|_| "invalid CIDR prefix")?;
        if bits > if ip.is_ipv4() { 32 } else { 128 } {
            return Err("invalid CIDR prefix".into());
        }
    } else if host.parse::<IpAddr>().is_err() {
        let name = host.strip_prefix("*.").unwrap_or(host);
        if name.is_empty()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err("invalid scope hostname".into());
        }
    }
    Ok((host, port))
}

pub fn contains(patterns: &[String], target: &Target) -> bool {
    patterns.is_empty()
        || patterns.iter().any(|pattern| {
            let Ok((host, port)) = parse(pattern) else {
                return false;
            };
            if port.is_some_and(|port| port != target.port) {
                return false;
            }
            let target_host = target.host.trim_start_matches('[').trim_end_matches(']');
            if let Some((network, bits)) = host.split_once('/') {
                let Ok(bits) = bits.parse::<u32>() else {
                    return false;
                };
                match (network.parse::<IpAddr>(), target_host.parse::<IpAddr>()) {
                    (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => {
                        bits == 0 || (u32::from(a) >> (32 - bits)) == (u32::from(b) >> (32 - bits))
                    }
                    (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => {
                        bits == 0
                            || (u128::from(a) >> (128 - bits)) == (u128::from(b) >> (128 - bits))
                    }
                    _ => false,
                }
            } else if let Some(suffix) = host.strip_prefix("*.") {
                let name = target_host.to_ascii_lowercase();
                let suffix = format!(".{}", suffix.to_ascii_lowercase());
                name.len() > suffix.len() && name.ends_with(&suffix)
            } else {
                match (host.parse::<IpAddr>(), target_host.parse::<IpAddr>()) {
                    (Ok(a), Ok(b)) => a == b,
                    _ => host.eq_ignore_ascii_case(target_host),
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_patterns() {
        for (pattern, host, port, expected) in [
            ("Example.com", "example.COM", 25565, true),
            ("*.example.com", "a.example.com", 25565, true),
            ("*.example.com", "example.com", 25565, false),
            ("*.example.com", "badexample.com", 25565, false),
            ("*.EXAMPLE.com:25565", "a.example.COM", 25565, true),
            ("*.example.com", "a.example.com.evil", 25565, false),
            ("0.0.0.0/0", "192.168.1.1", 25565, true),
            ("::/0", "2001:db8::1", 25565, true),
            ("example.com:25565", "example.com", 25566, false),
            ("10.0.0.0/8:25565", "10.2.3.4", 25565, true),
            ("10.0.0.0/8", "11.2.3.4", 25565, false),
            ("[2001:db8::/32]:25565", "2001:db8::1", 25565, true),
            ("2001:db8::/32", "2002::1", 25565, false),
            ("[::1]:25565", "::1", 25565, true),
        ] {
            let patterns = vec![pattern.to_owned()];
            validate(&patterns).unwrap();
            assert_eq!(
                contains(
                    &patterns,
                    &Target {
                        host: host.into(),
                        port
                    }
                ),
                expected,
                "{pattern} {host}"
            );
        }
        assert!(contains(
            &[],
            &Target {
                host: "anything.example".into(),
                port: 25565
            }
        ));
        for pattern in [
            "*",
            "example.com:0",
            "10.0.0.0/33",
            "::/129",
            "https://example.com",
            "",
        ] {
            assert!(validate(&[pattern.into()]).is_err());
        }
        assert!(validate(&["a.example".into(), "a.example".into()]).is_err());
    }
}
