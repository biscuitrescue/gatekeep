//! OpenSSH public key parsing, fingerprinting and strength checks.

use std::fmt;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Ed25519,
    SkEd25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    SkEcdsaP256,
    Rsa,
    Dss,
}

impl Algorithm {
    pub const ALL: [Algorithm; 8] = [
        Algorithm::Ed25519,
        Algorithm::SkEd25519,
        Algorithm::EcdsaP256,
        Algorithm::EcdsaP384,
        Algorithm::EcdsaP521,
        Algorithm::SkEcdsaP256,
        Algorithm::Rsa,
        Algorithm::Dss,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ssh-ed25519",
            Algorithm::SkEd25519 => "sk-ssh-ed25519@openssh.com",
            Algorithm::EcdsaP256 => "ecdsa-sha2-nistp256",
            Algorithm::EcdsaP384 => "ecdsa-sha2-nistp384",
            Algorithm::EcdsaP521 => "ecdsa-sha2-nistp521",
            Algorithm::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
            Algorithm::Rsa => "ssh-rsa",
            Algorithm::Dss => "ssh-dss",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == name)
    }

    /// Whether the key lives on a hardware security key (FIDO2).
    pub fn is_hardware(self) -> bool {
        matches!(self, Algorithm::SkEd25519 | Algorithm::SkEcdsaP256)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strength {
    Ok,
    Weak(String),
    Forbidden(String),
}

/// A single public key as it appears in a `.pub` file or `authorized_keys` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub algorithm: Algorithm,
    /// Base64 key blob exactly as supplied.
    pub data: String,
    pub comment: Option<String>,
    /// `authorized_keys` options prefix (e.g. `from="10.0.0.0/8"`), if any.
    pub options: Option<String>,
    rsa_bits: Option<u32>,
    fingerprint: String,
}

impl PublicKey {
    /// Parses `[options] <type> <base64> [comment]`.
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim();
        if line.is_empty() {
            bail!("empty key");
        }

        let (options, rest) = match split_token(line) {
            (first, _) if Algorithm::from_name(first).is_some() => (None, line),
            (first, rest) => (Some(first.to_owned()), rest),
        };

        let (type_name, rest) = split_token(rest);
        let algorithm = Algorithm::from_name(type_name)
            .with_context(|| format!("unsupported key type {type_name:?}"))?;
        let (data, comment) = split_token(rest);
        if data.is_empty() {
            bail!("missing key data after {type_name}");
        }

        let blob = STANDARD
            .decode(data)
            .context("key data is not valid base64")?;
        let rsa_bits = check_blob(algorithm, &blob)?;
        let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob)));

        Ok(Self {
            algorithm,
            data: data.to_owned(),
            comment: (!comment.is_empty()).then(|| comment.to_owned()),
            options,
            rsa_bits,
            fingerprint,
        })
    }

    /// `SHA256:...` fingerprint, identical to `ssh-keygen -lf`.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn bits(&self) -> Option<u32> {
        self.rsa_bits
    }

    pub fn strength(&self) -> Strength {
        match (self.algorithm, self.rsa_bits) {
            (Algorithm::Dss, _) => {
                Strength::Forbidden("DSA keys are disabled in modern OpenSSH".into())
            }
            (Algorithm::Rsa, Some(bits)) if bits < 2048 => {
                Strength::Forbidden(format!("RSA key is only {bits} bits (minimum 2048)"))
            }
            (Algorithm::Rsa, Some(bits)) if bits < 3072 => Strength::Weak(format!(
                "RSA key is {bits} bits; use ssh-ed25519 or RSA >= 3072"
            )),
            _ => Strength::Ok,
        }
    }

    /// `<type> <base64>` without options or comment.
    pub fn openssh(&self) -> String {
        format!("{} {}", self.algorithm, self.data)
    }
}

/// Splits off the first whitespace-delimited token, honouring double quotes
/// so `command="a b"` stays intact.
fn split_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => return (&s[..i], s[i..].trim()),
            _ => {}
        }
    }
    (s, "")
}

/// Reads one SSH wire-format `string` (u32 length prefix + bytes).
fn read_string<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    if buf.len() < 4 {
        bail!("truncated key data");
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let rest = &buf[4..];
    if rest.len() < len {
        bail!("truncated key data");
    }
    let (value, tail) = rest.split_at(len);
    *buf = tail;
    Ok(value)
}

/// Checks the blob's embedded type matches the declared one. Returns the RSA
/// modulus size for RSA keys.
fn check_blob(algorithm: Algorithm, blob: &[u8]) -> Result<Option<u32>> {
    let mut buf = blob;
    let embedded = read_string(&mut buf)?;
    if embedded != algorithm.name().as_bytes() {
        bail!(
            "key data is a {:?} key but is labelled {}",
            String::from_utf8_lossy(embedded),
            algorithm
        );
    }
    match algorithm {
        Algorithm::Ed25519 | Algorithm::SkEd25519 => {
            if read_string(&mut buf)?.len() != 32 {
                bail!("ed25519 public key must be 32 bytes");
            }
            Ok(None)
        }
        Algorithm::Rsa => {
            let _exponent = read_string(&mut buf)?;
            let modulus = read_string(&mut buf)?;
            let significant: Vec<&u8> = modulus.iter().skip_while(|b| **b == 0).collect();
            let bits = match significant.first() {
                Some(first) => (significant.len() as u32 - 1) * 8 + (8 - first.leading_zeros()),
                None => bail!("RSA modulus is empty"),
            };
            Ok(Some(bits))
        }
        Algorithm::EcdsaP256
        | Algorithm::EcdsaP384
        | Algorithm::EcdsaP521
        | Algorithm::SkEcdsaP256 => {
            let curve = read_string(&mut buf)?;
            if !algorithm.name().contains(&*String::from_utf8_lossy(curve)) {
                bail!("ECDSA curve does not match key type");
            }
            read_string(&mut buf)?;
            Ok(None)
        }
        Algorithm::Dss => Ok(None),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAmKxq7w3LYLq9/o8LH8jKZr9v0RovlSnlbNWEUlCH3b alice-laptop";

    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    /// Builds a structurally valid RSA public key with a modulus of `bits` bits.
    pub fn rsa_key(bits: usize) -> String {
        let mut modulus = vec![0u8]; // mpint sign byte
        modulus.push(0x80);
        modulus.extend(std::iter::repeat_n(0xAB, bits / 8 - 1));
        let mut blob = ssh_string(b"ssh-rsa");
        blob.extend(ssh_string(&[1, 0, 1]));
        blob.extend(ssh_string(&modulus));
        format!("ssh-rsa {} test-rsa", STANDARD.encode(blob))
    }

    #[test]
    fn parses_ed25519_with_comment() {
        let key = PublicKey::parse(ED25519).unwrap();
        assert_eq!(key.algorithm, Algorithm::Ed25519);
        assert_eq!(key.comment.as_deref(), Some("alice-laptop"));
        assert_eq!(key.options, None);
        assert_eq!(key.strength(), Strength::Ok);
        assert!(key.fingerprint().starts_with("SHA256:"));
        assert_eq!(key.fingerprint().len(), "SHA256:".len() + 43);
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        // Expected value from `ssh-keygen -lf alice-laptop.pub`.
        let key = PublicKey::parse(ED25519).unwrap();
        assert_eq!(
            key.fingerprint(),
            "SHA256:z2RrueMuAIydoyIhi0K3GNCqGGdNxx3QADDTbVlQlbE"
        );
    }

    #[test]
    fn parses_options_prefix_with_quoted_spaces() {
        let line = format!(r#"command="echo hi there",no-pty {ED25519}"#);
        let key = PublicKey::parse(&line).unwrap();
        assert_eq!(
            key.options.as_deref(),
            Some(r#"command="echo hi there",no-pty"#)
        );
        assert_eq!(key.algorithm, Algorithm::Ed25519);
        assert_eq!(key.comment.as_deref(), Some("alice-laptop"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(PublicKey::parse("").is_err());
        assert!(PublicKey::parse("ssh-ed25519").is_err());
        assert!(PublicKey::parse("ssh-ed25519 not*base64").is_err());
        assert!(PublicKey::parse("ssh-foo AAAA").is_err());
    }

    #[test]
    fn rejects_mislabelled_key() {
        let data = ED25519.split_whitespace().nth(1).unwrap();
        let err = PublicKey::parse(&format!("ssh-rsa {data}")).unwrap_err();
        assert!(err.to_string().contains("labelled ssh-rsa"), "{err}");
    }

    #[test]
    fn grades_rsa_by_modulus_size() {
        let strong = PublicKey::parse(&rsa_key(4096)).unwrap();
        assert_eq!(strong.bits(), Some(4096));
        assert_eq!(strong.strength(), Strength::Ok);

        let weak = PublicKey::parse(&rsa_key(2048)).unwrap();
        assert!(matches!(weak.strength(), Strength::Weak(_)));

        let broken = PublicKey::parse(&rsa_key(1024)).unwrap();
        assert!(matches!(broken.strength(), Strength::Forbidden(_)));
    }

    #[test]
    fn hardware_keys_are_flagged() {
        assert!(Algorithm::SkEd25519.is_hardware());
        assert!(!Algorithm::Ed25519.is_hardware());
    }
}
