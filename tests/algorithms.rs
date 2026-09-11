// Per-algorithm encode/decode roundtrips for every supported algorithm.
//
// PEM test keys below are throwaway keys generated for this test suite
// only (`openssl genpkey`); they sign no real tokens.
//
// unwrap/expect are the test signal here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use serde::{Deserialize, Serialize};
use tokenkit::service::{JwtAlgorithm, JwtConfig, JwtService};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct NumericClaims {
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

const RSA_2048_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4uuaIp1d/HIXK
6/lVQ0SNBii/JYfhz75QWqE15dxWincV8M/T4jffeTUNnwp7jvAmBkB00wK0JlKV
JWO7X5B0p4gCrbpXRIcgRxFj+GYBqHI7h5vcZEZiZ1gOs2QT/v6w5Y+7u2W/r/9a
IzIm/oysMuLWru8fYP/GneQR7UbccV8CFe5k/FjqW/8k3zaCAOXnvw+wk6nWKyev
Q9Y3Xg1wWybdn8cS4omZz2TtoPELmYVRKNsjgjbgPAKJOfBcedyBInZE01Xb+rN8
ONAwJbBkL7xpjBXknJzp5jfnH3Ia2bPuk1h1/7ISCoTiEzEtyZvgcdGRQEhd58+W
OT5MLjolAgMBAAECggEAHlhJVUpT46P+UFqZ/wkJQjcwS1Hxc8UJ6K4yjCWBn8+o
BzkjEpW3AuUos1+cO7a7uStOvEILUCd5almVe+qTUq5Qd8ws73fo0IMMFsVvkDco
6KF6l2X7b9+1BdkvB9/b25giF78NVEMnaZmde+1Vk1XakFR1IEzxRyGZnN5CxSQs
qZzg59Y30tc5Rcn7gLLZYO65za8dJ4+4uDSUswswHDTZ/m3dOvl78e16mVRvcmfI
9nIH94qpVcM3jeVeI/n8uqCDABvKWYAmjPtCdosL2cVqhc3Iz/hI5r2R34QzToOm
d2CqKGGTh+MOFB2S6Px+qdOSokivlWhVA8ELG9eb8QKBgQDu7gM3fUKGV5PuWJXK
/Nf17m6SzY/ALrMUh3kLzJrA8kx1XGXhngo7z+Oj083X+hvyyqTMIdzRhh2XUjL5
ABryJ9cwdviu7te1Bw8TMwlFE6P2jhS448YqUp+qrBTOpRiNuvzOBCBywgd922Hm
155WDGMArxwDYo/lyuTOv7cUDQKBgQDF7ZWxQ6e15MjY/6sozU+Z7q6ygAvY2YQs
B9xduqdCSBQWK1lpl4vXnif/3Ca2aQej5yUJgvf/XONOkdTry7RBeYuhGnEGFes3
sTMGiDK0CYWMKZ9q2VBGH1HbMLIWVZ4G8UZ8V6Y/4laEx+YRmM1KvjwCmSFoO6I9
C3leawzAeQKBgEJSr3Hnw1+nT9kJngsKxKfv16HIje67B9rbAC7WTN7iY3bwfxdx
10VjH72KPcmGE9wBhF1lyPYgVHZ8yslzzgcKKCG75KwqgJYvr2+U6y3RleIK7pWk
JI37AXdO7TevfHFbRnGpk5hHY+z7yOFbWQhpx9GYyh3mbitLdtgtP5TBAoGBAKv2
Ficzm4M56ZI21xMVBcK8j4VAIIrfuKi0j63TXDwG+YSlVwKZiwLjQudV80BqEhxB
13jjE+oGXurFYtMWYV69ZiWrHmVmJ710M9vJ+xtWZnP3Oa0Qb2DtFyYzsZYb/rcT
auTfFe7NC9RDBM1nD32Pt/2d41t27CbTUDhLE4IpAoGACjxSenoNlAdqzk3c+ugt
kcbqFm0Y4fEhn7e1ll55mWGU9eql5MDIijpVfcuO/GcxLsXpvnkwqI4m29WoxBIS
fvV5EgoWgcNheMFhTos3DuZdHr0fenx+1ZGITB4HftC3g4Nmb+ly2Ox/uhZ/OpKf
pKnx6KzY5k2Y9X4wbukK1Qo=
-----END PRIVATE KEY-----";

const EC_P256_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcHDEDVEzXE5RZwTh
UASQQ2Tfs9BEKpWOjmV/RMGGr5mhRANCAATL6Lb410UYtaA4wPn5NU9BNL6rWevE
vodSyCJktayqdOucSEI8U+kEGK9Z9n8LTY0rgZuU+1bbBmVgtpCfCN5e
-----END PRIVATE KEY-----";

const EC_P384_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDsqXnde5M8Z3QRqf2d
d8dcfnz1Wbw5nr+Xm1JzkeYQK1k9GmcCiCjH3sTov/IGztWhZANiAATPMiGkanWw
KMtoOHEop7Cp+k7GxzDhJ9Abjs+X8GxBjWVccYaVUJF+SUnVBfdznEFVabueIpVG
vCFrtwX8g4O+3Qo18Z3Q8UgGXyABNeXcqKq2FZldN6Q8Kp0lOHOo6vY=
-----END PRIVATE KEY-----";

const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOXHZq+vCcUhawi6/RDDStBfTyL1dAAGeSFcE5o2bQu4
-----END PRIVATE KEY-----";

/// Ed25519 PKCS#8 DER (the ED25519_PEM body, base64-decoded).
const ED25519_DER_HEX: &str = "302e020100300506032b657004220420e5c766afaf09c5216b08bafd10c34ad05f4f22f574000679215c139a366d0bb8";

const RSA_2048_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuLrmiKdXfxyFyuv5VUNE
jQYovyWH4c++UFqhNeXcVop3FfDP0+I333k1DZ8Ke47wJgZAdNMCtCZSlSVju1+Q
dKeIAq26V0SHIEcRY/hmAahyO4eb3GRGYmdYDrNkE/7+sOWPu7tlv6//WiMyJv6M
rDLi1q7vH2D/xp3kEe1G3HFfAhXuZPxY6lv/JN82ggDl578PsJOp1isnr0PWN14N
cFsm3Z/HEuKJmc9k7aDxC5mFUSjbI4I24DwCiTnwXHncgSJ2RNNV2/qzfDjQMCWw
ZC+8aYwV5Jyc6eY35x9yGtmz7pNYdf+yEgqE4hMxLcmb4HHRkUBIXefPljk+TC46
JQIDAQAB
-----END PUBLIC KEY-----";

/// RSA public key as PKCS#1 `RSAPublicKey` DER (SEQUENCE { n, e }).
const RSA_PUBLIC_PKCS1_DER_HEX: &str = "3082010a0282010100b8bae688a7577f1c85caebf95543448d0628bf2587e1cfbe505aa135e5dc568a7715f0cfd3e237df79350d9f0a7b8ef026064074d302b42652952563bb5f9074a78802adba57448720471163f86601a8723b879bdc64466267580eb36413fefeb0e58fbbbb65bfafff5a233226fe8cac32e2d6aeef1f60ffc69de411ed46dc715f0215ee64fc58ea5bff24df368200e5e7bf0fb093a9d62b27af43d6375e0d705b26dd9fc712e28999cf64eda0f10b99855128db238236e03c028939f05c79dc81227644d355dbfab37c38d03025b0642fbc698c15e49c9ce9e637e71f721ad9b3ee935875ffb2120a84e213312dc99be071d19140485de7cf96393e4c2e3a250203010001";

const EC_P256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy+i2+NdFGLWgOMD5+TVPQTS+q1nr
xL6HUsgiZLWsqnTrnEhCPFPpBBivWfZ/C02NK4GblPtW2wZlYLaQnwjeXg==
-----END PUBLIC KEY-----";

const EC_P384_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzzIhpGp1sCjLaDhxKKewqfpOxscw4SfQ
G47Pl/BsQY1lXHGGlVCRfklJ1QX3c5xBVWm7niKVRrwha7cF/IODvt0KNfGd0PFI
Bl8gATXl3KiqthWZXTekPCqdJThzqOr2
-----END PUBLIC KEY-----";

/// EC P-256 public key as SEC1 uncompressed point (0x04 || X || Y).
const EC_P256_PUBLIC_SEC1_HEX: &str = "04cbe8b6f8d74518b5a038c0f9f9354f4134beab59ebc4be8752c82264b5acaa74eb9c48423c53e90418af59f67f0b4d8d2b819b94fb56db066560b6909f08de5e";

const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAU7kDsr5puIyPP0wcnJVU/HX5XWbF+323g3XAhwf7Oc8=
-----END PUBLIC KEY-----";

/// Ed25519 public key, raw 32 bytes (SPKI wrapper stripped).
const ED25519_PUBLIC_RAW_HEX: &str =
    "53b903b2be69b88c8f3f4c1c9c9554fc75f95d66c5fb7db78375c08707fb39cf";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// Test-local convenience: set the issuer the roundtrip helper expects.
trait WithIssuer {
    fn with_issuer(self) -> JwtConfig;
}

impl WithIssuer for JwtConfig {
    fn with_issuer(mut self) -> JwtConfig {
        self.issuer = Some("issuer".to_string());
        self
    }
}

fn claims() -> NumericClaims {
    NumericClaims {
        sub: Some("user-1".to_string()),
        exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
        iss: Some("issuer".to_string()),
        aud: None,
    }
}

/// Encode + decode a roundtrip; both directions must succeed with
/// matching claims. Claims are computed once — two `now()` calls could
/// straddle a second boundary and flake the comparison.
fn assert_roundtrip(config: JwtConfig) {
    let service = JwtService::new(config);
    let expected = claims();
    let token = service.encode(&expected).unwrap();
    let decoded: NumericClaims = service.decode(&token).unwrap();
    assert_eq!(decoded, expected);
}

fn hmac_config(alg: JwtAlgorithm) -> JwtConfig {
    JwtConfig {
        algorithm: alg,
        secret: "symmetric-secret-for-roundtrip-tests".to_string(),
        issuer: Some("issuer".to_string()),
        ..Default::default()
    }
}

fn rsa_pem_config(alg: JwtAlgorithm) -> JwtConfig {
    JwtConfig {
        algorithm: alg,
        secret: RSA_2048_PEM.to_string(),
        public_key: Some(RSA_2048_PUBLIC_PEM.to_string()),
        issuer: Some("issuer".to_string()),
        ..Default::default()
    }
}

#[test]
fn roundtrip_hs256() {
    assert_roundtrip(hmac_config(JwtAlgorithm::HS256));
}

#[test]
fn roundtrip_hs384() {
    assert_roundtrip(hmac_config(JwtAlgorithm::HS384));
}

#[test]
fn roundtrip_hs512() {
    assert_roundtrip(hmac_config(JwtAlgorithm::HS512));
}

#[test]
fn roundtrip_rs256() {
    assert_roundtrip(rsa_pem_config(JwtAlgorithm::RS256));
}

#[test]
fn roundtrip_rs384() {
    assert_roundtrip(rsa_pem_config(JwtAlgorithm::RS384));
}

#[test]
fn roundtrip_rs512() {
    assert_roundtrip(rsa_pem_config(JwtAlgorithm::RS512));
}

#[test]
fn roundtrip_ps256() {
    assert_roundtrip(rsa_pem_config(JwtAlgorithm::PS256));
}

#[test]
fn roundtrip_ps384() {
    assert_roundtrip(rsa_pem_config(JwtAlgorithm::PS384));
}

#[test]
fn roundtrip_ps512() {
    assert_roundtrip(rsa_pem_config(JwtAlgorithm::PS512));
}

#[test]
fn roundtrip_es256() {
    assert_roundtrip(ec_config(
        JwtAlgorithm::ES256,
        EC_P256_PEM,
        EC_P256_PUBLIC_PEM,
    ));
}

#[test]
fn roundtrip_es384() {
    assert_roundtrip(ec_config(
        JwtAlgorithm::ES384,
        EC_P384_PEM,
        EC_P384_PUBLIC_PEM,
    ));
}

#[test]
fn roundtrip_eddsa_pem() {
    let config = JwtConfig::from_ed_pem(ED25519_PEM)
        .with_public_key(ED25519_PUBLIC_PEM)
        .with_issuer();
    assert_roundtrip(config);
}

#[test]
fn roundtrip_eddsa_der() {
    let config = JwtConfig::from_ed_der(hex_to_bytes(ED25519_DER_HEX))
        .with_der_public_key(hex_to_bytes(ED25519_PUBLIC_RAW_HEX))
        .with_issuer();
    assert_roundtrip(config);
}

fn ec_config(alg: JwtAlgorithm, private_pem: &str, public_pem: &str) -> JwtConfig {
    JwtConfig::from_ec_pem(alg, private_pem)
        .with_public_key(public_pem)
        .with_issuer()
}

/// Raw DER public key paths: RS256 via PKCS#1 `RSAPublicKey` DER and
/// ES256 via SEC1 point encoding.
#[test]
fn roundtrip_with_der_public_keys() {
    let rs256 = JwtConfig {
        algorithm: JwtAlgorithm::RS256,
        secret: RSA_2048_PEM.to_string(),
        der_public_key: Some(hex_to_bytes(RSA_PUBLIC_PKCS1_DER_HEX)),
        issuer: Some("issuer".to_string()),
        ..Default::default()
    };
    assert_roundtrip(rs256);

    let es256 = JwtConfig::from_ec_pem(JwtAlgorithm::ES256, EC_P256_PEM)
        .with_der_public_key(hex_to_bytes(EC_P256_PUBLIC_SEC1_HEX))
        .with_issuer();
    assert_roundtrip(es256);
}

/// ES384-signed tokens are rejected by an ES256 service (cross-algorithm
/// pinning within the EC family).
#[test]
fn cross_algorithm_within_ec_family_rejected() {
    let token = JwtService::new(ec_config(
        JwtAlgorithm::ES384,
        EC_P384_PEM,
        EC_P384_PUBLIC_PEM,
    ))
    .encode(&claims())
    .unwrap();
    assert!(
        JwtService::new(ec_config(
            JwtAlgorithm::ES256,
            EC_P256_PEM,
            EC_P256_PUBLIC_PEM
        ))
        .decode::<NumericClaims>(&token)
        .is_err()
    );
}

/// Malformed key material surfaces as `KeyLoading`, never a panic.
#[test]
fn bad_key_material_fails_cleanly() {
    let config = JwtConfig {
        algorithm: JwtAlgorithm::ES256,
        secret: "definitely-not-a-pem".to_string(),
        ..Default::default()
    };
    let service = JwtService::new(config);
    assert!(service.encode(&claims()).is_err());

    let config = JwtConfig {
        algorithm: JwtAlgorithm::EdDSA,
        secret: "definitely-not-a-pem".to_string(),
        ..Default::default()
    };
    assert!(JwtService::new(config).encode(&claims()).is_err());

    let config = JwtConfig {
        algorithm: JwtAlgorithm::RS256,
        secret: "definitely-not-a-pem".to_string(),
        ..Default::default()
    };
    assert!(
        JwtService::new(config)
            .decode::<NumericClaims>("h.p.s")
            .is_err()
    );
}

/// Every `JwtAlgorithm` maps to a distinct `jsonwebtoken::Algorithm`, and
/// the Debug name matches the JWT alg identifier.
#[test]
fn algorithm_mapping_and_names() {
    use tokenkit::service::{JwtAlgorithm as A, JwtConfig};
    let cases = [
        (A::HS256, "HS256"),
        (A::HS384, "HS384"),
        (A::HS512, "HS512"),
        (A::ES256, "ES256"),
        (A::ES384, "ES384"),
        (A::RS256, "RS256"),
        (A::RS384, "RS384"),
        (A::RS512, "RS512"),
        (A::PS256, "PS256"),
        (A::PS384, "PS384"),
        (A::PS512, "PS512"),
        (A::EdDSA, "EdDSA"),
    ];
    let mut seen = std::collections::HashSet::new();
    for (alg, name) in cases {
        let json_alg: jsonwebtoken::Algorithm = alg.into();
        assert!(seen.insert(json_alg), "duplicate mapping for {name}");
        let debug = format!(
            "{:?}",
            JwtConfig {
                algorithm: alg,
                ..Default::default()
            }
        );
        assert!(debug.contains(name), "{debug} must name {name}");
    }
}
