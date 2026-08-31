use criterion::{criterion_group, criterion_main, Criterion};
use tokenkit::claims::StandardClaims;
use tokenkit::service::{JwtConfig, JwtService, JwtAlgorithm};

fn setup_service() -> JwtService {
    let config = JwtConfig {
        algorithm: JwtAlgorithm::HS256,
        secret: "benchmark-secret-key-for-jwt-tokens".to_string(),
        issuer: Some("benchmark-app".to_string()),
        audience: Some("benchmark-audience".to_string()),
        ..Default::default()
    };
    JwtService::new(config)
}

fn bench_encode(c: &mut Criterion) {
    let service = setup_service();
    let claims = StandardClaims {
        sub: Some("user-42".to_string()),
        iss: Some("benchmark-app".to_string()),
        aud: Some("benchmark-audience".to_string()),
        role: Some("admin".to_string()),
        permissions: vec!["read".to_string(), "write".to_string()],
        ..Default::default()
    };

    c.bench_function("jwt_encode_standard_claims", |b| {
        b.iter(|| service.encode(&claims).unwrap());
    });
}

fn bench_decode(c: &mut Criterion) {
    let service = setup_service();
    let claims = StandardClaims {
        sub: Some("user-42".to_string()),
        iss: Some("benchmark-app".to_string()),
        aud: Some("benchmark-audience".to_string()),
        role: Some("admin".to_string()),
        permissions: vec!["read".to_string(), "write".to_string()],
        ..Default::default()
    };
    let token = service.encode(&claims).unwrap();

    c.bench_function("jwt_decode_standard_claims", |b| {
        b.iter(|| service.decode::<StandardClaims>(&token).unwrap());
    });
}

fn bench_roundtrip(c: &mut Criterion) {
    let service = setup_service();
    let claims = StandardClaims {
        sub: Some("user-42".to_string()),
        iss: Some("benchmark-app".to_string()),
        aud: Some("benchmark-audience".to_string()),
        role: Some("admin".to_string()),
        permissions: vec!["read".to_string(), "write".to_string()],
        ..Default::default()
    };

    c.bench_function("jwt_roundtrip_encode_decode", |b| {
        b.iter(|| {
            let token = service.encode(&claims).unwrap();
            service.decode::<StandardClaims>(&token).unwrap();
        });
    });
}

criterion_group!(benches, bench_encode, bench_decode, bench_roundtrip);
criterion_main!(benches);
