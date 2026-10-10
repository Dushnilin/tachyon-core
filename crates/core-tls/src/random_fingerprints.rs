//! Process-stable random policies, distinct from the captured browser tables.
//!
//! `random` chooses a modern browser, like the reference. `randomized` builds
//! a native randomized TLS 1.3 profile: cipher order, optional extensions and
//! extension order vary, while the negotiation essentials stay consistent.
//! This does not reproduce uTLS's seeded byte distribution. Always retain ALPN
//! for HTTP/2 callers, and keep supported groups paired with their key shares.

use std::sync::OnceLock;

use rand_core::{OsRng, RngCore};

use crate::fingerprints;
use crate::hello::{Ext, Template};

const BROWSERS: &[fn() -> Template] = &[
    fingerprints::chrome,
    fingerprints::firefox,
    fingerprints::edge,
    fingerprints::safari,
    fingerprints::ios,
];

pub(crate) fn random() -> Template {
    static PROFILE: OnceLock<Template> = OnceLock::new();
    PROFILE
        .get_or_init(|| BROWSERS[index(&mut OsRng, BROWSERS.len())]())
        .clone()
}

pub(crate) fn randomized() -> Template {
    static PROFILE: OnceLock<Template> = OnceLock::new();
    PROFILE.get_or_init(|| generate(&mut OsRng)).clone()
}

fn index(rng: &mut impl RngCore, upper: usize) -> usize {
    let upper = upper as u64;
    let limit = u64::MAX - u64::MAX % upper;
    loop {
        let draw = rng.next_u64();
        if draw < limit {
            return (draw % upper) as usize;
        }
    }
}

fn shuffle<T>(values: &mut [T], rng: &mut impl RngCore) {
    for i in (1..values.len()).rev() {
        values.swap(i, index(rng, i + 1));
    }
}

fn generate(rng: &mut impl RngCore) -> Template {
    let mut profile = fingerprints::chrome();
    let mut suites: Vec<[u8; 2]> = profile
        .cipher_suites
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        // Never randomly remove the TLS 1.3 suites our record layer supports.
        .filter(|pair| pair[0] == 0x13 || rng.next_u32() & 1 == 0)
        .collect();
    shuffle(&mut suites, rng);
    profile.cipher_suites = suites.into_iter().flatten().collect();
    profile.extensions.retain(|ext| {
        // These independent extensions are optional. SNI, ALPN, versions,
        // signatures, groups and shares are kept intact, including the hybrid.
        !matches!(ext, Ext::Static(0x0005 | 0x0012 | 0x001b | 0x0023, _)) || rng.next_u32() & 1 == 0
    });
    shuffle(&mut profile.extensions, rng);
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic entropy exercises many draws without flaky diversity tests.
    struct Draws(u64);

    impl RngCore for Draws {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn generated_profiles_vary_but_keep_negotiation_essentials() {
        let chrome = fingerprints::chrome();
        let required: Vec<_> = chrome
            .extensions
            .iter()
            .filter(|ext| {
                matches!(
                    ext,
                    Ext::Sni
                        | Ext::Alpn
                        | Ext::KeyShare(_)
                        | Ext::Static(0x000a | 0x000d | 0x002b | 0x002d, _)
                )
            })
            .collect();
        let mut rng = Draws(7);
        let first = generate(&mut rng);
        let mut different_order = false;
        let mut different_extensions = false;
        for _ in 0..128 {
            let profile = generate(&mut rng);
            for ext in &required {
                assert!(profile.extensions.contains(ext));
            }
            for suite in [[0x13, 1], [0x13, 2], [0x13, 3]] {
                assert!(profile.cipher_suites.as_chunks::<2>().0.contains(&suite));
            }
            different_order |= profile.cipher_suites != first.cipher_suites;
            different_extensions |= profile.extensions != first.extensions;
        }
        assert!(different_order);
        assert!(different_extensions);
    }

    #[tokio::test]
    async fn many_generated_profiles_complete_tls_with_h2() {
        use std::sync::Arc;

        use crate::client::{Config, Handshake};

        crate::install_default_provider();
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(fixtures.join("localhost.crt")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(fixtures.join("localhost.key")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let mut rng = Draws(19);
        for draw in 0..64 {
            let template = generate(&mut rng);
            let verifier = crate::verify::AcceptsAnything;
            let mut client = Handshake::new(Config {
                template: &template,
                server_name: "localhost",
                alpn: &[b"h2"],
                verifier: &verifier,
                reality: None,
                fragment: false,
                cipher_suites: Vec::new(),
            })
            .unwrap();
            let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn({
                let acceptor = acceptor.clone();
                async move {
                    let stream = acceptor.accept(theirs).await.unwrap();
                    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                }
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                client.run(&mut ours).await.unwrap();
                assert_eq!(client.alpn.as_deref(), Some(&b"h2"[..]));
                server.await.unwrap();
            })
            .await
            .unwrap_or_else(|_| panic!("profile draw {draw} timed out"));
        }
    }
}
