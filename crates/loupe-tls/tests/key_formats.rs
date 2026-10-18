//! Public throwaway keys check private-key format support.

use loupe_tls::{client_config, reqwest_client_config, server_config, Ca};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;

const RSA_PKCS1: &str = include_str!("fixtures/throwaway-rsa-pkcs1.pem");
const RSA_PKCS8: &str = include_str!("fixtures/throwaway-rsa-pkcs8.pem");
const EC_SEC1: &str = include_str!("fixtures/throwaway-ec-sec1.pem");
const EC_PKCS8: &str = include_str!("fixtures/throwaway-ec-pkcs8.pem");

#[test]
fn imported_supported_ca_keys_issue_verifiable_clients() {
	let keys = [
		KeyPair::from_pem(RSA_PKCS8).unwrap(),
		KeyPair::from_pem(EC_PKCS8).unwrap(),
		KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap(),
		KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
	];
	for key in keys {
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		let cert = params.self_signed(&key).unwrap();
		let imported = Ca::from_pem(&cert.pem(), &key.serialize_pem()).unwrap();
		let client = imported.mint_client("worker").unwrap();
		let client_der = CertificateDer::from(pem::parse(client.cert_pem).unwrap().into_contents());
		let mut roots = RootCertStore::empty();
		roots.add(cert.der().clone()).unwrap();
		let verifier = WebPkiClientVerifier::builder_with_provider(
			std::sync::Arc::new(roots),
			std::sync::Arc::new(rustls::crypto::ring::default_provider()),
		)
		.build()
		.unwrap();
		verifier.verify_client_cert(&client_der, &[], UnixTime::now()).unwrap();
	}
}

#[test]
fn loaders_accept_pkcs1_pkcs8_and_sec1_while_ca_import_stays_pkcs8() {
	for (pkcs8, alternative) in [(RSA_PKCS8, RSA_PKCS1), (EC_PKCS8, EC_SEC1)] {
		let key = KeyPair::from_pem(pkcs8).unwrap();
		let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		let cert = params.self_signed(&key).unwrap().pem();
		assert!(Ca::from_pem(&cert, pkcs8).is_ok());
		assert!(Ca::from_pem(&cert, alternative).is_err(), "CA import is PKCS#8-only");
		for pem in [pkcs8, alternative] {
			assert!(server_config(&cert, pem, &cert).is_ok());
			assert!(client_config(&cert, pem, &cert).is_ok());
			let config = reqwest_client_config(&cert, pem, &cert).unwrap();
			assert!(reqwest::Client::builder().use_preconfigured_tls(config).build().is_ok());
		}
		let first = format!("{pkcs8}{alternative}");
		assert!(Ca::from_pem(&cert, &first).is_ok());
		let first = format!("{alternative}{pkcs8}");
		assert!(Ca::from_pem(&cert, &first).is_err(), "CA import still selects first PEM block");
	}
}
