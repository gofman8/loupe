use anyhow::{Context, Result};
use rcgen::{
	BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa, KeyPair,
	KeyUsagePurpose, SanType,
};

/// PEM-encoded cert + key. The key is plaintext PEM; callers are
/// responsible for keeping it safe (envelope-encrypted in the `secrets`
/// table on the server side, on-disk under restrictive perms on the
/// worker side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertBundle {
	pub cert_pem: String,
	pub key_pem: String,
}

/// In-memory certificate authority used to mint client and server certs.
///
/// `Ca::new` generates a fresh self-signed CA. `Ca::from_pem` rebuilds
/// one from previously persisted PEM (the server reloads its CA from the
/// envelope-encrypted `secrets` row on startup).
pub struct Ca {
	cert: rcgen::Certificate,
	key: KeyPair,
	cert_pem: String,
	key_pem: String,
}

impl Ca {
	pub fn new(common_name: &str) -> Result<Self> {
		let key = KeyPair::generate().context("generating CA key pair")?;
		let mut params = CertificateParams::default();
		params.distinguished_name = {
			let mut dn = DistinguishedName::new();
			dn.push(DnType::CommonName, common_name);
			dn.push(DnType::OrganizationName, "loupe");
			dn
		};
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages = vec![
			KeyUsagePurpose::KeyCertSign,
			KeyUsagePurpose::CrlSign,
			KeyUsagePurpose::DigitalSignature,
		];
		let cert = params.self_signed(&key).context("self-signing CA cert")?;
		let cert_pem = cert.pem();
		let key_pem = key.serialize_pem();
		Ok(Self { cert, key, cert_pem, key_pem })
	}

	pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
		let key = KeyPair::from_pem(key_pem).context("parsing CA key PEM")?;
		let params =
			CertificateParams::from_ca_cert_pem(cert_pem).context("parsing CA cert PEM")?;
		validate_imported_oids(&params).context("validating imported CA certificate OIDs")?;
		let cert = params.self_signed(&key).context("re-binding CA cert to key pair")?;
		Ok(Self { cert_pem: cert_pem.to_owned(), key_pem: key_pem.to_owned(), cert, key })
	}

	pub fn cert_pem(&self) -> &str {
		&self.cert_pem
	}

	pub fn key_pem(&self) -> &str {
		&self.key_pem
	}

	/// Mint a client cert. The cert's CN is `name`; subject-alt-names are
	/// not set because we identify clients by certificate fingerprint, not
	/// by hostname.
	pub fn mint_client(&self, name: &str) -> Result<CertBundle> {
		self.mint(name, &[], false)
	}

	/// Mint a server cert. `hostnames` populates SubjectAltName so clients
	/// can verify the server identity; pass at least one entry.
	pub fn mint_server(&self, common_name: &str, hostnames: &[String]) -> Result<CertBundle> {
		anyhow::ensure!(!hostnames.is_empty(), "mint_server requires at least one hostname");
		self.mint(common_name, hostnames, true)
	}

	fn mint(&self, common_name: &str, hostnames: &[String], is_server: bool) -> Result<CertBundle> {
		let key = KeyPair::generate().context("generating leaf key pair")?;
		let mut params = CertificateParams::new(hostnames.to_vec()).context("new leaf params")?;
		params.distinguished_name = {
			let mut dn = DistinguishedName::new();
			dn.push(DnType::CommonName, common_name);
			dn.push(DnType::OrganizationName, "loupe");
			dn
		};
		params.is_ca = IsCa::NoCa;
		params.key_usages =
			vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
		params.extended_key_usages = if is_server {
			vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth]
		} else {
			vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth]
		};
		let cert = params.signed_by(&key, &self.cert, &self.key).context("signing leaf cert")?;
		Ok(CertBundle { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
	}
}

// rcgen imports these OIDs without validating the decoded arcs. Its ASN.1
// writer panics for unsupported arcs, including some valid OIDs that the
// current parser decodes incorrectly. Reject them before re-encoding; changing
// an arc would change the certificate's identity or constraints.
fn validate_imported_oids(params: &CertificateParams) -> Result<()> {
	validate_name_oids(&params.distinguished_name)?;
	for san in &params.subject_alt_names {
		if let SanType::OtherName((oid, _)) = san {
			validate_oid(oid)?;
		}
	}
	if let Some(constraints) = &params.name_constraints {
		for subtree in constraints.permitted_subtrees.iter().chain(&constraints.excluded_subtrees) {
			if let GeneralSubtree::DirectoryName(name) = subtree {
				validate_name_oids(name)?;
			}
		}
	}
	Ok(())
}

fn validate_name_oids(name: &DistinguishedName) -> Result<()> {
	for (kind, _) in name.iter() {
		if let DnType::CustomDnType(oid) = kind {
			validate_oid(oid)?;
		}
	}
	Ok(())
}

fn validate_oid(oid: &[u64]) -> Result<()> {
	// Match yasna's encoding preconditions, including its strict bound when
	// combining the first two arcs into one u64 (the first arc adds at most 80).
	anyhow::ensure!(
		matches!(oid, [first, second, ..]
			if *first < 3 && *second < u64::MAX - 80 && (*first == 2 || *second < 40)),
		"unsupported certificate OID"
	);
	Ok(())
}

#[cfg(test)]
mod tests {
	use rcgen::{CustomExtension, SanType};

	use super::*;

	fn cert_with_oid(oid: &[u64], location: &str) -> (String, String) {
		let key = KeyPair::generate().unwrap();
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		let mut name = DistinguishedName::new();
		name.push(DnType::CustomDnType(oid.to_vec()), "test");
		match location {
			"subject" => params.distinguished_name = name,
			"other-name" => {
				params.subject_alt_names.push(SanType::OtherName((oid.to_vec(), "test".into())));
			},
			"permitted" | "excluded" => {
				// DirectoryName is explicitly tagged. Build the extension directly:
				// rcgen's constraint writer uses an implicit tag, which its parser
				// ignores and would make the test miss this import path entirely.
				let mut arcs = vec![u8::try_from(oid[0] * 40 + oid[1]).unwrap()];
				arcs.extend(oid[2..].iter().map(|arc| u8::try_from(*arc).unwrap()));
				let attribute = [der(0x06, arcs), der(0x0c, b"test".to_vec())].concat();
				let name = der(0x30, der(0x31, der(0x30, attribute)));
				let subtree = der(0x30, der(0xa4, name));
				let tag = if location == "permitted" { 0xa0 } else { 0xa1 };
				let constraints = der(0x30, der(tag, subtree));
				params
					.custom_extensions
					.push(CustomExtension::from_oid_content(&[2, 5, 29, 30], constraints));
			},
			_ => panic!("unknown OID location"),
		}
		(params.self_signed(&key).unwrap().pem(), key.serialize_pem())
	}

	// The test's small, fixed fields all use DER's one-byte length form.
	fn der(tag: u8, content: Vec<u8>) -> Vec<u8> {
		assert!(content.len() < 128);
		let mut encoded = vec![tag, u8::try_from(content.len()).unwrap()];
		encoded.extend(content);
		encoded
	}

	macro_rules! rejects_imported_oid {
		($test:ident, $location:literal, $oid:expr) => {
			#[test]
			fn $test() {
				let (cert, key) = cert_with_oid($oid, $location);
				assert!(
					Ca::from_pem(&cert, &key).is_err(),
					"unencodable imported OID must be rejected"
				);
			}
		};
	}

	// These ASN.1 OIDs are valid, but the current dependency decodes 0.0
	// as one arc and 2.40 as 3.0. Neither result is safe to re-encode.
	rejects_imported_oid!(rejects_short_subject_oid, "subject", &[0, 0]);
	rejects_imported_oid!(rejects_unsupported_subject_oid, "subject", &[2, 40]);
	rejects_imported_oid!(rejects_short_other_name_oid, "other-name", &[0, 0]);
	rejects_imported_oid!(rejects_unsupported_other_name_oid, "other-name", &[2, 40]);
	rejects_imported_oid!(rejects_short_permitted_oid, "permitted", &[0, 0]);
	rejects_imported_oid!(rejects_unsupported_permitted_oid, "permitted", &[2, 40]);
	rejects_imported_oid!(rejects_short_excluded_oid, "excluded", &[0, 0]);
	rejects_imported_oid!(rejects_unsupported_excluded_oid, "excluded", &[2, 40]);

	#[test]
	fn supported_custom_oids_survive_ca_reload() {
		for location in ["subject", "other-name", "permitted", "excluded"] {
			for oid in [&[0, 1][..], &[1, 39], &[2, 39], &[2, 5, 4, 42]] {
				let (cert, key) = cert_with_oid(oid, location);
				let before = CertificateParams::from_ca_cert_pem(&cert).unwrap();
				if matches!(location, "permitted" | "excluded") {
					let constraints = before.name_constraints.as_ref().unwrap();
					assert_eq!(
						constraints.permitted_subtrees.len() + constraints.excluded_subtrees.len(),
						1
					);
				}
				let ca = Ca::from_pem(&cert, &key).unwrap();
				assert_eq!(ca.cert.params().distinguished_name, before.distinguished_name);
				assert_eq!(ca.cert.params().subject_alt_names, before.subject_alt_names);
				assert_eq!(ca.cert.params().name_constraints, before.name_constraints);
				assert!(ca.mint_client("worker").is_ok());
				assert!(ca.mint_server("server", &["localhost".into()]).is_ok());
			}
		}
	}

	#[test]
	fn rejects_invalid_subject_oid() {
		let ca = Ca::new("loupe-test-ca").unwrap();
		let cert_pem = include_str!("../tests/fixtures/invalid-subject-oid.pem");
		assert!(
			Ca::from_pem(cert_pem, ca.key_pem()).is_err(),
			"invalid subject OID must be rejected"
		);
	}

	#[test]
	fn round_trips_through_pem() {
		let ca = Ca::new("loupe-test-ca").unwrap();
		let cert_pem = ca.cert_pem().to_owned();
		let key_pem = ca.key_pem().to_owned();
		let reloaded = Ca::from_pem(&cert_pem, &key_pem).unwrap();
		assert_eq!(reloaded.cert_pem(), cert_pem);
	}

	#[test]
	fn mints_client_and_server_certs() {
		let ca = Ca::new("loupe-test-ca").unwrap();
		let client = ca.mint_client("worker-1").unwrap();
		assert!(client.cert_pem.contains("BEGIN CERTIFICATE"));
		assert!(client.key_pem.contains("PRIVATE KEY"));

		let server = ca.mint_server("loupe-server", &["localhost".into()]).unwrap();
		assert!(server.cert_pem.contains("BEGIN CERTIFICATE"));
	}

	#[test]
	fn server_mint_requires_hostname() {
		let ca = Ca::new("loupe-test-ca").unwrap();
		assert!(ca.mint_server("loupe-server", &[]).is_err());
	}
}
