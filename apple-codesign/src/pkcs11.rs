use bytes::Bytes;
use cryptoki::{mechanism::Mechanism, session::UserType, types::AuthPin};
use signature::Signer;
use x509_certificate::{
    CapturedX509Certificate, KeyAlgorithm, Sign, Signature, SignatureAlgorithm,
    X509CertificateError,
};
use zeroize::Zeroizing;

use crate::{cli::certificate_source::SigningCertificates, remote_signing::RemoteSignError};
use {
    crate::{
        cryptography::PrivateKey, remote_signing::session_negotiation::PublicKeyPeerDecrypt,
        AppleCodesignError,
    },
    cryptoki::{
        context::Pkcs11,
        object::{Attribute, AttributeType, ObjectClass},
    },
    x509_certificate::KeyInfoSigner,
};

#[derive(Clone)]
pub(crate) struct PKCS11Signer {
    pkcs11: Pkcs11,
    cert: CapturedX509Certificate,
}

impl PKCS11Signer {
    pub(crate) fn new(pkcs11: Pkcs11, cert: CapturedX509Certificate) -> Self {
        Self { pkcs11, cert }
    }
}

impl PublicKeyPeerDecrypt for PKCS11Signer {
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, RemoteSignError> {
        Err(RemoteSignError::Crypto(
            "decryption not yet implemented for PKCS11 stored keys".into(),
        ))
    }
}

impl Signer<Signature> for PKCS11Signer {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        // Implement the signing logic using PKCS11
        let slot = self
            .pkcs11
            .get_slots_with_token()
            .map_err(|e| signature::Error::from_source(e))?[0];
        let session = self
            .pkcs11
            .open_rw_session(slot)
            .map_err(|e| signature::Error::from_source(e))?;
        let pin = AuthPin::new("1234".into());
        session
            .login(UserType::User, Some(&pin))
            .map_err(|e| signature::Error::from_source(e))?;

        let search = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        let objects = session
            .find_objects(&search)
            .map_err(|e| signature::Error::from_source(e))?;
        for handle in objects {
            println!("found private key");
            let signature = session
                .sign(&Mechanism::RsaPkcs, handle, message)
                .map_err(|e| signature::Error::from_source(e))?;
            return Ok(signature.into());
        }

        Err(signature::Error::from_source("no private key found"))
    }
}

impl Sign for PKCS11Signer {
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
        let algorithm = self.signature_algorithm()?;

        Ok((self.try_sign(message)?.into(), algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        self.cert.key_algorithm()
    }

    fn public_key_data(&self) -> Bytes {
        self.cert.public_key_data()
    }

    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError> {
        self.cert
            .signature_algorithm()
            .ok_or(X509CertificateError::UnknownSignatureAlgorithm(format!(
                "{:?}",
                self.cert.signature_algorithm_oid()
            )))
    }

    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        // We never have access to private keys stored on hardware devices.
        None
    }

    fn rsa_primes(
        &self,
    ) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError> {
        Ok(None)
    }
}

impl KeyInfoSigner for PKCS11Signer {}

impl PrivateKey for PKCS11Signer {
    fn as_key_info_signer(&self) -> &dyn KeyInfoSigner {
        self
    }

    fn to_public_key_peer_decrypt(
        &self,
    ) -> Result<Box<dyn PublicKeyPeerDecrypt>, AppleCodesignError> {
        Ok(Box::new(self.clone()))
    }

    fn finish(&self) -> Result<(), AppleCodesignError> {
        Ok(())
    }
}
