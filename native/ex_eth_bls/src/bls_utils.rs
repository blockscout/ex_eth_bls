use blst::{
    min_pk::{PublicKey, SecretKey, Signature, AggregatePublicKey, AggregateSignature},
    BLST_ERROR
};
use sha2::{Digest, Sha256};
use crate::errors::BlsError;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub fn generate_private_key(seed: &[u8]) -> Result<[u8; 32], BlsError> {
    if seed.len() != 32 {
        return Err(BlsError::InvalidSeed);
    }

    for salt in 0u32..1000 {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(b"BLS_KEYGEN_SALT");
        hasher.update(salt.to_be_bytes());
        let hash = hasher.finalize();
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash[..32]);
        
        if let Ok(secret_key) = SecretKey::from_bytes(&key_bytes) {
            return Ok(secret_key.to_bytes());
        }
    }
    
    Err(BlsError::InvalidSeed)
}

pub fn private_key_to_public_key(private_key_bytes: &[u8]) -> Result<[u8; 48], BlsError> {
    if private_key_bytes.len() != 32 {
        return Err(BlsError::InvalidPrivateKey);
    }

    let secret_key = SecretKey::from_bytes(private_key_bytes)
        .map_err(|_| BlsError::InvalidPrivateKey)?;
    
    let public_key = secret_key.sk_to_pk();
    Ok(public_key.to_bytes())
}

pub fn sign_message(private_key_bytes: &[u8], message: &[u8]) -> Result<[u8; 96], BlsError> {
    if private_key_bytes.len() != 32 {
        return Err(BlsError::InvalidPrivateKey);
    }

    let secret_key = SecretKey::from_bytes(private_key_bytes)
        .map_err(|_| BlsError::InvalidPrivateKey)?;
    
    let signature = secret_key.sign(message, DST, &[]);
    Ok(signature.to_bytes())
}

pub fn verify_signature(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool, BlsError> {
    if public_key_bytes.len() != 48 {
        return Err(BlsError::InvalidPublicKey);
    }
    if signature_bytes.len() != 96 {
        return Err(BlsError::InvalidSignature);
    }

    let public_key = PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| BlsError::InvalidPublicKey)?;
    
    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|_| BlsError::InvalidSignature)?;
    
    let result = signature.verify(true, message, DST, &[], &public_key, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

pub fn aggregate_public_keys_impl(public_keys_bytes: &[&[u8]]) -> Result<[u8; 48], BlsError> {
    if public_keys_bytes.is_empty() {
        return Err(BlsError::ZeroSizeInput);
    }

    let mut public_keys = Vec::new();
    
    for pk_bytes in public_keys_bytes {
        if pk_bytes.len() != 48 {
            continue; // Skip invalid public keys
        }
        
        match PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => public_keys.push(pk),
            Err(_) => continue, // Skip invalid public keys
        }
    }

    if public_keys.is_empty() {
        return Err(BlsError::ZeroSizeInput);
    }

    let public_key_refs: Vec<&PublicKey> = public_keys.iter().collect();
    let aggregate = AggregatePublicKey::aggregate(&public_key_refs, true)
        .map_err(|_| BlsError::CryptoError)?;

    Ok(aggregate.to_public_key().to_bytes())
}

pub fn aggregate_signatures_impl(signatures_bytes: &[&[u8]]) -> Result<[u8; 96], BlsError> {
    if signatures_bytes.is_empty() {
        return Err(BlsError::ZeroSizeInput);
    }

    let mut signatures = Vec::new();
    
    for sig_bytes in signatures_bytes {
        if sig_bytes.len() != 96 {
            continue;
        }
        
        match Signature::from_bytes(sig_bytes) {
            Ok(sig) => signatures.push(sig),
            Err(_) => continue,
        }
    }

    if signatures.is_empty() {
        return Err(BlsError::ZeroSizeInput);
    }

    let signature_refs: Vec<&Signature> = signatures.iter().collect();
    let aggregate = AggregateSignature::aggregate(&signature_refs, true)
        .map_err(|_| BlsError::CryptoError)?;

    Ok(aggregate.to_signature().to_bytes())
}

pub fn fast_aggregate_verify_impl(public_keys_bytes: &[&[u8]], message: &[u8], signature_bytes: &[u8]) -> Result<bool, BlsError> {
    if public_keys_bytes.is_empty() || signature_bytes.len() != 96 {
        return Err(BlsError::InvalidInput);
    }

    let mut public_keys = Vec::new();
    
    for pk_bytes in public_keys_bytes {
        if pk_bytes.len() != 48 {
            continue;
        }
        
        match PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => public_keys.push(pk),
            Err(_) => continue,
        }
    }

    if public_keys.is_empty() {
        return Err(BlsError::InvalidInput);
    }

    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|_| BlsError::InvalidSignature)?;
    
    let public_key_refs: Vec<&PublicKey> = public_keys.iter().collect();
    let result = signature.fast_aggregate_verify(true, message, DST, &public_key_refs);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

pub fn aggregate_verify_impl(public_keys_bytes: &[&[u8]], messages: &[&[u8]], signature_bytes: &[u8]) -> Result<bool, BlsError> {
    if public_keys_bytes.is_empty() || messages.is_empty() || 
       public_keys_bytes.len() != messages.len() || signature_bytes.len() != 96 {
        return Err(BlsError::InvalidInput);
    }

    let mut public_keys = Vec::new();
    
    for pk_bytes in public_keys_bytes {
        if pk_bytes.len() != 48 {
            return Err(BlsError::InvalidInput);
        }
        
        let pk = PublicKey::from_bytes(pk_bytes)
            .map_err(|_| BlsError::InvalidPublicKey)?;
        
        public_keys.push(pk);
    }

    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|_| BlsError::InvalidSignature)?;
    
    let public_key_refs: Vec<&PublicKey> = public_keys.iter().collect();
    let result = signature.aggregate_verify(true, messages, DST, &public_key_refs, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}
