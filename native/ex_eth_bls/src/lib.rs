use rustler::{Env, NifResult, Binary, NewBinary};

mod errors;
mod bls_utils;

use bls_utils::*;

#[rustler::nif]
fn key_gen<'a>(env: Env<'a>, key_material: Binary) -> NifResult<Binary<'a>> {
    let sk = generate_private_key(key_material.as_slice())?;
    let mut binary = NewBinary::new(env, 32);
    binary.as_mut_slice().copy_from_slice(&sk);
    Ok(Binary::from(binary))
}

#[rustler::nif] 
fn sk_to_pk<'a>(env: Env<'a>, private_key: Binary) -> NifResult<Binary<'a>> {
    let pk = private_key_to_public_key(private_key.as_slice())?;
    let mut binary = NewBinary::new(env, 48);
    binary.as_mut_slice().copy_from_slice(&pk);
    Ok(Binary::from(binary))
}

#[rustler::nif]
fn sign<'a>(env: Env<'a>, private_key: Binary, message: Binary) -> NifResult<Binary<'a>> {
    let signature = sign_message(private_key.as_slice(), message.as_slice())?;
    let mut binary = NewBinary::new(env, 96);
    binary.as_mut_slice().copy_from_slice(&signature);
    Ok(Binary::from(binary))
}

#[rustler::nif]
fn verify(public_key: Binary, message: Binary, signature: Binary) -> NifResult<bool> {
    verify_signature(public_key.as_slice(), message.as_slice(), signature.as_slice())
        .map_err(|e| e.into())
}

#[rustler::nif]
fn aggregate_public_keys<'a>(env: Env<'a>, public_keys: Vec<Binary>) -> NifResult<Binary<'a>> {
    let pk_bytes: Vec<&[u8]> = public_keys.iter().map(|pk| pk.as_slice()).collect();
    let aggregated = aggregate_public_keys_impl(&pk_bytes)?;
    let mut binary = NewBinary::new(env, 48);
    binary.as_mut_slice().copy_from_slice(&aggregated);
    Ok(Binary::from(binary))
}

#[rustler::nif]
fn aggregate_signatures<'a>(env: Env<'a>, signatures: Vec<Binary>) -> NifResult<Binary<'a>> {
    let sig_bytes: Vec<&[u8]> = signatures.iter().map(|sig| sig.as_slice()).collect();
    let aggregated = aggregate_signatures_impl(&sig_bytes)?;
    let mut binary = NewBinary::new(env, 96);
    binary.as_mut_slice().copy_from_slice(&aggregated);
    Ok(Binary::from(binary))
}

#[rustler::nif]
fn fast_aggregate_verify(public_keys: Vec<Binary>, message: Binary, signature: Binary) -> NifResult<bool> {
    let pk_bytes: Vec<&[u8]> = public_keys.iter().map(|pk| pk.as_slice()).collect();
    fast_aggregate_verify_impl(&pk_bytes, message.as_slice(), signature.as_slice())
        .map_err(|e| e.into())
}

#[rustler::nif]
fn aggregate_verify(public_keys: Vec<Binary>, messages: Vec<Binary>, signature: Binary) -> NifResult<bool> {
    let pk_bytes: Vec<&[u8]> = public_keys.iter().map(|pk| pk.as_slice()).collect();
    let msg_bytes: Vec<&[u8]> = messages.iter().map(|msg| msg.as_slice()).collect();
    aggregate_verify_impl(&pk_bytes, &msg_bytes, signature.as_slice())
        .map_err(|e| e.into())
}

rustler::init!("Elixir.ExEthBls.Native");
