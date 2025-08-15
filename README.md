# ExEthBls

ExEthBls is an Elixir library for BLS signature verification that wraps the highly optimized BLST library used by Ethereum 2.0. This library provides Ethereum-compatible BLS signature operations including signing, verification, and aggregation.

## Features

- ✅ BLS signature generation and verification
- ✅ Public key aggregation
- ✅ Signature aggregation
- ✅ Fast aggregate verification (all signatures on same message)
- ✅ Aggregate verification (different messages per signature)
- ✅ Ethereum 2.0 compatible BLS12-381 curve
- ✅ Uses the same highly optimized BLST library as Ethereum clients

## Installation

Add `ex_eth_bls` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_eth_bls, "~> 0.1.0"}
  ]
end
```

## Usage

### Basic Operations

```elixir
# Generate a private key from a seed
seed = :crypto.hash(:sha256, "my secret seed")
private_key = ExEthBls.key_gen!(seed)

# Derive the public key
public_key = ExEthBls.sk_to_pk!(private_key)

# Sign a message
message = "Hello, Ethereum!"
signature = ExEthBls.sign!(private_key, message)

# Verify the signature
ExEthBls.verify(public_key, message, signature)
# => true
```

### Signature Aggregation

```elixir
# Create multiple signers
signers = for i <- 1..3 do
  seed = :crypto.hash(:sha256, "signer#{i}")
  private_key = ExEthBls.key_gen!(seed)
  public_key = ExEthBls.sk_to_pk!(private_key)
  {private_key, public_key}
end

message = "Collective message"

# Each signer signs the same message
signers_with_signatures =
  signers
  |> Enum.map(fn {private_key, public_key} ->
    signature = ExEthBls.sign!(private_key, message)
    {signature, public_key}
  end)

{signatures, public_keys} = Enum.unzip(signers_with_signatures)

# Aggregate the signatures and public keys
aggregated_signature = ExEthBls.aggregate_signatures!(signatures)
aggregated_public_key = ExEthBls.aggregate_public_keys!(public_keys)

# Verify the aggregated signature
ExEthBls.verify(aggregated_public_key, message, aggregated_signature)
# => true

# Or use fast aggregate verification (more efficient)
ExEthBls.fast_aggregate_verify(public_keys, message, aggregated_signature)
# => true
```

### Different Messages per Signer

```elixir
# Each signer signs a different message
messages = ["message1", "message2", "message3"]

signers_with_messages =
  signers
  |> Enum.zip(messages)
  |> Enum.map(fn {{private_key, public_key}, message} ->
    signature = ExEthBls.sign!(private_key, message)
    {signature, public_key}
  end)

{signatures, public_keys} = Enum.unzip(signers_with_messages)
aggregated_signature = ExEthBls.aggregate_signatures!(signatures)

# Verify that each signer signed their respective message
ExEthBls.aggregate_verify(public_keys, messages, aggregated_signature)
# => true
```

## API Reference

### Key Generation

- `ExEthBls.key_gen(seed)` - Generate a private key from a seed (≥32 bytes)
- `ExEthBls.key_gen!(seed)` - Same as above but raises on error
- `ExEthBls.sk_to_pk(private_key)` - Derive public key from private key
- `ExEthBls.sk_to_pk!(private_key)` - Same as above but raises on error

### Signing and Verification

- `ExEthBls.sign(private_key, message)` - Sign a message
- `ExEthBls.sign!(private_key, message)` - Same as above but raises on error
- `ExEthBls.verify(public_key, message, signature)` - Verify a signature

### Aggregation

- `ExEthBls.aggregate_public_keys(public_keys)` - Aggregate multiple public keys
- `ExEthBls.aggregate_public_keys!(public_keys)` - Same as above but raises on error
- `ExEthBls.aggregate_signatures(signatures)` - Aggregate multiple signatures
- `ExEthBls.aggregate_signatures!(signatures)` - Same as above but raises on error

### Aggregate Verification

- `ExEthBls.fast_aggregate_verify(public_keys, message, signature)` - Verify aggregated signature where all signers signed the same message
- `ExEthBls.aggregate_verify(public_keys, messages, signature)` - Verify aggregated signature where each signer signed a different message

## Types

- `private_key` - 32-byte binary
- `public_key` - 48-byte binary (G1 point on BLS12-381)
- `signature` - 96-byte binary (G2 point on BLS12-381)

## Ethereum Compatibility

This library is designed to be compatible with Ethereum 2.0 BLS signatures. It uses:

- BLS12-381 elliptic curve
- G1 for public keys (48 bytes compressed)
- G2 for signatures (96 bytes compressed)
- Same domain separation tags as Ethereum 2.0

## Building from Source

If you need to build the native library from source, set the environment variable:

```bash
export EX_ETH_BLS_BUILD=true
mix deps.compile ex_eth_bls
```

This requires:

- Rust toolchain (1.70+)
- C compiler (for BLST)

## License

MIT License - see [LICENSE](LICENSE) for details.
