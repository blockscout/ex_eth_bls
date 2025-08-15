defmodule ExEthBls do
  @moduledoc """
  ExEthBls provides utility to leverage BLS signatures using Ethereum-compatible
  BLS signature verification from Lighthouse crypto library.

  BLS scheme supports aggregation of public keys and aggregation of signatures.

  Here's a full example of signature verification:

      iex> seed = :crypto.hash(:sha256, "myseed")
      iex> {:ok, private_key} = ExEthBls.key_gen(seed)
      iex> {:ok, public_key} = ExEthBls.sk_to_pk(private_key)
      iex> message = "hello world"
      iex> {:ok, signature} = ExEthBls.sign(private_key, message)
      iex> ExEthBls.verify(public_key, message, signature)
      true
  """

  @type private_key :: <<_::256>>
  @type public_key :: <<_::384>>
  @type signature :: <<_::768>>

  alias __MODULE__.Native

  @doc """
  Generate a private key from a seed using the key generation algorithm.
  """
  @spec key_gen(seed :: binary()) :: {:ok, private_key()} | {:error, :invalid_seed}
  def key_gen(seed) when is_binary(seed) and byte_size(seed) >= 32 do
    key_material = binary_part(seed, 0, 32)

    case Native.key_gen(key_material) do
      {:error, _reason} -> {:error, :invalid_seed}
      private_key when is_binary(private_key) -> {:ok, private_key}
    end
  end

  def key_gen(_), do: {:error, :invalid_seed}

  @doc """
  Same as `key_gen/1` but raises on error
  """
  @spec key_gen!(seed :: binary()) :: private_key()
  def key_gen!(seed) do
    case key_gen(seed) do
      {:ok, private_key} -> private_key
      {:error, :invalid_seed} -> raise "Invalid seed"
    end
  end

  @doc """
  Generate a public key from a private key
  """
  @spec sk_to_pk(private_key :: private_key()) :: {:ok, public_key()} | {:error, :invalid_private_key}
  def sk_to_pk(private_key) when is_binary(private_key) and byte_size(private_key) == 32 do
    case Native.sk_to_pk(private_key) do
      {:error, _reason} -> {:error, :invalid_private_key}
      public_key when is_binary(public_key) -> {:ok, public_key}
    end
  end

  def sk_to_pk(_), do: {:error, :invalid_private_key}

  @doc """
  Same as `sk_to_pk/1` but raises on error
  """
  @spec sk_to_pk!(private_key :: private_key()) :: public_key()
  def sk_to_pk!(private_key) do
    case sk_to_pk(private_key) do
      {:ok, public_key} -> public_key
      {:error, :invalid_private_key} -> raise "Invalid private key"
    end
  end

  @doc """
  Sign a message using a private key
  """
  @spec sign(private_key :: private_key(), message :: binary()) :: {:ok, signature()} | {:error, :invalid_private_key}
  def sign(private_key, message) when is_binary(private_key) and byte_size(private_key) == 32 and is_binary(message) do
    case Native.sign(private_key, message) do
      {:error, _reason} -> {:error, :invalid_private_key}
      signature when is_binary(signature) -> {:ok, signature}
    end
  end

  def sign(_, _), do: {:error, :invalid_private_key}

  @doc """
  Same as `sign/2` but raises on error
  """
  @spec sign!(private_key :: private_key(), message :: binary()) :: signature()
  def sign!(private_key, message) do
    case sign(private_key, message) do
      {:ok, signature} -> signature
      {:error, :invalid_private_key} -> raise "Invalid private key"
    end
  end

  @doc """
  Verify a signature against a public key and message
  """
  @spec verify(public_key :: public_key(), message :: binary(), signature :: signature()) :: boolean()
  def verify(public_key, message, signature)
      when is_binary(public_key) and byte_size(public_key) == 48 and
             is_binary(message) and
             is_binary(signature) and byte_size(signature) == 96 do
    case Native.verify(public_key, message, signature) do
      {:error, _} -> false
      true -> true
      false -> false
    end
  end

  def verify(_, _, _), do: false

  @doc """
  Aggregate public keys into a single public key
  """
  @spec aggregate_public_keys(public_keys :: list(public_key())) ::
          {:ok, public_key()} | {:error, :no_valid_keys}
  def aggregate_public_keys(public_keys) when is_list(public_keys) and length(public_keys) > 0 do
    case Native.aggregate_public_keys(public_keys) do
      {:error, _reason} -> {:error, :no_valid_keys}
      public_key when is_binary(public_key) -> {:ok, public_key}
    end
  end

  def aggregate_public_keys(_), do: {:error, :no_valid_keys}

  @doc """
  Same as `aggregate_public_keys/1` but raises on error
  """
  @spec aggregate_public_keys!(public_keys :: list(public_key())) :: public_key()
  def aggregate_public_keys!(public_keys) do
    case aggregate_public_keys(public_keys) do
      {:ok, public_key} -> public_key
      {:error, :no_valid_keys} -> raise "No valid public keys"
    end
  end

  @doc """
  Aggregate signatures into a single signature
  """
  @spec aggregate_signatures(signatures :: list(signature())) ::
          {:ok, signature()} | {:error, :no_valid_signatures}
  def aggregate_signatures(signatures) when is_list(signatures) and length(signatures) > 0 do
    case Native.aggregate_signatures(signatures) do
      {:error, _reason} -> {:error, :no_valid_signatures}
      signature when is_binary(signature) -> {:ok, signature}
    end
  end

  def aggregate_signatures(_), do: {:error, :no_valid_signatures}

  @doc """
  Same as `aggregate_signatures/1` but raises on error
  """
  @spec aggregate_signatures!(signatures :: list(signature())) :: signature()
  def aggregate_signatures!(signatures) do
    case aggregate_signatures(signatures) do
      {:ok, signature} -> signature
      {:error, :no_valid_signatures} -> raise "No valid signatures"
    end
  end

  @doc """
  Fast aggregate verify - verify that all public keys signed the same message
  """
  @spec fast_aggregate_verify(public_keys :: list(public_key()), message :: binary(), signature :: signature()) ::
          boolean()
  def fast_aggregate_verify(public_keys, message, signature)
      when is_list(public_keys) and length(public_keys) > 0 and
             is_binary(message) and
             is_binary(signature) and byte_size(signature) == 96 do
    case Native.fast_aggregate_verify(public_keys, message, signature) do
      {:error, _} -> false
      true -> true
      false -> false
    end
  end

  def fast_aggregate_verify(_, _, _), do: false

  @doc """
  Aggregate verify - verify that each public key signed its corresponding message
  """
  @spec aggregate_verify(public_keys :: list(public_key()), messages :: list(binary()), signature :: signature()) ::
          boolean()
  def aggregate_verify(public_keys, messages, signature)
      when is_list(public_keys) and is_list(messages) and
             length(public_keys) == length(messages) and length(public_keys) > 0 and
             is_binary(signature) and byte_size(signature) == 96 do
    case Native.aggregate_verify(public_keys, messages, signature) do
      {:error, _} -> false
      true -> true
      false -> false
    end
  end

  def aggregate_verify(_, _, _), do: false
end
