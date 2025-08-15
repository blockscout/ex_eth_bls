defmodule ExEthBlsTest do
  use ExUnit.Case
  use ExUnitProperties

  doctest ExEthBls

  property "cryptographic material should work with all seeds" do
    check all(seed <- StreamData.binary(min_length: 32, max_length: 64)) do
      private_key = ExEthBls.key_gen!(seed)
      public_key = ExEthBls.sk_to_pk!(private_key)

      message = "hello world"
      signature = ExEthBls.sign!(private_key, message)

      assert ExEthBls.verify(public_key, message, signature)

      refute ExEthBls.verify(public_key, "different message", signature)
    end
  end

  property "key generation should be deterministic" do
    check all(seed <- StreamData.binary(length: 32)) do
      private_key1 = ExEthBls.key_gen!(seed)
      private_key2 = ExEthBls.key_gen!(seed)

      assert private_key1 == private_key2

      public_key1 = ExEthBls.sk_to_pk!(private_key1)
      public_key2 = ExEthBls.sk_to_pk!(private_key2)

      assert public_key1 == public_key2
    end
  end

  property "signature aggregation should work" do
    message = "hello world"

    check all(seeds <- StreamData.list_of(StreamData.binary(length: 32), min_length: 2, max_length: 5)) do
      {public_keys, signatures} =
        seeds
        |> Enum.map(fn seed ->
          private_key = ExEthBls.key_gen!(seed)
          public_key = ExEthBls.sk_to_pk!(private_key)
          signature = ExEthBls.sign!(private_key, message)
          {public_key, signature}
        end)
        |> Enum.unzip()

      # Test aggregation
      aggregated_signature = ExEthBls.aggregate_signatures!(signatures)
      aggregated_public_key = ExEthBls.aggregate_public_keys!(public_keys)

      assert ExEthBls.fast_aggregate_verify(public_keys, message, aggregated_signature)

      assert ExEthBls.verify(aggregated_public_key, message, aggregated_signature)
    end
  end

  test "invalid inputs should be handled gracefully" do
    assert {:error, :invalid_seed} = ExEthBls.key_gen("short")

    assert {:error, :invalid_private_key} = ExEthBls.sk_to_pk("short")
    assert {:error, :invalid_private_key} = ExEthBls.sign("short", "message")

    refute ExEthBls.verify("short", "message", <<0::768>>)

    refute ExEthBls.verify(<<0::384>>, "message", "short")

    assert {:error, :no_valid_keys} = ExEthBls.aggregate_public_keys([])
    assert {:error, :no_valid_signatures} = ExEthBls.aggregate_signatures([])

    refute ExEthBls.fast_aggregate_verify([], "message", <<0::768>>)
  end

  test "different messages with aggregate verify" do
    seeds = [
      :crypto.hash(:sha256, "seed1"),
      :crypto.hash(:sha256, "seed2"),
      :crypto.hash(:sha256, "seed3")
    ]

    messages = ["message1", "message2", "message3"]

    {public_keys, signatures} =
      seeds
      |> Enum.zip(messages)
      |> Enum.map(fn {seed, message} ->
        private_key = ExEthBls.key_gen!(seed)
        public_key = ExEthBls.sk_to_pk!(private_key)
        signature = ExEthBls.sign!(private_key, message)
        {public_key, signature}
      end)
      |> Enum.unzip()

    aggregated_signature = ExEthBls.aggregate_signatures!(signatures)

    assert ExEthBls.aggregate_verify(public_keys, messages, aggregated_signature)

    wrong_messages = ["wrong1", "wrong2", "wrong3"]
    refute ExEthBls.aggregate_verify(public_keys, wrong_messages, aggregated_signature)
  end
end
