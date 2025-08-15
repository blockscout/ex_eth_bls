defmodule ExEthBls.Native do
  @moduledoc false

  @version Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :ex_eth_bls,
    crate: "ex_eth_bls",
    base_url: "https://github.com/blockscout/ex_eth_bls/releases/download/v#{@version}",
    force_build: System.get_env("EX_ETH_BLS_BUILD") in ["1", "true"],
    version: @version,
    nif_versions: ~w(2.16 2.17)

  # NIF stub implementations - these will be replaced by the compiled Rust code
  def key_gen(_key_material), do: :erlang.nif_error(:nif_not_loaded)
  def sk_to_pk(_private_key), do: :erlang.nif_error(:nif_not_loaded)
  def sign(_private_key, _message), do: :erlang.nif_error(:nif_not_loaded)
  def verify(_public_key, _message, _signature), do: :erlang.nif_error(:nif_not_loaded)
  def aggregate_public_keys(_public_keys), do: :erlang.nif_error(:nif_not_loaded)
  def aggregate_signatures(_signatures), do: :erlang.nif_error(:nif_not_loaded)
  def fast_aggregate_verify(_public_keys, _message, _signature), do: :erlang.nif_error(:nif_not_loaded)
  def aggregate_verify(_public_keys, _messages, _signature), do: :erlang.nif_error(:nif_not_loaded)
end
