defmodule ExEthBls.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_eth_bls,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      description: "Ethereum BLS signature verification using BLST library",
      deps: deps(),
      package: package(),
      docs: docs(),
      source_url: "https://github.com/blockscout/ex_eth_bls"
    ]
  end

  defp package do
    [
      files: [
        "lib",
        "native/ex_eth_bls/.cargo",
        "native/ex_eth_bls/src",
        "native/ex_eth_bls/Cargo*",
        "checksum-*.exs",
        "mix.exs",
        "README.md"
      ],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/blockscout/ex_eth_bls"}
    ]
  end

  defp docs do
    [
      main: "ExEthBls",
      source_ref: "v#{Mix.Project.config()[:version]}",
      source_url: "https://github.com/blockscout/ex_eth_bls"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:test]},
      {:ex_doc, "~> 0.34.1", only: :dev, runtime: false},
      {:benchee, "~> 1.3", only: :test},
      {:rustler, ">= 0.0.0", optional: true},
      {:rustler_precompiled, "~> 0.8"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end
end
