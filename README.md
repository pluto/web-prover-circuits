<h1 align="center">
  Web-Prover Circuits
</h1>

<div align="center">
  <a href="https://github.com/pluto/web-prover-circuits/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/pluto/spark?style=flat-square&logo=github&logoColor=8b949e&labelColor=282f3b&color=32c955" alt="Contributors" />
  </a>
  <a href="https://github.com/pluto/web-prover-circuits/actions/workflows/test.yml">
    <img src="https://img.shields.io/badge/tests-passing-32c955?style=flat-square&logo=github-actions&logoColor=8b949e&labelColor=282f3b" alt="Tests" />
  </a>
</div>

> [!WARNING]
> ⚠️ Repository No Longer Maintained ⚠️
>https://github.com/pluto/noir-web-prover-circuits
> This repository has been archived and is no longer maintained.
All development has moved to the [noir-web-prover-circuits](https://github.com/pluto/noir-web-prover-circuits) repository under the Pluto organization.

## Overview

`web-prover-circuits` is a project focused on implementing parsers and extractors/selective-disclosure for various data formats inside zero-knowledge circuits.
Specifically, these are designed to be used in an NIVC folding scheme.
Currently, our program layout looks like this:
![v0.9.0](docs/images/v0.9.0.png)

## Repository Structure

- `circuits/`: Current implementation of circuits
  - `chacha`: ChaCha encryption circuit
  - `http`: HTTP parser and extractor
  - `json`: JSON parser and extractor
    - `json` has its own documentation [here](docs/json.md)
  - `utils`: Utility circuits
  - `test`: Circuit tests
- `src/`: Rust public-params creation binary
- `examples/`: Reference examples for JSON and HTTP parsers

Documentation, in general, can be found in the `docs` directory.

## Getting Started

### Prerequisites

To use this repo, you will need to install the following dependencies.
These instructions should work on Linux/GNU and MacOS, but aren't guaranteed to work on Windows.

#### Install Rust
To install Rust, you need to run:
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
exec $SHELL
```
Check this is installed by running:
```sh
rustc --version && cargo --version
```
to see the path to your Rust compiler and Cargo package manager.

#### Install Circom
Succinctly, `cd` to a directory of your choosing and run:
```sh
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```
in order to install `circom` globally.

#### Install Node
First, install `nvm` by running:
```sh
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | bash
exec $SHELL
```
Now with `nvm` installed, run:
```sh
nvm install --lts
nvm use --lts
node --version && npm --version
```

#### Node packages
From the root of the repository, you can now run:
```sh
npm install
```
which will install all the necessary packages for working with Circom.
This includes executables `circomkit`, `snarkjs`, and `mocha` which are accessible with Node: `npx`.

##### Circomkit
This repository uses `circomkit` to manage Circom circuits.
To see what you can do with `circomkit`, we suggest running:
```
npx circomkit help
```
`circomkit` can essentially do everything you would want to do with these Circuits, though we can't guarantee all commands work properly.

**Example:**
For example, to compile the `plaintext_authentication`, you can run the following from the repository root:
```
npx circomkit compile plaintext_authentication_1024b
```
which implicitly checks the `circuits.json` for an object that points to the circuit's code itself.

If you are having trouble with `circomkit`, consider

##### Mocha
`mocha` will also be installed from before.
Running
```sh
npx mocha
```
will run every circuit test.
To filter tests, you can use the `-g` flag (very helpful!).

## License

Licensed under the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contributing

We welcome contributions to our open-source projects. If you want to contribute or follow along with contributor discussions, join our [main Telegram channel](https://t.me/pluto_xyz/1) to chat about Pluto's development.

Our contributor guidelines can be found in [CONTRIBUTING.md](./CONTRIBUTING.md). A good starting point is issues labelled 'bounty' in our repositories.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.
