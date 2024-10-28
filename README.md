<h1 align="center">
  Parser Attestor
</h1>

<div align="center">
  <a href="https://github.com/pluto/parser-attestor/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/pluto/spark?style=flat-square&logo=github&logoColor=8b949e&labelColor=282f3b&color=32c955" alt="Contributors" />
  </a>
  <a href="https://github.com/pluto/parser-attestor/actions/workflows/test.yaml">
    <img src="https://img.shields.io/badge/tests-passing-32c955?style=flat-square&logo=github-actions&logoColor=8b949e&labelColor=282f3b" alt="Tests" />
  </a>
  <a href="https://github.com/pluto/parser-attestor/actions/workflows/lint.yaml">
    <img src="https://img.shields.io/badge/lint-passing-32c955?style=flat-square&logo=github-actions&logoColor=8b949e&labelColor=282f3b" alt="Lint" />
  </a>
</div>

## Overview

`parser-attestor` is a project focused on implementing parsers and extractors/selective-disclosure for various data formats inside of zero-knowledge circuits.

## Repository Structure

- `circuits/`: Current implementation of circuits
  - `http`: HTTP parser and extractor
  - `json`: JSON parser and extractor
    - `json` has its own documentation [here](docs/json.md)
  - `utils`: Utility circuits
  - `test`: Circuit tests
- `src/`: Rust `pabuild` binary
  - `pabuild` has its own documentation [here](docs/pabuild.md)
- `examples/`: Reference examples for JSON and HTTP parsers

Documentation, in general, can be found in the `docs` directory.
We will add to this over time to make working with `parser-attestor` easier.

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
For example, to compile the `json-parser`, you can run the following from the repository root:
```
npx circomkit compile json-parser
```
which implicitly checks the `circuits.json` for an object that points to the circuit's code itself.

If you are having trouble with `circomkit`, consider:

##### SNARKJS
Likewise, `snarkjs` is used to handle proofs and verification under the hood.
There is [documentation](https://docs.circom.io/getting-started/compiling-circuits/) on Circom's usage to work with this.
We suggest starting at that link and carrying through to "Proving circuits with ZK".

##### Mocha
`mocha` will also be installed from before.
Running
```sh
npx mocha
```
will run every circuit test.
To filter tests, you can use the `-g` flag (very helpful!).


### Install `pabuild`
From the root of this repository, run:
```sh
cargo install --path .
```
to install the `pabuild` binary.
You can see a help menu with the subcommands by:
```sh
pabuild --help
```
This is our local Rust command line application.
Please see the [documentation](docs/pabuild.md) for how to use this alongside the other tools.


## License

Licensed under the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contributing

We welcome contributions to our open-source projects. If you want to contribute or follow along with contributor discussions, join our [main Telegram channel](https://t.me/pluto_xyz/1) to chat about Pluto's development.

Our contributor guidelines can be found in [CONTRIBUTING.md](./CONTRIBUTING.md). A good starting point is issues labelled 'bounty' in our repositories.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.
