use clap::{Parser, Subcommand};
use std::{error::Error, path::PathBuf};

pub mod circuit_config;
pub mod codegen;
pub mod witness;

use crate::codegen::ExtractorArgs;

#[derive(Parser, Debug)]
#[command(name = "pabuild")]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Witness(WitnessType),
    Codegen(ExtractorArgs),
}

/// Lockfile file type
#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum FileType {
    Json,
    Http,
    Extended,
}

#[derive(Debug, Parser)]
pub enum WitnessType {
    Parser(ParserWitnessArgs),
    Extractor(ExtractorWitnessArgs),
}

/// Parser witness arguments
#[derive(Parser, Debug)]
pub struct ParserWitnessArgs {
    #[arg(value_enum)]
    subcommand: FileType,

    /// Path to the JSON file
    #[arg(long)]
    input_file: PathBuf,

    /// Name of the circuit (to be used in circomkit config)
    #[arg(long)]
    circuit_name: String,
}

#[derive(Parser, Debug)]
pub struct ExtractorWitnessArgs {
    #[arg(value_enum)]
    subcommand: FileType,

    /// Name of the circuit (to be used in circomkit config)
    #[arg(long)]
    circuit_name: String,

    /// Path to the JSON file
    #[arg(long)]
    input_file: PathBuf,

    /// Path to the lockfile
    #[arg(long)]
    lockfile: PathBuf,
}

pub fn main() -> Result<(), Box<dyn Error>> {
    match Args::parse().command {
        Command::Witness(witness_type) => match witness_type {
            WitnessType::Parser(args) => witness::parser_witness(args)?,
            WitnessType::Extractor(args) => witness::extractor_witness(args)?,
        },
        Command::Codegen(args) => args.build_circuit()?,
    };

    Ok(())
}
