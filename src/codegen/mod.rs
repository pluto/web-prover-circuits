pub mod http;
pub mod integrated;
pub mod json;
use crate::FileType;

use clap::Parser;
use http::http_circuit_from_args;
use integrated::integrated_circuit;
use json::json_circuit_from_args;
use std::path::PathBuf;

#[derive(Parser, Debug)]
/// JSON Extractor arguments
pub struct ExtractorArgs {
    #[arg(value_enum)]
    subcommand: FileType,

    /// Name of the circuit (to be used in circomkit config)
    #[arg(long)]
    circuit_name: String,

    /// Path to the JSON/HTTP file
    #[arg(long)]
    input_file: PathBuf,

    /// Path to the lockfile
    #[arg(long)]
    lockfile: PathBuf,

    /// Optional circuit debug logs
    #[arg(long, short, action = clap::ArgAction::SetTrue)]
    debug: bool,
}

impl ExtractorArgs {
    pub fn subcommand(&self) -> FileType {
        self.subcommand.clone()
    }

    pub fn build_circuit(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.subcommand {
            FileType::Http => {
                http_circuit_from_args(self)?;
            }
            FileType::Json => {
                json_circuit_from_args(self)?;
            }
            FileType::Extended => {
                integrated_circuit(self)?;
            }
        }

        Ok(())
    }
}
