use std::{
  fs::{self, File},
  io::Write,
  path::{Path, PathBuf},
};

use anyhow::{Context, Result};

struct CircuitFiles {
  r1cs_path: PathBuf,
}

const BASE_CIRCUIT_NAMES: &[&str] =
  &["plaintext_authentication", "http_verification", "json_extraction"];

fn read_file(path: &Path) -> Result<Vec<u8>> {
  fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
}

fn load_circuit_files(artifacts_dir: &Path, target_size: &str) -> Result<Vec<CircuitFiles>> {
  BASE_CIRCUIT_NAMES
    .iter()
    .map(|name| {
      let circuit_name = format!("{name}_{target_size}");
      let r1cs_path = artifacts_dir.join(format!("{circuit_name}.r1cs"));

      // Verify files exist before proceeding
      if !r1cs_path.exists() {
        anyhow::bail!("R1CS file not found: {}", r1cs_path.display());
      }

      Ok(CircuitFiles { r1cs_path })
    })
    .collect()
}

fn main() -> Result<()> {
  let args: Vec<String> = std::env::args().collect();
  if args.len() != 4 {
    anyhow::bail!("Usage: {} <artifacts_directory> <target_size> <max_rom_length>", args[0]);
  }

  let artifacts_dir = PathBuf::from(&args[1]);
  let target_size = &args[2];
  let max_rom_length = args[3].parse().context("Failed to parse max_rom_length as number")?;

  println!("Processing circuits for target size: {target_size}");
  println!("Loading circuit files from: {}", artifacts_dir.display());
  println!("Using max ROM length: {max_rom_length}");

  let circuit_files = load_circuit_files(&artifacts_dir, target_size)?;

  let r1cs_files = circuit_files
    .iter()
    .map(|cf| {
      let data = read_file(&cf.r1cs_path)?;
      Ok(proofs::program::data::R1CSType::Raw(data))
    })
    .collect::<Result<Vec<_>>>()?;

  println!("Generating `BackendData`...");

  let setup = proofs::setup::setup(&r1cs_files, max_rom_length);

  let output_file =
    artifacts_dir.join(format!("serialized_setup_{target_size}_rom_length_{max_rom_length}.bin",));
  println!("Writing output to: {}", output_file.display());

  let mut file = File::create(&output_file)
    .with_context(|| format!("Failed to create output file: {}", output_file.display()))?;

  file
    .write_all(&setup)
    .with_context(|| format!("Failed to write to output file: {}", output_file.display()))?;

  println!("Successfully completed setup for target size: {target_size}");
  Ok(())
}
