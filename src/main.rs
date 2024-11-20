use anyhow::{Context, Result};
use proofs::program::{
    self,
    data::{ProgramData, SetupData},
    setup,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

struct CircuitFiles {
    r1cs_path: PathBuf,
    graph_path: PathBuf,
}

const BASE_CIRCUIT_NAMES: &[&str] = &[
    "aes_gctr_nivc",
    "http_nivc",
    "json_extract_value",
    "json_mask_array_index",
    "json_mask_object",
];

const MAX_ROM_LENGTH: usize = 45;

fn read_binary_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
}

fn load_circuit_files(artifacts_dir: &Path, target_size: &str) -> Result<Vec<CircuitFiles>> {
    BASE_CIRCUIT_NAMES
        .iter()
        .map(|name| {
            let circuit_name = format!("{}_{}", name, target_size);
            let r1cs_path = artifacts_dir.join(format!("{}.r1cs", circuit_name));
            let graph_path = artifacts_dir.join(format!("{}.graph", circuit_name));

            // Verify files exist before proceeding
            if !r1cs_path.exists() {
                anyhow::bail!("R1CS file not found: {}", r1cs_path.display());
            }
            if !graph_path.exists() {
                anyhow::bail!("Graph file not found: {}", graph_path.display());
            }

            Ok(CircuitFiles {
                r1cs_path,
                graph_path,
            })
        })
        .collect()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        anyhow::bail!("Usage: {} <artifacts_directory> <target_size>", args[0]);
    }

    let artifacts_dir = PathBuf::from(&args[1]);
    let target_size = &args[2];

    println!("Processing circuits for target size: {}", target_size);
    println!("Loading circuit files from: {}", artifacts_dir.display());

    let circuit_files = load_circuit_files(&artifacts_dir, target_size)?;

    let setup_data = SetupData {
        r1cs_types: circuit_files
            .iter()
            .map(|cf| {
                let data = read_binary_file(&cf.r1cs_path)?;
                Ok(program::data::R1CSType::Raw(data))
            })
            .collect::<Result<Vec<_>>>()?,

        witness_generator_types: circuit_files
            .iter()
            .map(|cf| {
                let data = read_binary_file(&cf.graph_path)?;
                Ok(program::data::WitnessGeneratorType::Raw(data))
            })
            .collect::<Result<Vec<_>>>()?,

        max_rom_length: MAX_ROM_LENGTH,
    };

    println!("Generating public parameters...");
    let public_params = program::setup(&setup_data);
    let aux_params = public_params.aux_params();
    let serialized_aux_params =
        bincode::serialize(&aux_params).context("Failed to serialize auxiliary parameters")?;

    let output_file = artifacts_dir.join(format!("aux_params_{}.bin", target_size));
    println!("Writing output to: {}", output_file.display());

    let mut file = File::create(&output_file)
        .with_context(|| format!("Failed to create output file: {}", output_file.display()))?;

    file.write_all(&serialized_aux_params)
        .with_context(|| format!("Failed to write to output file: {}", output_file.display()))?;

    println!(
        "Successfully completed setup for target size: {}",
        target_size
    );
    Ok(())
}
