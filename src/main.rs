use anyhow::{Context, Result};
// use client_side_prover::{
//     provider::{hyperkzg::EvaluationEngine, Bn256EngineKZG, GrumpkinEngine},
//     spartan::batched::BatchedRelaxedR1CSSNARK,
//     supernova::snark::CompressedSNARK,
// };
use proofs::program::{
    self,
    data::{ProgramData, SetupData},
    setup,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

// pub type E1 = Bn256EngineKZG;
// pub type E2 = GrumpkinEngine;
// pub type EE1 = EvaluationEngine<halo2curves::bn256::Bn256, E1>;
// pub type EE2 = client_side_prover::provider::ipa_pc::EvaluationEngine<E2>;
// pub type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
// pub type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

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

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
}

fn load_circuit_files(artifacts_dir: &Path, target_size: &str) -> Result<Vec<CircuitFiles>> {
    BASE_CIRCUIT_NAMES
        .iter()
        .map(|name| {
            let circuit_name = format!("{}_{}", name, target_size);
            let r1cs_path = artifacts_dir.join(format!("{}.r1cs", circuit_name));
            let graph_path = artifacts_dir.join(format!("{}.bin", circuit_name));

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
    if args.len() != 4 {
        anyhow::bail!(
            "Usage: {} <artifacts_directory> <target_size> <max_rom_length>",
            args[0]
        );
    }

    let artifacts_dir = PathBuf::from(&args[1]);
    let target_size = &args[2];
    let max_rom_length = args[3]
        .parse()
        .context("Failed to parse max_rom_length as number")?;

    println!("Processing circuits for target size: {}", target_size);
    println!("Loading circuit files from: {}", artifacts_dir.display());
    println!("Using max ROM length: {}", max_rom_length);

    let circuit_files = load_circuit_files(&artifacts_dir, target_size)?;

    let setup_data = SetupData {
        r1cs_types: circuit_files
            .iter()
            .map(|cf| {
                let data = read_file(&cf.r1cs_path)?;
                Ok(program::data::R1CSType::Raw(data))
            })
            .collect::<Result<Vec<_>>>()?,

        witness_generator_types: circuit_files
            .iter()
            .map(|cf| {
                let data = read_file(&cf.graph_path)?;
                Ok(program::data::WitnessGeneratorType::Raw(data))
            })
            .collect::<Result<Vec<_>>>()?,

        max_rom_length,
    };

    println!("Generating public parameters...");
    let public_params = program::setup(&setup_data);

    // TODO (autoparallel): Implement serde on the `ProverKey` and `VerifierKey` then uncomment this. Would be smarter to expose a function in `proofs` so we don't do as much here
    // let (pk, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params)?;

    // Write out the `ProverKey`
    // let serialized_pk =
    //     bincode::serialize(&pk).context("Failed to serialize auxiliary parameters")?;

    // let output_file = artifacts_dir.join(format!("prover_key_{}.bin", target_size));
    // println!("Writing output to: {}", output_file.display());

    // let mut file = File::create(&output_file)
    //     .with_context(|| format!("Failed to create output file: {}", output_file.display()))?;

    // file.write_all(&serialized_pk)
    //     .with_context(|| format!("Failed to write to output file: {}", output_file.display()))?;

    // Write out the `VerifierKey`
    // let serialized_vk =
    //     bincode::serialize(&vk).context("Failed to serialize auxiliary parameters")?;

    // let output_file = artifacts_dir.join(format!("prover_key_{}.bin", target_size));
    // println!("Writing output to: {}", output_file.display());

    // let mut file = File::create(&output_file)
    //     .with_context(|| format!("Failed to create output file: {}", output_file.display()))?;

    // file.write_all(&serialized_vk)
    //     .with_context(|| format!("Failed to write to output file: {}", output_file.display()))?;

    // Write out the `AuxParams`
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
