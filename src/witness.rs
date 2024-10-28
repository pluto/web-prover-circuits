use serde::Serialize;

use crate::{
    codegen::{
        http::HttpData,
        integrated::ExtendedLockfile,
        json::{json_max_stack_height, Lockfile},
    },
    ExtractorWitnessArgs, FileType, ParserWitnessArgs,
};
use std::{collections::HashMap, io::Write, path::Path};

#[derive(Serialize)]
pub struct ParserWitness {
    data: Vec<u8>,
}

#[derive(Serialize)]
pub struct JsonExtractorWitness {
    data: Vec<u8>,

    #[serde(flatten)]
    keys: HashMap<String, Vec<u8>>,
}

#[derive(Serialize)]
pub struct HttpExtractorWitness {
    data: Vec<u8>,

    #[serde(flatten)]
    http_data: HttpData,
}

#[derive(Serialize)]
pub struct ExtendedWitness {
    #[serde(flatten)]
    http_witness: HttpExtractorWitness,
    #[serde(flatten)]
    keys: HashMap<String, Vec<u8>>,
}

fn print_boxed_output(lines: Vec<String>) {
    // Determine the maximum length of the lines
    let max_length = lines.iter().map(|line| line.len()).max().unwrap_or(0);

    // Characters for the box
    let top_border = format!("┌{}┐", "─".repeat(max_length + 2));
    let bottom_border = format!("└{}┘", "─".repeat(max_length + 2));

    // Print the box with content
    println!("{}", top_border);
    for line in lines {
        println!("│ {:<width$} │", line, width = max_length);
    }
    println!("{}", bottom_border);
}

impl FileType {
    pub fn read_input(&self, input: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match self {
            FileType::Json => Ok(std::fs::read(input)?),
            FileType::Http | FileType::Extended => {
                let mut data = std::fs::read(input)?;
                let mut i = 0;
                // convert LF to CRLF
                while i < data.len() {
                    if data[i] == 10 && (i == 0 || data[i - 1] != 13) {
                        data.insert(i, 13);
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                Ok(data)
            }
        }
    }
}

fn write_witness(circuit_name: &str, witness: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut output_dir = std::env::current_dir()?;
    output_dir.push("inputs");
    output_dir.push(circuit_name);

    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir)?;
    }

    let output_file = output_dir.join("inputs.json");
    let mut file = std::fs::File::create(&output_file)?;

    file.write_all(witness)?;

    let output = format!("Witness file generated: {:?}", output_file.display());
    Ok(output)
}

pub fn parser_witness(args: ParserWitnessArgs) -> Result<(), Box<dyn std::error::Error>> {
    let data = args.subcommand.read_input(&args.input_file)?;

    let witness = ParserWitness { data: data.clone() };

    let output = write_witness(
        &args.circuit_name,
        serde_json::to_string_pretty(&witness)?.as_bytes(),
    )?;

    // Prepare lines to print
    let mut lines = Vec::new();
    lines.push(format!("Data length: {}", data.len()));

    if args.subcommand == FileType::Json {
        lines.push(format!(
            "Max stack height: {}",
            json_max_stack_height(&data)
        ))
    }

    lines.push(output);

    // Print the output inside a nicely formatted box
    print_boxed_output(lines);

    Ok(())
}

fn json_extractor_witness(args: ExtractorWitnessArgs) -> Result<(), Box<dyn std::error::Error>> {
    // read input and lockfile
    let input_data = args.subcommand.read_input(&args.input_file)?;

    let lockfile_data = std::fs::read(&args.lockfile)?;
    let lockfile: Lockfile = serde_json::from_slice(&lockfile_data)?;

    // create extractor witness data
    let witness = JsonExtractorWitness {
        data: input_data.clone(),
        keys: lockfile.keys_as_bytes(),
    };

    let output = write_witness(
        &args.circuit_name,
        serde_json::to_string_pretty(&witness)?.as_bytes(),
    )?;

    // Prepare lines to print
    let mut lines = Vec::new();
    lines.push(format!("Data length: {}", input_data.len()));
    lines.push(format!(
        "Max stack height: {}",
        json_max_stack_height(&input_data)
    ));

    lines.push(output);

    // Print the output inside a nicely formatted box
    print_boxed_output(lines);

    Ok(())
}

fn http_extractor_witness(args: ExtractorWitnessArgs) -> Result<(), Box<dyn std::error::Error>> {
    // read input and lockfile
    let data = args.subcommand.read_input(&args.input_file)?;

    let lockfile_data = std::fs::read(&args.lockfile)?;
    let http_data: HttpData = serde_json::from_slice(&lockfile_data)?;

    // create witness data
    let witness = HttpExtractorWitness {
        data: data.clone(),
        http_data,
    };

    let output = write_witness(
        &args.circuit_name,
        serde_json::to_string_pretty(&witness)?.as_bytes(),
    )?;

    // Prepare lines to print
    let mut lines = Vec::new();
    lines.push(format!("Data length: {}", data.len()));

    lines.push(output);

    // Print the output inside a nicely formatted box
    print_boxed_output(lines);

    Ok(())
}

fn extended_extractor_witness(
    args: ExtractorWitnessArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // read input and lockfile
    let data = args.subcommand.read_input(&args.input_file)?;

    let lockfile_data = std::fs::read(&args.lockfile)?;
    let lockfile: ExtendedLockfile = serde_json::from_slice(&lockfile_data)?;

    // create witness data
    let witness = ExtendedWitness {
        http_witness: HttpExtractorWitness {
            data: data.clone(),
            http_data: lockfile.http,
        },
        keys: lockfile.json.keys_as_bytes(),
    };

    let output = write_witness(
        &args.circuit_name,
        serde_json::to_string_pretty(&witness)?.as_bytes(),
    )?;

    // Prepare lines to print
    let mut lines = Vec::new();
    lines.push(format!("Data length: {}", data.len()));

    lines.push(output);

    // Print the output inside a nicely formatted box
    print_boxed_output(lines);

    Ok(())
}

pub fn extractor_witness(args: ExtractorWitnessArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.subcommand {
        FileType::Json => json_extractor_witness(args),
        FileType::Http => http_extractor_witness(args),
        FileType::Extended => extended_extractor_witness(args),
    }
}
