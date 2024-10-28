use crate::{
    circuit_config::CircomkitCircuitConfig,
    codegen::{
        http::HttpData,
        json::{Key, Lockfile as JsonLockfile},
    },
    ExtractorArgs, FileType,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::{http::http_circuit_from_lockfile, json::json_circuit_from_lockfile};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendedLockfile {
    pub http: HttpData,
    pub json: JsonLockfile,
}

fn build_integrated_circuit(
    http_data: &HttpData,
    http_circuit_config: &CircomkitCircuitConfig,
    json_lockfile: &JsonLockfile,
    json_circuit_config: &CircomkitCircuitConfig,
    integrated_circuit_config: &CircomkitCircuitConfig,
    output_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut circuit_buffer = String::new();

    circuit_buffer += "pragma circom 2.1.9;\n\n";

    let http_circuit_filename = Path::new(&http_circuit_config.file)
        .file_name()
        .expect("incorrect filepath in circuit config")
        .to_str()
        .expect("improper circuit filename");

    let json_circuit_filename = Path::new(&json_circuit_config.file)
        .file_name()
        .expect("incorrect filepath in circuit config")
        .to_str()
        .expect("improper circuit filename");

    circuit_buffer += &format!("include \"./{}.circom\";\n", http_circuit_filename);
    circuit_buffer += &format!("include \"./{}.circom\";\n\n", json_circuit_filename);

    let http_params = http_data.params();

    let mut json_params = json_lockfile.params();
    // remove `DATA_BYTES` from json params
    json_params.remove(0);

    circuit_buffer += &format!(
        "template {}({}, {}) {{\n",
        integrated_circuit_config.template,
        http_params.join(", "),
        json_params.join(", ")
    );

    {
        circuit_buffer += r#"
    // Raw HTTP bytestream
    signal input data[DATA_BYTES];
"#;

        // Start line signals
        {
            match http_data {
                HttpData::Request(_) => {
                    circuit_buffer += r#"
    // Request line attributes
    signal input method[methodLen];
    signal input target[targetLen];
    signal input version[versionLen];

"#;
                }
                HttpData::Response(_) => {
                    circuit_buffer += r#"
    // Status line attributes
    signal input version[versionLen];
    signal input status[statusLen];
    signal input message[messageLen];

"#;
                }
            }
        }

        // Header signals
        circuit_buffer += "    // Header names and values to lock\n";
        for (i, _header) in http_data.headers().iter().enumerate() {
            circuit_buffer += &format!(
                "    signal input header{}[headerNameLen{}];\n",
                i + 1,
                i + 1
            );
            circuit_buffer += &format!(
                "    signal input value{}[headerValueLen{}];\n",
                i + 1,
                i + 1
            );
        }
    }

    circuit_buffer += "\n    signal httpBody[maxContentLength];\n\n";
    let http_inputs = http_data.inputs();
    circuit_buffer += &format!(
        "    httpBody <== {}({})({});\n\n",
        http_circuit_config.template,
        http_params.join(", "),
        http_inputs.join(", "),
    );

    for (i, key) in json_lockfile.keys.iter().enumerate() {
        match key {
            Key::String(_) => {
                circuit_buffer += &format!("    signal input key{}[keyLen{}];\n", i + 1, i + 1)
            }
            Key::Num(_) => (),
        }
    }

    circuit_buffer += "\n    signal output value[maxValueLen];\n";
    circuit_buffer += &format!(
        "    value <== {}(maxContentLength, {}",
        json_circuit_config.template,
        json_params.join(", ")
    );

    let mut json_inputs = json_lockfile.inputs();
    json_inputs.remove(0);
    circuit_buffer += &format!(")(httpBody, {});\n", json_inputs.join(", "));

    circuit_buffer += "}";

    // write circuits to file
    let mut file_path = std::env::current_dir()?;
    file_path.push("circuits");
    file_path.push("main");

    // create dir if doesn't exist
    std::fs::create_dir_all(&file_path)?;

    file_path.push(format!("{}.circom", output_filename));

    std::fs::write(&file_path, circuit_buffer)?;

    println!("Code generated at: {}", file_path.display());

    Ok(())
}

fn build_circuit_config(
    args: &ExtractorArgs,
    http_data: &HttpData,
    json_lockfile: &JsonLockfile,
    output_filename: &str,
) -> Result<CircomkitCircuitConfig, Box<dyn std::error::Error>> {
    let input = FileType::Http.read_input(&args.input_file)?;

    let (_, http_body) = http_data.parse_input(input.clone())?;

    // populate http params
    let mut params = http_data.populate_params(input)?;

    // add json params and remove first param: `DATA_BYTES`
    let mut json_params = json_lockfile.populate_params(&http_body)?;
    json_params.remove(0);
    params.append(&mut json_params);

    Ok(CircomkitCircuitConfig {
        file: format!("main/{}", output_filename),
        template: String::from("HttpJson"),
        params,
    })
}

/// Builds a HTTP + JSON combined circuit extracting body response from HTTP response and
/// extracting value of keys from JSON.
pub fn integrated_circuit(args: &ExtractorArgs) -> Result<(), Box<dyn std::error::Error>> {
    let extended_lockfile: ExtendedLockfile =
        serde_json::from_slice(&std::fs::read(&args.lockfile)?)?;

    let http_data: HttpData = extended_lockfile.http;
    let lockfile: JsonLockfile = extended_lockfile.json;

    let http_circuit_filename = format!("{}_http", args.circuit_name);
    let http_circuit_config = http_circuit_from_lockfile(
        &args.input_file,
        &http_data,
        &http_circuit_filename,
        args.debug,
    )?;

    // read http response body as json input
    let json_circuit_filename = format!("{}_json", args.circuit_name);
    let input = FileType::Http.read_input(&args.input_file)?;
    let (_, http_body) = http_data.parse_input(input.clone())?;

    let json_circuit_config =
        json_circuit_from_lockfile(&http_body, &lockfile, &json_circuit_filename, args.debug)?;

    let output_filename = format!("extended_{}", args.circuit_name);
    let config = build_circuit_config(args, &http_data, &lockfile, &output_filename)?;

    build_integrated_circuit(
        &http_data,
        &http_circuit_config,
        &lockfile,
        &json_circuit_config,
        &config,
        &output_filename,
    )?;

    config.write(&args.circuit_name)?;

    Ok(())
}
