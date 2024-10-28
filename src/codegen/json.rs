use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    cmp::max_by,
    collections::HashMap,
    error::Error,
    fs::{self, create_dir_all},
};

use crate::{circuit_config::CircomkitCircuitConfig, ExtractorArgs};

#[derive(Debug, Serialize, Deserialize)]
pub enum ValueType {
    #[serde(rename = "string")]
    String,
    #[serde(rename = "number")]
    Number,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Key {
    String(String),
    Num(usize),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Lockfile {
    pub keys: Vec<Key>,
    pub value_type: ValueType,
}

impl Lockfile {
    pub fn keys_as_bytes(&self) -> HashMap<String, Vec<u8>> {
        let mut keys = HashMap::<String, Vec<u8>>::new();
        for (i, key) in self.keys.iter().enumerate() {
            if let Key::String(key) = key {
                let key_name = format!("key{}", i + 1);
                keys.insert(key_name, key.as_bytes().to_vec());
            }
        }
        keys
    }
    pub fn params(&self) -> Vec<String> {
        let mut params = vec!["DATA_BYTES".to_string(), "MAX_STACK_HEIGHT".to_string()];

        for (i, key) in self.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    params.push(format!("keyLen{}", i + 1));
                    params.push(format!("depth{}", i + 1));
                }
                Key::Num(_) => {
                    params.push(format!("index{}", i + 1));
                    params.push(format!("depth{}", i + 1));
                }
            }
        }

        params.push("maxValueLen".to_string());

        params
    }

    pub fn inputs(&self) -> Vec<String> {
        let mut inputs = vec![String::from("data")];

        for (i, key) in self.keys.iter().enumerate() {
            match key {
                Key::String(_) => inputs.push(format!("key{}", i + 1)),
                Key::Num(_) => (),
            }
        }

        inputs
    }

    /// Builds circuit config for circomkit support.
    pub fn build_circuit_config(
        &self,
        input: &[u8],
        output_filename: &str,
    ) -> Result<CircomkitCircuitConfig, Box<dyn Error>> {
        let circuit_template_name = match self.value_type {
            ValueType::String => String::from("ExtractStringValue"),
            ValueType::Number => String::from("ExtractNumValue"),
        };

        Ok(CircomkitCircuitConfig {
            file: format!("main/{}", output_filename),
            template: circuit_template_name,
            params: self.populate_params(input)?,
        })
    }

    /// Builds circuit arguments
    /// `[DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, ..., maxValueLen]`
    pub fn populate_params(&self, input: &[u8]) -> Result<Vec<usize>, Box<dyn Error>> {
        let mut params = vec![input.len(), json_max_stack_height(input)];

        for (i, key) in self.keys.iter().enumerate() {
            match key {
                Key::String(key) => params.push(key.len()),
                Key::Num(index) => params.push(*index),
            }
            params.push(i);
        }

        let current_value = self.get_value(input)?;
        params.push(current_value.as_bytes().len());

        Ok(params)
    }

    pub fn get_value(&self, input: &[u8]) -> Result<String, Box<dyn Error>> {
        let mut current_value: Value = serde_json::from_slice(input)?;
        for key in self.keys.iter() {
            match key {
                Key::String(key) => {
                    if let Some(value) = current_value.get_mut(key) {
                        // update current object value inside key
                        current_value = value.to_owned();
                    } else {
                        return Err(String::from("provided key not present in input JSON").into());
                    }
                }
                Key::Num(index) => {
                    if let Some(value) = current_value.get_mut(index) {
                        current_value = value.to_owned();
                    } else {
                        return Err(String::from("provided index not present in input JSON").into());
                    }
                }
            }
        }

        match current_value {
            Value::Number(num) => Ok(num.to_string()),
            Value::String(val) => Ok(val),
            _ => unimplemented!(),
        }
    }
}

/// Returns maximum stack height for JSON parser circuit. Tracks maximum open braces and square
/// brackets at any position.
///
/// # Input
/// - `input`: input json bytes
/// # Output
/// - `max_stack_height`: maximum stack height needed for JSON parser circuit
pub fn json_max_stack_height(input: &[u8]) -> usize {
    let mut max_stack_height = 1;
    let mut curr_stack_height = 1;
    let mut inside_string: bool = false;

    for (i, char) in input.iter().skip(1).enumerate() {
        match char {
            b'"' if input[i] != b'\\' => inside_string = !inside_string,
            b'{' | b'[' if !inside_string => {
                curr_stack_height += 1;
                max_stack_height = max_by(max_stack_height, curr_stack_height, |x, y| x.cmp(y));
            }
            b'}' | b']' if !inside_string => curr_stack_height -= 1,
            _ => {}
        }
    }

    max_stack_height
}

fn extract_string(
    config: &CircomkitCircuitConfig,
    data: &Lockfile,
    circuit_buffer: &mut String,
    debug: bool,
) {
    let params = data.params();
    let inputs = data.inputs();

    *circuit_buffer += &format!("template {}({}) {{\n", config.template, params.join(", "),);

    *circuit_buffer += "    signal input data[DATA_BYTES];\n\n";

    for (i, key) in data.keys.iter().enumerate() {
        match key {
            Key::String(_) => {
                *circuit_buffer += &format!("    signal input key{}[keyLen{}];\n", i + 1, i + 1)
            }
            Key::Num(_) => (),
        }
    }

    *circuit_buffer += r#"
    signal output value[maxValueLen];

    signal value_starting_index[DATA_BYTES];
"#;

    // value_starting_index <== ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, keyLen2, depth2, index3, depth3, index4, depth4, maxValueLen)(data, key1, key2);
    {
        *circuit_buffer += &format!(
            "    value_starting_index <== ExtractValue({})({});\n",
            params.join(", "),
            inputs.join(", "),
        );
    }

    *circuit_buffer += r#"
    value <== SelectSubArray(DATA_BYTES, maxValueLen)(data, value_starting_index[DATA_BYTES-1]+1, maxValueLen);"#;

    if debug {
        *circuit_buffer += r#"
    log("value_starting_index", value_starting_index[DATA_BYTES-1]+1);
    for (var i=0 ; i<maxValueLen; i++) {
        log("value[",i,"]=", value[i]);
    }"#;
    }

    *circuit_buffer += r#"
}
"#;
}

fn extract_number(
    config: &CircomkitCircuitConfig,
    data: &Lockfile,
    circuit_buffer: &mut String,
    debug: bool,
) {
    let params = data.params();
    let inputs = data.inputs();

    *circuit_buffer += &format!("template {}({}) {{\n", config.template, params.join(", "),);

    *circuit_buffer += "    signal input data[DATA_BYTES];\n\n";

    for (i, key) in data.keys.iter().enumerate() {
        match key {
            Key::String(_) => {
                *circuit_buffer += &format!("    signal input key{}[keyLen{}];\n", i + 1, i + 1)
            }
            Key::Num(_) => (),
        }
    }

    *circuit_buffer += r#"
    signal value_string[maxValueLen];
    signal output value;

    signal value_starting_index[DATA_BYTES];
"#;

    // value_starting_index <== ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, keyLen2, depth2, index3, depth3, index4, depth4, maxValueLen)(data, key1, key2);
    {
        *circuit_buffer += &format!(
            "    value_starting_index <== ExtractValue({})({});\n",
            params.join(", "),
            inputs.join(", "),
        );
    }

    *circuit_buffer += r#"
    value_string <== SelectSubArray(DATA_BYTES, maxValueLen)(data, value_starting_index[DATA_BYTES-1], maxValueLen);
"#;

    if debug {
        *circuit_buffer += r#"
    log("value_starting_index", value_starting_index[DATA_BYTES-1]);
    for (var i=0 ; i<maxValueLen; i++) {
        log("value[",i,"]=", value_string[i]);
    }"#;
    }

    *circuit_buffer += r#"

    signal number_value[maxValueLen];
    number_value[0] <== (value_string[0]-48);
    for (var i=1 ; i<maxValueLen ; i++) {
        number_value[i] <== number_value[i-1] * 10 + (value_string[i]-48);
    }

    value <== number_value[maxValueLen-1];
}
"#;
}

fn build_json_circuit(
    config: &CircomkitCircuitConfig,
    data: &Lockfile,
    output_filename: &str,
    debug: bool,
) -> Result<(), Box<dyn Error>> {
    let mut circuit_buffer = String::new();

    // Dump out the contents of the lockfile used into the circuit
    circuit_buffer += "/*\n";
    circuit_buffer += &format!("{:#?}", data);
    circuit_buffer += "\n*/\n";

    circuit_buffer += "pragma circom 2.1.9;\n\n";
    circuit_buffer += "include \"../json/interpreter.circom\";\n\n";

    // template ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, index2, depth2, keyLen3, depth3, index4, depth4, maxValueLen) {
    {
        let params = data.params();
        circuit_buffer += &format!("template ExtractValue({}) {{\n", params.join(", "));
    }

    /*
    signal input data[DATA_BYTES];

    signal input key1[keyLen1];
    signal input key3[keyLen3];
     */
    {
        circuit_buffer += "    signal input data[DATA_BYTES];\n\n";

        for (i, key) in data.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    circuit_buffer += &format!("    signal input key{}[keyLen{}];\n", i + 1, i + 1)
                }
                Key::Num(_) => (),
            }
        }
    }
    circuit_buffer += r#"    // value starting index in `data`
    signal output value_starting_index[DATA_BYTES];
    // flag determining whether this byte is matched value
    signal is_value_match[DATA_BYTES];
    // final mask
    signal mask[DATA_BYTES];

    component State[DATA_BYTES];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    signal parsing_key[DATA_BYTES];
    signal parsing_value[DATA_BYTES];
"#;

    /* // signals for parsing string key and array index
    signal parsing_key[DATA_BYTES];
    signal parsing_value[DATA_BYTES];
    signal parsing_object1_value[DATA_BYTES];
    signal parsing_array2[DATA_BYTES];
    signal is_key1_match[DATA_BYTES];
    signal is_key1_match_for_value[DATA_BYTES];
    is_key1_match_for_value[0] <== 0;
    signal is_next_pair_at_depth1[DATA_BYTES];
     */
    {
        for (i, key) in data.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    circuit_buffer +=
                        &format!("    signal parsing_object{}_value[DATA_BYTES];\n", i + 1)
                }
                Key::Num(_) => {
                    circuit_buffer += &format!("    signal parsing_array{}[DATA_BYTES];\n", i + 1)
                }
            }
        }

        for (i, key) in data.keys.iter().enumerate() {
            match key {
            Key::String(_) => circuit_buffer += &format!("    signal is_key{}_match[DATA_BYTES];\n    signal is_key{}_match_for_value[DATA_BYTES+1];\n    is_key{}_match_for_value[0] <== 0;\n    signal is_next_pair_at_depth{}[DATA_BYTES];\n", i+1, i+1, i+1, i+1),
            Key::Num(_) => (),
        }
        }
    }

    let mut num_objects = 0;

    // initialise first iteration
    {
        // parsing_key and parsing_object{i}_value
        circuit_buffer += r#"
    // initialise first iteration
    parsing_key[0] <== InsideKeyAtTop(MAX_STACK_HEIGHT)(State[0].next_stack, State[0].next_parsing_string, State[0].next_parsing_number);

"#;

        for (i, key) in data.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    circuit_buffer += &format!("    parsing_object{}_value[0] <== InsideValue()(State[0].next_stack[0], State[0].next_parsing_string, State[0].next_parsing_number);\n", i+1);
                }
                Key::Num(_) => {
                    circuit_buffer += &format!("    parsing_array{}[0] <== InsideArrayIndex(index{})(State[0].next_stack[0], State[0].next_parsing_string, State[0].next_parsing_number);\n", i+1, i+1);
                }
            }
        }

        // parsing_value[0] <== MultiAND(5)([parsing_object1_value[0], parsing_object2_value[0], parsing_array3[0], parsing_object4_value[0], parsing_object5_value[0]]);
        circuit_buffer += &format!(
            "     // parsing correct value = AND(all individual stack values)\n    parsing_value[0] <== MultiAND({})([",
            data.keys.len()
        );
        for (i, key) in data.keys.iter().take(data.keys.len() - 1).enumerate() {
            match key {
                Key::String(_) => circuit_buffer += &format!("parsing_object{}_value[0], ", i + 1),
                Key::Num(_) => circuit_buffer += &format!("parsing_array{}[0], ", i + 1),
            }
        }
        match data.keys[data.keys.len() - 1] {
            Key::String(_) => {
                circuit_buffer += &format!("parsing_object{}_value[0]]);\n\n", data.keys.len())
            }
            Key::Num(_) => circuit_buffer += &format!("parsing_array{}[0]]);\n\n", data.keys.len()),
        }

        // is_key{i}_match_for_value
        for (i, key) in data.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    num_objects += 1;
                    circuit_buffer += &format!("    is_key{}_match[0] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen{}, depth{})(data, key{}, 0, parsing_key[0], State[0].next_stack);\n", i+1, i+1, i+1, i+1);
                    circuit_buffer += &format!("    is_next_pair_at_depth{}[0] <== NextKVPairAtDepth(MAX_STACK_HEIGHT)(State[0].next_stack, data[0], depth{});\n", i+1, i+1);
                    circuit_buffer += &format!("    is_key{}_match_for_value[1] <== Mux1()([is_key{}_match_for_value[0] * (1-is_next_pair_at_depth{}[0]), is_key{}_match[0] * (1-is_next_pair_at_depth{}[0])], is_key{}_match[0]);\n", i+1, i+1, i+1, i+1, i+1, i+1);
                    if debug {
                        circuit_buffer += &format!("        // log(\"is_key{}_match_for_value\", is_key{}_match_for_value[1]);\n\n", i + 1, i + 1);
                    }
                }
                Key::Num(_) => (),
            }
        }

        // is_value_match[data_idx] <== MultiAND(2)([is_key1_match_for_value[data_idx], is_key3_match_for_value[data_idx]]);
        {
            circuit_buffer += &format!("    is_value_match[0] <== MultiAND({})([", num_objects);
            for (i, key) in data.keys.iter().enumerate() {
                match key {
                    Key::String(_) => {
                        circuit_buffer += &format!("is_key{}_match_for_value[1], ", i + 1)
                    }
                    Key::Num(_) => (),
                }
            }

            // remove last 2 chars `, ` from string buffer
            circuit_buffer.pop();
            circuit_buffer.pop();
            circuit_buffer += "]);\n";
        }

        circuit_buffer += r#"
    mask[0] <== parsing_value[0] * is_value_match[0];
"#;
    }

    // debugging
    circuit_buffer += r#"
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {"#;

    if debug {
        circuit_buffer += r#"
        // Debugging
        for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
            log("State[", data_idx-1, "].stack[", i,"]    ", "= [",State[data_idx-1].next_stack[i][0], "][", State[data_idx-1].next_stack[i][1],"]" );
        }
        log("State[", data_idx-1, "].byte", "= ", data[data_idx-1]);
        log("State[", data_idx-1, "].parsing_string", "= ", State[data_idx-1].next_parsing_string);
        log("State[", data_idx-1, "].parsing_number", "= ", State[data_idx-1].next_parsing_number);
"#;
    }

    circuit_buffer += r#"
        State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].stack          <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;

        // - parsing key
        // - parsing value (different for string/numbers and array)
        // - key match (key 1, key 2)
        // - is next pair
        // - is key match for value
        // - value_mask
        // - mask

        // check if inside key or not
        parsing_key[data_idx] <== InsideKeyAtTop(MAX_STACK_HEIGHT)(State[data_idx].next_stack, State[data_idx].next_parsing_string, State[data_idx].next_parsing_number);

"#;

    /* Determining wheter parsing correct value and array index
    parsing_object1_value[data_idx-1] <== InsideValue(MAX_STACK_HEIGHT, depth1)(State[data_idx].stack, State[data_idx].parsing_string, State[data_idx].parsing_number);
    parsing_array2[data_idx-1] <== InsideArrayIndex(MAX_STACK_HEIGHT, index2, depth2)(State[data_idx].stack, State[data_idx].parsing_string, State[data_idx].parsing_number);
     */
    {
        for (i, key) in data.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    circuit_buffer += &format!("        parsing_object{}_value[data_idx] <== InsideValue()(State[data_idx].next_stack[depth{}], State[data_idx].next_parsing_string, State[data_idx].next_parsing_number);\n", i+1, i+1);
                }
                Key::Num(_) => {
                    circuit_buffer += &format!("        parsing_array{}[data_idx] <== InsideArrayIndex(index{})(State[data_idx].next_stack[depth{}], State[data_idx].next_parsing_string, State[data_idx].next_parsing_number);\n", i+1, i+1, i+1);
                }
            }
        }
    }

    // parsing correct value = AND(all individual stack values)
    //     parsing_value[data_idx-1] <== MultiAND(4)([parsing_object1_value[data_idx-1], parsing_array2[data_idx-1], parsing_object3_value[data_idx-1], parsing_array4[data_idx-1]]);
    {
        circuit_buffer += &format!(
            "        // parsing correct value = AND(all individual stack values)\n        parsing_value[data_idx] <== MultiAND({})([",
            data.keys.len()
        );

        for (i, key) in data.keys.iter().take(data.keys.len() - 1).enumerate() {
            match key {
                Key::String(_) => {
                    circuit_buffer += &format!("parsing_object{}_value[data_idx], ", i + 1)
                }
                Key::Num(_) => circuit_buffer += &format!("parsing_array{}[data_idx], ", i + 1),
            }
        }
        match data.keys[data.keys.len() - 1] {
            Key::String(_) => {
                circuit_buffer += &format!("parsing_object{}_value[data_idx]]);\n", data.keys.len())
            }
            Key::Num(_) => {
                circuit_buffer += &format!("parsing_array{}[data_idx]]);\n", data.keys.len())
            }
        }

        // optional debug logs
        if debug {
            circuit_buffer += "        // log(\"parsing value:\", ";
            for (i, key) in data.keys.iter().enumerate() {
                match key {
                    Key::String(_) => {
                        circuit_buffer += &format!("parsing_object{}_value[data_idx], ", i + 1)
                    }
                    Key::Num(_) => circuit_buffer += &format!("parsing_array{}[data_idx], ", i + 1),
                }
            }
            circuit_buffer += "parsing_value[data_idx]);\n\n";
        }
    }

    let mut num_objects = 0;

    /*
    to get correct value, check:
    - key matches at current index and depth of key is as specified
    - whether next KV pair starts
    - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
    is_key1_match[data_idx-1] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1)(data, key1, data_idx-1, parsing_key[data_idx-1], State[data_idx].stack);
    is_next_pair_at_depth1[data_idx-1] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, depth1)(State[data_idx].stack, data[data_idx-1]);
    is_key1_match_for_value[data_idx] <== Mux1()([is_key1_match_for_value[data_idx-1] * (1-is_next_pair_at_depth1[data_idx-1]), is_key1_match[data_idx-1] * (1-is_next_pair_at_depth1[data_idx-1])], is_key1_match[data_idx-1]);
    */
    {
        circuit_buffer += r#"
        // to get correct value, check:
        // - key matches at current index and depth of key is as specified
        // - whether next KV pair starts
        // - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
"#;

        for (i, key) in data.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    num_objects += 1;
                    circuit_buffer += &format!("        is_key{}_match[data_idx] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen{}, depth{})(data, key{}, data_idx, parsing_key[data_idx], State[data_idx].next_stack);\n", i+1, i+1, i+1, i+1);
                    circuit_buffer += &format!("        is_next_pair_at_depth{}[data_idx] <== NextKVPairAtDepth(MAX_STACK_HEIGHT)(State[data_idx].next_stack, data[data_idx], depth{});\n", i+1, i+1);
                    circuit_buffer += &format!("        is_key{}_match_for_value[data_idx+1] <== Mux1()([is_key{}_match_for_value[data_idx] * (1-is_next_pair_at_depth{}[data_idx]), is_key{}_match[data_idx] * (1-is_next_pair_at_depth{}[data_idx])], is_key{}_match[data_idx]);\n", i+1, i+1, i+1, i+1, i+1, i+1);
                    if debug {
                        circuit_buffer += &format!("        // log(\"is_key{}_match_for_value\", is_key{}_match_for_value[data_idx+1]);\n\n", i + 1, i + 1);
                    }
                }
                Key::Num(_) => (),
            }
        }
    }

    // is_value_match[data_idx] <== MultiAND(2)([is_key1_match_for_value[data_idx], is_key3_match_for_value[data_idx]]);
    {
        circuit_buffer += &format!(
            "        is_value_match[data_idx] <== MultiAND({})([",
            num_objects
        );
        for (i, key) in data.keys.iter().enumerate() {
            match key {
                Key::String(_) => {
                    circuit_buffer += &format!("is_key{}_match_for_value[data_idx+1], ", i + 1)
                }
                Key::Num(_) => (),
            }
        }

        // remove last 2 chars `, ` from string buffer
        circuit_buffer.pop();
        circuit_buffer.pop();
        circuit_buffer += "]);\n";
    }

    // debugging and output bytes
    {
        circuit_buffer += r#"
        // mask = currently parsing value and all subsequent keys matched
        mask[data_idx] <== parsing_value[data_idx] * is_value_match[data_idx];
    }"#;

        // Debugging
        if debug {
            circuit_buffer += r#"
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        log("State[", DATA_BYTES-1, "].stack[", i,"]    ", "= [",State[DATA_BYTES -1].next_stack[i][0], "][", State[DATA_BYTES - 1].next_stack[i][1],"]" );
    }
    log("State[", DATA_BYTES-1, "].parsing_string", "= ", State[DATA_BYTES-1].next_parsing_string);
    log("State[", DATA_BYTES-1, "].parsing_number", "= ", State[DATA_BYTES-1].next_parsing_number);
    log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    "#;
        }

        circuit_buffer += r#"

    // find starting index of value in data by matching mask
    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(mask[0]);
    for (var i=1 ; i<DATA_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }
"#;

        // template ends
        circuit_buffer += "}\n";
    }

    match data.value_type {
        ValueType::String => extract_string(config, data, &mut circuit_buffer, debug),
        ValueType::Number => extract_number(config, data, &mut circuit_buffer, debug),
    }

    // write circuits to file
    let mut file_path = std::env::current_dir()?;
    file_path.push("circuits");
    file_path.push("main");

    // create dir if doesn't exist
    create_dir_all(&file_path)?;

    file_path.push(format!("{}.circom", output_filename));

    fs::write(&file_path, circuit_buffer)?;

    println!("Code generated at: {}", file_path.display());

    Ok(())
}

/// Builds a JSON extractor circuit from [`ExtractorArgs`]
/// - reads [`Lockfile`]
/// - reads input
/// - create [`CircomkitCircuitConfig`]
/// - builds circuit
/// - writes file
pub fn json_circuit_from_args(
    args: &ExtractorArgs,
) -> Result<CircomkitCircuitConfig, Box<dyn Error>> {
    let lockfile: Lockfile = serde_json::from_slice(&fs::read(&args.lockfile)?)?;

    let circuit_filename = format!("json_{}", args.circuit_name);

    let input = fs::read(&args.input_file)?;

    let config = json_circuit_from_lockfile(&input, &lockfile, &circuit_filename, args.debug)?;
    config.write(&args.circuit_name)?;

    Ok(config)
}

pub fn json_circuit_from_lockfile(
    input: &[u8],
    lockfile: &Lockfile,
    output_filename: &str,
    debug: bool,
) -> Result<CircomkitCircuitConfig, Box<dyn Error>> {
    let config = lockfile.build_circuit_config(input, output_filename)?;

    build_json_circuit(&config, lockfile, output_filename, debug)?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn params() {
        let lockfile: Lockfile = serde_json::from_slice(include_bytes!(
            "../../examples/json/lockfile/value_array_object.json"
        ))
        .unwrap();

        let params = lockfile.params();

        assert_eq!(params[0], "DATA_BYTES");
        assert_eq!(params[1], "MAX_STACK_HEIGHT");
        assert_eq!(params.len(), 2 + 2 * lockfile.keys.len() + 1);
    }

    #[test]
    fn inputs() {
        let lockfile: Lockfile = serde_json::from_slice(include_bytes!(
            "../../examples/json/lockfile/value_array_number.json"
        ))
        .unwrap();

        let inputs = lockfile.inputs();

        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0], "data");
    }

    #[test]
    fn populate_params() {
        let input = include_bytes!("../../examples/json/test/spotify.json");
        let lockfile: Lockfile =
            serde_json::from_slice(include_bytes!("../../examples/json/lockfile/spotify.json"))
                .unwrap();

        let params = lockfile.populate_params(input).unwrap();

        assert_eq!(params.len(), lockfile.params().len());
        assert_eq!(params[0], input.len());
    }

    #[test]
    fn build_circuit_config() {
        let input = include_bytes!("../../examples/json/test/spotify.json");
        let lockfile: Lockfile =
            serde_json::from_slice(include_bytes!("../../examples/json/lockfile/spotify.json"))
                .unwrap();

        let config = lockfile
            .build_circuit_config(input, "output_filename")
            .unwrap();

        assert_eq!(config.template, "ExtractStringValue");
        assert_eq!(config.file, "main/output_filename");
    }

    #[test]
    fn json_value() {
        let input = include_bytes!("../../examples/json/test/spotify.json");
        let lockfile: Lockfile =
            serde_json::from_slice(include_bytes!("../../examples/json/lockfile/spotify.json"))
                .unwrap();

        let value = lockfile.get_value(input).unwrap();

        assert_eq!(value, "Taylor Swift");
    }

    #[test]
    fn max_stack_height() {
        let input = include_bytes!("../../examples/json/test/two_keys.json");

        assert_eq!(json_max_stack_height(input), 1);

        let input = include_bytes!("../../examples/json/test/spotify.json");
        assert_eq!(json_max_stack_height(input), 5);
    }
}
