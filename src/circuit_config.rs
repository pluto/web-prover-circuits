use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env};

/// circuit config used for circomkit support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircomkitCircuitConfig {
    /// file name containing the circuit template
    pub file: String,
    /// circuit template name
    pub template: String,
    /// circuit parameters
    pub params: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircomkitConfig(HashMap<String, CircomkitCircuitConfig>);

impl CircomkitCircuitConfig {
    /// Writes [`CircomkitCircuitConfig`] to `circuits.json` for circomkit support
    /// # Inputs
    /// - `name`: circuit name
    pub fn write(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut circomkit_config = env::current_dir()?;
        circomkit_config.push("circuits.json");

        let _ = std::fs::File::create_new(&circomkit_config);

        let mut circomkit_circuits: CircomkitConfig =
            serde_json::from_slice(&std::fs::read(&circomkit_config)?)?;

        if let Some(circuits_inputs) = circomkit_circuits.0.get_mut(name) {
            *circuits_inputs = self.clone();
        } else {
            let _ = circomkit_circuits.0.insert(name.to_string(), self.clone());
        }

        std::fs::write(
            circomkit_config.clone(),
            serde_json::to_string_pretty(&circomkit_circuits)?,
        )?;

        println!("Config updated: {}", circomkit_config.display());

        Ok(())
    }
}
