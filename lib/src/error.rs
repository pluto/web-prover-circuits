use thiserror::Error;

#[derive(Error, Debug)]
pub enum WitnessGeneratorError {
  #[error("{0}")]
  CatchAll(String),
  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),
  #[error("{0}")]
  JsonParser(String),
}
