use super::*;

// TODO: This test doesn't actually test anything at all. Fix that.
#[test]
fn test_json_tree_hasher() {
  let key_sequence = vec![
    JsonKey::String(KEY_0.to_string()),
    JsonKey::String(KEY_1.to_string()),
    JsonKey::Num(0),
    JsonKey::String(KEY_2.to_string()),
    JsonKey::String(KEY_3.to_string()),
  ];

  let polynomial_input = poseidon::<2>(&[F::from(69), F::from(420)]);
  println!("polynomial_input: {:?}", BigUint::from_bytes_le(&polynomial_input.to_bytes()));
  let stack_and_tree_hashes = json_tree_hasher(polynomial_input, &key_sequence, 10);

  println!("Stack (decimal):");
  for (i, pair) in stack_and_tree_hashes.0.iter().enumerate() {
    let num1 = BigUint::from_bytes_le(&pair[0].to_bytes());
    let num2 = BigUint::from_bytes_le(&pair[1].to_bytes());
    println!("  {i}: [{num1}, {num2}]");
  }

  println!("\nTree hashes (decimal):");
  for (i, pair) in stack_and_tree_hashes.1.iter().enumerate() {
    let num1 = BigUint::from_bytes_le(&pair[0].to_bytes());
    let num2 = BigUint::from_bytes_le(&pair[1].to_bytes());
    println!("  {i}: [{num1}, {num2}]");
  }

  let digest = compress_tree_hash(polynomial_input, stack_and_tree_hashes);
  println!("\nDigest (decimal):");
  println!("  {}", BigUint::from_bytes_le(&digest.to_bytes()));
}

#[test]
fn test_json_value_digest() {
  let json = r#"{"data": {"items": [{"profile": {"name": "Taylor Swift"}}]}}"#;
  let json_bytes_padded = ByteOrPad::from_bytes_with_padding(json.as_bytes(), 1024);

  let keys = vec![
    JsonKey::String(KEY_0.to_string()),
    JsonKey::String(KEY_1.to_string()),
    JsonKey::Num(0),
    JsonKey::String(KEY_2.to_string()),
    JsonKey::String(KEY_3.to_string()),
  ];

  let value = json_value_digest(&json_bytes_padded, &keys).unwrap();
  assert_eq!(value, b"Taylor Swift");
}
