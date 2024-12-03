pragma circom 2.1.9;

include "../../circuits/chacha20/nivc/chacha20_nivc.circom";

// Note: this takes in 32 bits (4 bytes) per chunk, so 256 * 4 = 1024 bytes 
component main { public [step_in] } = ChaCha20_NIVC(256);