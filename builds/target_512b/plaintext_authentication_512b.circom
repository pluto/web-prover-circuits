pragma circom 2.1.9;

include "../../circuits/chacha20/nivc/chacha20_nivc.circom";

component main { public [step_in] } = ChaCha20_NIVC(512);