pragma circom 2.1.9;

include "../../circuits/json/nivc/extractor.circom";

component main { public [step_in] } = MaskExtractFinal(256, 10, 50);