pragma circom 2.1.9;

include "../../circuits/json/nivc/parse.circom";

component main { public [step_in] } = JsonParseNIVC(512, 10);

