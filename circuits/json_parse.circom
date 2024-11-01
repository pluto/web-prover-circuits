pragma circom 2.1.9;

include "json/nivc/parse.circom";

component main { public [step_in] } = JsonParseNIVC(48, 16);

