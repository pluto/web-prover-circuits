pragma circom 2.1.9;

include "../../circuits/json/nivc/masker.circom";

component main { public [step_in] } = JsonMaskObjectNIVC(1024, 10, 10);
