pragma circom 2.1.9;

include "../../circuits/json/nivc/masker.circom";

component main { public [step_in] } = JsonMaskArrayIndexNIVC(512, 10);