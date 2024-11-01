pragma circom 2.1.9;

include "json/nivc/masker.circom";

component main { public [step_in] } = JsonMaskObjectNIVC(48, 16, 5);
