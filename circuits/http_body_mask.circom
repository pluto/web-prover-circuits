pragma circom 2.1.9;

include "http/nivc/body_mask.circom";

component main { public [step_in] } = HTTPMaskBodyNIVC(4160, 320);

