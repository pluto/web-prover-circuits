pragma circom 2.1.9;

include "../../circuits/http/nivc/body_mask.circom";

component main { public [step_in] } = HTTPMaskBodyNIVC(1024, 10);

