pragma circom 2.1.9;

include "../../circuits/http/nivc/http_nivc.circom";

component main { public [step_in] } = HttpNIVC(512, 5);
