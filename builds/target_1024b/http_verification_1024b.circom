pragma circom 2.1.9;

include "../../circuits/http/verification.circom";

component main { public [step_in] } = HTTPVerification(1024, 25);
