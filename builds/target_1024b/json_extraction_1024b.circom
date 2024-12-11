pragma circom 2.1.9;

include "../../circuits/json/extraction.circom";

component main { public [step_in] } = JSONExtraction(1024);