pragma circom 2.1.9;

include "../../circuits/http/nivc/lock_header.circom";

component main { public [step_in] } = LockHeader(512, 10, 50, 100);