pragma circom 2.1.9;

include "../../circuits/http/nivc/lock_header.circom";

component main { public [step_in] } = LockHeader(1024, 50, 100);