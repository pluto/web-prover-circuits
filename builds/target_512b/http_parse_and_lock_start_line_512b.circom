pragma circom 2.1.9;

include "../../circuits/http/nivc/parse_and_lock_start_line.circom";

component main { public [step_in] } = ParseAndLockStartLine(512, 10, 20, 20, 20);