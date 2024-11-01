pragma circom 2.1.9;

include "http/nivc/parse_and_lock_start_line.circom";

component main { public [step_in] } = ParseAndLockStartLine(48, 16, 8, 3, 2);