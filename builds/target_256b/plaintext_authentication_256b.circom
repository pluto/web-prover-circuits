pragma circom 2.1.9;

include "../../circuits/chacha20/authentication.circom";

component main { public [step_in] } = PlaintextAuthentication(256, 11);