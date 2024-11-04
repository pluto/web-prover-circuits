pragma circom 2.1.9;

include "../../circuits/aes-gcm/nivc/aes-gctr-nivc.circom";

// the circomkit tests become unhappy when there is a main.
component main { public [step_in] } = AESGCTRFOLD(512, 10);