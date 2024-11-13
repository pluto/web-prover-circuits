pragma circom 2.1.9;

include "../../circuits/aes-gcm/nivc/aes-gctr-nivc.circom";

component main { public [step_in] } = AESGCTRFOLD(1);