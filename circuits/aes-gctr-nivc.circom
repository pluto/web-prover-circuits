pragma circom 2.1.9;

include "aes-gcm/nivc/aes-gctr-nivc.circom";

// Note(WJ 2024-10-31): I put this here like this because i have tests i wanted to include for this component
// the circomkit tests become unhappy when there is a main.
component main { public [step_in] } = AESGCTRFOLD(48);