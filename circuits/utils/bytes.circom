pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";

/*
This template passes if a given array contains only valid ASCII values (e.g., u8 vals).

# Params:
 - `n`: the length of the array

# Inputs:
 - `in[n]`: array to check
*/
template ASCII(n) {
    signal input in[n];

    component Byte[n];
    for(var i = 0; i < n; i++) {
        Byte[i] = Num2Bits(8);
        Byte[i].in <== in[i];
    }
}