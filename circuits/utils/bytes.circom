pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/gates.circom";

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

/*
This template converts bytes to bits.
# Params:
 - `n`: the number of bytes

# Inputs:
 - `in[n]`: array of bytes of length n
# Outputs:
 - `out`: an array of bits of length n * 8
*/
template BytesToBits(n_bytes) {
    signal input in[n_bytes];
    signal output out[n_bytes*8];
    component num2bits[n_bytes];
    for (var i = 0; i < n_bytes; i++) {
        num2bits[i] = Num2Bits(8);
        num2bits[i].in <== in[i];
        for (var j = 7; j >=0; j--) {
            out[i*8 + j] <== num2bits[i].out[7 -j];
        }
    }
}

/*
This template converts bits to bytes.
# Params:
 - `n`: the number of bytes you want out
# Inputs:
 - `in[n]`: array of bits of length n * 8
# Outputs:
 - `out`: an array of bytes of length n
*/
template BitsToBytes(n) {
    signal input in[n*8];
    signal output out[n];
    component bits2num[n];
    for (var i = 0; i < n; i++) {
        bits2num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            bits2num[i].in[7 - j] <== in[i*8 + j];
        }
        out[i] <== bits2num[i].out;
    }
}

/*
This template XORs two bytes.
# Inputs:
 - `a`: a single byte
 - `b`: a single byte
# Outputs:
 - `out`: a XOR b
*/
template XorByte(){
        signal input a;
        signal input b;
        signal output out;

        component abits = Num2Bits(8);
        abits.in <== a;

        component bbits = Num2Bits(8);
        bbits.in <== b;

        component XorBits = BitwiseXor(8);
        XorBits.a <== abits.out;
        XorBits.b <== bbits.out;

        component num = Bits2Num(8);
        num.in <== XorBits.out;

        out <== num.out;
}

/*
This template XORs n bytes.
# Inputs:
 - `a`: an array of bytes of length n
 - `b`: an array of bytes of length n
# Outputs:
 - `out`: a XOR b
*/
template XORBLOCK(n_bytes){
    signal input a[n_bytes];
    signal input b[n_bytes];
    signal output out[n_bytes];

    component xorByte[n_bytes];
    for (var i = 0; i < n_bytes; i++) {
        xorByte[i] = XorByte();
        xorByte[i].a <== a[i];
        xorByte[i].b <== b[i];
        out[i] <== xorByte[i].out;
    }
}

/*
This template right shifts an n bit array by r.
# Params:
 - `n`: length of bits to right shift
 - `r`: number of bits to right shift by
# Inputs:
 - `in`: an array of bits of length n
# Outputs:
 - `out`: the bit array right shifted by r
*/
template BitwiseRightShift(n, r) {
    signal input in[n];
    signal output out[n];
    for (var i=0; i<r; i++) {
        out[i] <== 0;
    }
    for (var i=r; i<n; i++) {
        out[i] <== in[i-r];
    }
}

/*
This template computes the XOR of n inputs, each m bits wide.
# Params:
 - `n`: number of inputs to xor
 - `m`: size of each input
# Inputs:
 - `in`: a n x m mattrix representing n inputs each of size m
# Outputs:
 - `out`: a single size m output which is the the n inputs xor'ed together
*/
template XorMultiple(n, m) {
    signal input inputs[n][m];
    signal output out[m];

    signal mids[n][m];
    mids[0] <== inputs[0];

    component xors[n-1];
    for(var i=0; i<n-1; i++) {
        xors[i] = BitwiseXor(m);
        xors[i].a <== mids[i];
        xors[i].b <== inputs[i+1];
        mids[i+1] <== xors[i].out;
    }

    out <== mids[n-1];
}

/*
This template XORs two arrays of n bits.
# Params:
 - `n`: number of bits to xor
# Inputs:
 - `a[n]`: array of bits of length n
 - `b[n]`: array of bits of length n
# Outputs:
 - `out`: an array of bits of length n
*/
template BitwiseXor(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];
    signal mid[n];

    for (var k=0; k<n; k++) {
        mid[k] <== a[k]*b[k];
        out[k] <== a[k] + b[k] - 2*mid[k];
    }
}