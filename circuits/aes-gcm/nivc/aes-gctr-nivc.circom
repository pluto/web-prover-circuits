pragma circom 2.1.9;

include "gctr-nivc.circom";
include "../../utils/array.circom";
include "../../utils/hash.circom";

// Compute AES-GCTR
template AESGCTRFOLD() {
    signal input key[16];
    signal input iv[12];
    signal input aad[16];
    signal input ctr[4];
    signal input plainText[16];

    signal input cipherText[16];

    signal input step_in[1];
    signal output step_out[1];

    component aes     = AESGCTRFOLDABLE();
    aes.key         <== key;
    aes.iv          <== iv;
    aes.aad         <== aad;
    aes.plainText   <== plainText;
    aes.lastCounter <== ctr;

    signal equalCheck[16];
    for(var i = 0 ; i < 16 ; i++) {
        equalCheck[i] <== IsEqual()([aes.cipherText[i], cipherText[i]]);
        equalCheck[i] === 1;
    }

    
    var packedPlaintext = 0;
    for(var i = 0 ; i < 16 ; i++) {
        packedPlaintext += plainText[i] * 2**(8*i);
    }
    step_out[0] <== PoseidonChainer()([step_in[0],packedPlaintext]);
}
