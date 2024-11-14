pragma circom 2.1.9;

include "gctr-nivc.circom";
include "../../utils/array.circom";
include "../../utils/hash.circom";

// Compute AES-GCTR
template AESGCTRFOLD(NUM_CHUNKS) {
    signal input key[16];
    signal input iv[12];
    signal input aad[16];

    signal input ctr[4];

    signal input plainText[NUM_CHUNKS][16];
    signal input cipherText[NUM_CHUNKS][16];

    signal input step_in[1];
    signal output step_out[1];

    component aes[NUM_CHUNKS];
    for(var i = 0 ; i < NUM_CHUNKS ; i++) {
        aes[i] = AESGCTRFOLDABLE();
        if( i == 0) {
            aes[i].plainText   <== plainText[i];
            aes[i].lastCounter <== ctr;
        } else {
            aes[i].plainText   <== plainText[i];
            aes[i].lastCounter <== aes[i - 1].counter;
        }
        aes[i].key         <== key;
        aes[i].iv          <== iv;
        aes[i].aad         <== aad;
    }

    signal ciphertext_equal_check[NUM_CHUNKS][16];
    for(var i = 0 ; i < NUM_CHUNKS; i++) {
        for(var j = 0 ; j < 16 ; j++) {
            ciphertext_equal_check[i][j] <== IsEqual()([aes[i].cipherText[j], cipherText[i][j]]);
            ciphertext_equal_check[i][j] === 1;
        }
    }

    
    var packedPlaintext[NUM_CHUNKS];
    for(var i = 0 ; i < NUM_CHUNKS ; i++) {
        packedPlaintext[i] = 0;
        for(var j = 0 ; j < 16 ; j++) {
            packedPlaintext[i] += plainText[i][j] * 2**(8*j);
        }
    }
    signal hash[NUM_CHUNKS];
    for(var i = 0 ; i < NUM_CHUNKS ; i++) {
        if(i == 0) {
            hash[i] <== PoseidonChainer()([step_in[0],packedPlaintext[i]]);
        } else {
            hash[i] <== PoseidonChainer()([hash[i-1], packedPlaintext[i]]);
        }
    }
    step_out[0] <== hash[NUM_CHUNKS - 1];
}
