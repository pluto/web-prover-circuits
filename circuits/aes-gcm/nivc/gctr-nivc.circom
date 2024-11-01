pragma circom 2.1.9;

include "../aes/cipher.circom";
include "../../utils/array.circom";
include "../gctr.circom";

/// AES-GCTR with 128 bit key encryption according to: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
/// 
/// Parameters:
/// l: length of the plaintext
///
/// Inputs:
/// key: 128-bit key
/// iv: initialization vector
/// plainText: plaintext to be encrypted
/// aad: additional data to be authenticated
///
/// Outputs:
/// cipherText: encrypted ciphertext
/// 
/// This folds a single block without authentication via ghash.
template AESGCTRFOLDABLE() {
    // Inputs
    signal input key[16];           // 128-bit key
    signal input iv[12];            // IV length is 96 bits (12 bytes)
    signal input plainText[16];     // only fold 16 bytes at a time.
    signal input aad[16];           // AAD length is 128 bits (16 bytes)

    // Fold inputs
    signal input lastCounter[4];            // Always start at one, then bring forward last counter.

    // Fold outputs
    signal output counter[4];      
    signal output cipherText[16];

    component zeroBlock = ToBlocks(16);
    for (var i = 0; i < 16; i++) {
        zeroBlock.stream[i] <== 0;
    }

    // Step 1: Let HashKey = aes(key, zeroBlock)
    component cipherH = Cipher(); 
    cipherH.key <== key;
    cipherH.block <== zeroBlock.blocks[0];

    // Step 2: Define a block, J0 with 96 bits of iv and 32 bits of 0s
    component J0builder = ToBlocks(16);
    for (var i = 0; i < 12; i++) {
        J0builder.stream[i] <== iv[i];
    }
    // Use the fold counter as input. 
    for (var i = 12; i < 16; i++) {
        J0builder.stream[i] <== lastCounter[i%4]; // initialize to 0001. 
    }

    component J0WordIncrementer = IncrementWord();
    J0WordIncrementer.in <== J0builder.blocks[0][3];

    signal J0[4][4];
    for (var i = 0; i < 3; i++) {
        J0[i] <== J0builder.blocks[0][i];
    }
    J0[3] <== J0WordIncrementer.out;

    // Step 3: Let C = GCTRK(inc32(J0), P)
    component gctr = GCTR(16);
    gctr.key <== key;
    gctr.initialCounterBlock <== J0;
    gctr.plainText <== plainText;
    cipherText <== gctr.cipherText;

    // extract the counter column wise.
    for (var i = 0; i < 4; i++) {
        counter[i] <== J0[i][3];
    }
}