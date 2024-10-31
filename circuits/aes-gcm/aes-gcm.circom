pragma circom 2.1.9;

include "ghash/ghash.circom";
include "aes/cipher.circom";
include "../utils/transformations.circom";
include "gctr.circom";


/// AES-GCM with 128 bit key authenticated encryption according to: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
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
/// authTag: authentication tag
///
template AESGCM(l) {
    // Inputs
    signal input key[16]; // 128-bit key
    signal input iv[12]; // IV length is 96 bits (12 bytes)
    signal input plainText[l];
    signal input aad[16]; // AAD length is 128 bits (16 bytes)

    // Outputs
    signal output cipherText[l];
    signal output authTag[16]; //   Authentication tag length is 128 bits (16 bytes)

    component zeroBlock = ToBlocks(16);
    for (var i = 0; i < 16; i++) {
        zeroBlock.stream[i] <== 0;
    }

    // Step 1: Let H = aes(key, zeroBlock)
    component cipherH = Cipher();
    cipherH.key <== key;
    cipherH.block <== zeroBlock.blocks[0];

    // Step 2: Define a block, J0 with 96 bits of iv and 32 bits of 0s
    component J0builder = ToBlocks(16);
    for (var i = 0; i < 12; i++) {
        J0builder.stream[i] <== iv[i];
    }
    for (var i = 12; i < 16; i++) {
        J0builder.stream[i] <== 0;
    }
    component J0WordIncrementer = IncrementWord();
    J0WordIncrementer.in <== J0builder.blocks[0][3];

    component J0WordIncrementer2 = IncrementWord();
    J0WordIncrementer2.in <== J0WordIncrementer.out;

    signal J0[4][4];
    for (var i = 0; i < 3; i++) {
        J0[i] <== J0builder.blocks[0][i];
    }
    J0[3] <== J0WordIncrementer2.out;

    // Step 3: Let C = GCTRK(inc32(J0), P)
    component gctr = GCTR(l);
    gctr.key <== key;
    gctr.initialCounterBlock <== J0;
    gctr.plainText <== plainText;


    // Step 4: Let u and v (v is always zero with out key size and aad length)
    var blockCount = l\16;
    if(l%16 > 0){
        blockCount = blockCount + 1;
    }
    // so the reason there is a plus two is because 
    // the first block is the aad 
    // the second is the ciphertext
    // the last is the length of the aad and ciphertext
    // i.e. S = GHASHH (A || C || [len(A)] || [len(C)]). <- which is always 48 bytes: 3 blocks
    var ghashblocks = blockCount + 2; 
    signal ghashMessage[ghashblocks][4][4];

    // set aad as first block
    for (var i=0; i < 4; i++) {
        for (var j=0; j < 4; j++) {
            ghashMessage[0][i][j] <== aad[i*4+j];
        }
    }
    // set cipher text block padded
    component ciphertextBlocks = ToBlocks(l);
    ciphertextBlocks.stream <== gctr.cipherText;

    for (var i=0; i<blockCount; i++) {
        ghashMessage[i+1] <== ciphertextBlocks.blocks[i];
    }

    // length of aad = 128 = 0x80 as 64 bit number
    ghashMessage[ghashblocks-1][0] <== [0x00, 0x00, 0x00, 0x00];
    ghashMessage[ghashblocks-1][1] <== [0x00, 0x00, 0x00, 0x80];

    var len = blockCount * 128;
    for (var i=0; i<8; i++) {
        var byte_value = 0;
        for (var j=0; j<8; j++) {
            byte_value += (len >> i*8+j) & 1;
        }
        ghashMessage[ghashblocks-1][i\4+2][i%4] <== byte_value;
    }

    // Step 5: Define a block, S
    // needs to take in the number of blocks
    component ghash = GHASH(ghashblocks);
    component hashKeyToStream = ToStream(1, 16);
    hashKeyToStream.blocks[0] <== cipherH.cipher;
    ghash.HashKey <== hashKeyToStream.stream;
    // S = GHASHH (A || 0^v || C || 0^u || [len(A)] || [len(C)]).
    component selectedBlocksToStream[ghashblocks];
    for (var i = 0 ; i<ghashblocks ; i++) {
        ghash.msg[i] <== ToStream(1, 16)([ghashMessage[i]]);
    }

    signal bytes[16];
    signal tagBytes[16 * 8] <== BytesToBits(16)(ghash.tag);
    for(var i = 0; i < 16; i++) {
        var byteValue = 0;
        var sum=1;
        for(var j = 0; j<8; j++) {
            var bitIndex = i*8+j;
            byteValue += tagBytes[bitIndex]*sum;
            sum = sum*sum;
        }
        bytes[i] <== byteValue;
    }

    // Step 6: Let T = MSBt(GCTRK(J0, S))
    component gctrT = GCTR(16);
    gctrT.key <== key;
    gctrT.initialCounterBlock <== J0;
    gctrT.plainText <== bytes;

    authTag <== gctrT.cipherText;
    cipherText <== gctr.cipherText;
}