pragma circom 2.1.9;

include "gctr-nivc.circom";
include "../../utils/array.circom";


// Compute AES-GCTR
template AESGCTRFOLD(DATA_BYTES) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    assert(DATA_BYTES % 16 == 0);
    // Value for accumulating both packed plaintext and ciphertext as well as counter
    // var TOTAL_BYTES_ACROSS_NIVC = DATA_BYTES + 4; 
    // ------------------------------------------------------------------------------------------------------------------ //


    signal input key[16];
    signal input iv[12];
    signal input aad[16];
    signal input plainText[16];

    // step_in[0..DATA_BYTES] => accumulate plaintext blocks
    // step_in[DATA_BYTES..DATA_BYTES*2]  => accumulate ciphertext blocks
    // step_in[DATA_BYTES_LEN*2..DATA_BYTES*2+4]  => accumulate counter
    signal input step_in[4];
    signal output step_out[4];


    // We extract the number from the 4 byte word counter
    component last_counter_bits = BytesToBits(4);
    for(var i = 0; i < 4; i ++) {
        last_counter_bits.in[i] <== step_in[i];
    }
    component last_counter_num = Bits2Num(32);
    // pass in reverse order
    for (var i = 0; i< 32; i++){
        last_counter_num.in[i] <== last_counter_bits.out[31 - i];
    }
    signal index <== last_counter_num.out - 1;

    // folds one block
    component aes = AESGCTRFOLDABLE();
    aes.key       <== key;
    aes.iv        <== iv;
    aes.aad       <== aad;
    aes.plainText <== plainText;

    for(var i = 0; i < 4; i++) {
        aes.lastCounter[i] <== step_in[i];
    }

    // Write out the plaintext and ciphertext to our accumulation arrays, both at once.
    signal nextPackedChunk[16] <== DoubleBytePackArray(16)(plainText, aes.cipherText);

    signal prevAccumulatedPackedText[DATA_BYTES];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        prevAccumulatedPackedText[i] <== 0;
    }
    component nextAccumulatedPackedText = WriteToIndex(DATA_BYTES, 16);
    nextAccumulatedPackedText.array_to_write_to <== prevAccumulatedPackedText;
    nextAccumulatedPackedText.array_to_write_at_index <== nextPackedChunk;
    nextAccumulatedPackedText.index <== index * 16;

    step_out <== aes.counter;
    // for(var i = 0 ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
    //     if(i < DATA_BYTES) {
    //         step_out[i] <== nextAccumulatedPackedText.out[i];
    //     } else {
    //         step_out[i] <== aes.counter[i - DATA_BYTES];
    //     }
    // }
}

