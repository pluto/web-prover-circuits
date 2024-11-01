pragma circom 2.1.9;

include "gctr-nivc.circom";
include "../../utils/array.circom";


// Compute AES-GCTR
template AESGCTRFOLD(DATA_BYTES, MAX_STACK_HEIGHT) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~    
    assert(DATA_BYTES % 16 == 0); 
    // Total number of variables in the parser for each byte of data
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
    // ------------------------------------------------------------------------------------------------------------------ //
    

    signal input key[16];
    signal input iv[12];
    signal input aad[16];
    signal input plainText[16];

    // step_in[0..DATA_BYTES] => accumulate plaintext blocks
    // step_in[DATA_BYTES..DATA_BYTES*2]  => accumulate ciphertext blocks
    // step_in[DATA_BYTES_LEN*2..DATA_BYTES*2+4]  => accumulate counter
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC]; 
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];
    signal counter;

    // We extract the number from the 4 byte word counter
    component last_counter_bits = BytesToBits(4);
    for(var i = 0; i < 4; i ++) {
        last_counter_bits.in[i] <== step_in[DATA_BYTES * 2 + i];
    }
    component last_counter_num = Bits2Num(32);
    // pass in reverse order
    for (var i = 0; i< 32; i++){
        last_counter_num.in[i] <== last_counter_bits.out[31 - i];
    }

    counter <== last_counter_num.out;

    // TODO (Colin): We can't call this `WriteToIndex` array this many times, it is too expensive.
    // write new plain text block.
    signal prevAccumulatedPlaintext[DATA_BYTES];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        prevAccumulatedPlaintext[i] <== step_in[i];   
    }
    signal nextAccumulatedPlaintext[DATA_BYTES];    
    component writeToIndex = WriteToIndex(DATA_BYTES, 16);
    writeToIndex.array_to_write_to <== prevAccumulatedPlaintext;
    writeToIndex.array_to_write_at_index <== plainText;
    writeToIndex.index <== counter * 16;
    writeToIndex.out ==> nextAccumulatedPlaintext;
    
    // folds one block
    component aes = AESGCTRFOLDABLE();
    aes.key       <== key;
    aes.iv        <== iv;
    aes.aad       <== aad;
    aes.plainText <== plainText;

    for(var i = 0; i < 4; i++) {
        aes.lastCounter[i] <== step_in[DATA_BYTES * 2 + i];
    }

    // accumulate cipher text
    signal prevAccumulatedCiphertext[DATA_BYTES];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        prevAccumulatedCiphertext[i] <== step_in[DATA_BYTES + i];   
    }
    signal nextAccumulatedCiphertext[DATA_BYTES];
    component writeCipherText = WriteToIndex(DATA_BYTES, 16);
    writeCipherText.array_to_write_to <== prevAccumulatedCiphertext;
    writeCipherText.array_to_write_at_index <== aes.cipherText;
    writeCipherText.index <== counter * 16;
    writeCipherText.out ==> nextAccumulatedCiphertext;

    for(var i = 0 ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
        if(i < DATA_BYTES) {
            step_out[i] <== nextAccumulatedPlaintext[i];
        } else if(i < 2 * DATA_BYTES) {
            step_out[i] <== nextAccumulatedCiphertext[i - DATA_BYTES];
        } else if(i < 2 * DATA_BYTES + 4) {
            step_out[i] <== aes.counter[i - (2 * DATA_BYTES)];
        }
    }
}
