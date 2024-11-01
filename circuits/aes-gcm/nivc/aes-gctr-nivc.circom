pragma circom 2.1.9;

include "gctr-nivc.circom";
include "../../utils/array.circom";


// Compute AES-GCTR
template AESGCTRFOLD(DATA_BYTES) {

    assert(DATA_BYTES % 16 == 0);
    var TOTAL_BYTES_ACROSS_NIVC = (DATA_BYTES * 2) + 4;

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
        last_counter_bits.in[i] <== step_in[DATA_BYTES*2 + i];
    }
    component last_counter_num = Bits2Num(32);
    // pass in reverse order
    for (var i = 0; i< 32; i++){
        last_counter_num.in[i] <== last_counter_bits.out[31 - i];
    }

    counter <== last_counter_num.out - 1;

    // write new plain text block.
    signal plainTextAccumulator[TOTAL_BYTES_ACROSS_NIVC];    
    component writeToIndex = WriteToIndex(TOTAL_BYTES_ACROSS_NIVC, 16);
    writeToIndex.array_to_write_to <== step_in;
    writeToIndex.array_to_write_at_index <== plainText;
    writeToIndex.index <== counter * 16;
    writeToIndex.out ==> plainTextAccumulator;

    // folds one block
    component aes = AESGCTRFOLDABLE();
    aes.key       <== key;
    aes.iv        <== iv;
    aes.aad       <== aad;
    aes.plainText <== plainText;

    for(var i = 0; i < 4; i++) {
        aes.lastCounter[i] <== step_in[DATA_BYTES*2 + i];
    }

    // accumulate cipher text
    signal cipherTextAccumulator[TOTAL_BYTES_ACROSS_NIVC];
    component writeCipherText = WriteToIndex(TOTAL_BYTES_ACROSS_NIVC, 16);
    writeCipherText.array_to_write_to <== plainTextAccumulator;
    writeCipherText.array_to_write_at_index <== aes.cipherText;
    writeCipherText.index <== DATA_BYTES + counter * 16;
    writeCipherText.out ==> cipherTextAccumulator;

    // get counter
    signal counterAccumulator[TOTAL_BYTES_ACROSS_NIVC];
    component writeCounter = WriteToIndex(TOTAL_BYTES_ACROSS_NIVC, 4);
    writeCounter.array_to_write_to <== cipherTextAccumulator;
    writeCounter.array_to_write_at_index <== aes.counter;
    writeCounter.index <== DATA_BYTES*2;
    writeCounter.out ==> step_out;
}