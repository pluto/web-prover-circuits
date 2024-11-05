pragma circom 2.1.9;

include "gctr-nivc.circom";
include "../../utils/array.circom";


// Compute AES-GCTR
template AESGCTRFOLD(DATA_BYTES) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    assert(DATA_BYTES % 16 == 0);
    // Value for accumulating both plaintext and ciphertext as well as counter
    var TOTAL_BYTES_ACROSS_NIVC = 2 * DATA_BYTES + 4; 
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
    signal index <== last_counter_num.out - 1;

    // folds one block
    component aes = AESGCTRFOLDABLE();
    aes.key       <== key;
    aes.iv        <== iv;
    aes.aad       <== aad;
    aes.plainText <== plainText;

    for(var i = 0; i < 4; i++) {
        aes.lastCounter[i] <== step_in[DATA_BYTES * 2 + i];
    }


    // Write out the plaintext and ciphertext to our accumulation arrays, both at once.
    signal prevAccumulatedPlaintext[DATA_BYTES];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        prevAccumulatedPlaintext[i] <== step_in[i];
    }
    signal prevAccumulatedCiphertext[DATA_BYTES];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        prevAccumulatedCiphertext[i] <== step_in[DATA_BYTES + i];
    }
    component nextTexts = WriteToIndexForTwoArrays(DATA_BYTES, 16);
    nextTexts.first_array_to_write_to <== prevAccumulatedPlaintext;
    nextTexts.second_array_to_write_to <== prevAccumulatedCiphertext;
    nextTexts.first_array_to_write_at_index <== plainText;
    nextTexts.second_array_to_write_at_index <== aes.cipherText;
    nextTexts.index <== index * 16;


    for(var i = 0 ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
        if(i < DATA_BYTES) {
            step_out[i] <== nextTexts.outFirst[i];
        } else if(i < 2 * DATA_BYTES) {
            step_out[i] <== nextTexts.outSecond[i - DATA_BYTES];
        } else if(i < 2 * DATA_BYTES + 4) {
            step_out[i] <== aes.counter[i - (2 * DATA_BYTES)];
        }
    }
}



template WriteToIndexForTwoArrays(m, n) {
    signal input first_array_to_write_to[m];
    signal input second_array_to_write_to[m];
    signal input first_array_to_write_at_index[n];
    signal input second_array_to_write_at_index[n];
    signal input index;

    signal output outFirst[m];
    signal output outSecond[m];

    assert(m >= n);

    // Note: this is underconstrained, we need to constrain that index + n <= m
    // Need to constrain that index + n <= m -- can't be an assertion, because uses a signal
    // ------------------------- //

    // Here, we get an array of ALL zeros, except at the `index` AND `index + n`
    //                                    beginning-------^^^^^ end---^^^^^^^^^
    signal indexMatched[m];
    component indexBegining[m];
    component indexEnding[m];
    for(var i = 0 ; i < m ; i++) {
        indexBegining[i] = IsZero();
        indexBegining[i].in <== i - index;
        indexEnding[i] = IsZero();
        indexEnding[i].in <== i - (index + n);
        indexMatched[i] <== indexBegining[i].out + indexEnding[i].out;
    }

    // E.g., index == 31, m == 160, n == 16
    // => indexMatch[31] == 1;
    // => indexMatch[47] == 1;
    // => otherwise, all 0.

    signal accum[m];
    accum[0] <== indexMatched[0];

    component writeAt = IsZero();
    writeAt.in <== accum[0] - 1;

    component orFirst = OR();
    orFirst.a <== (writeAt.out * first_array_to_write_at_index[0]);
    orFirst.b <== (1 - writeAt.out) * first_array_to_write_to[0];
    outFirst[0] <== orFirst.out;

    component orSecond = OR();
    orSecond.a <== (writeAt.out * second_array_to_write_at_index[0]);
    orSecond.b <== (1 - writeAt.out) * second_array_to_write_to[0];
    outSecond[0] <== orSecond.out;
    //          IF accum == 1 then { array_to_write_at } ELSE IF accum != 1 then { array to write_to }
    signal accum_index[m];
    accum_index[0] <== accum[0];

    component writeSelector[m - 1];
    component indexSelectorFirst[m - 1];
    component indexSelectorSecond[m - 1];
    component orsFirst[m-1];
    component orsSecond[m-1];
    for(var i = 1 ; i < m ; i++) {
        // accum will be 1 at all indices where we want to write the new array
        accum[i] <== accum[i-1] + indexMatched[i];
        writeSelector[i-1] = IsZero();
        writeSelector[i-1].in <== accum[i] - 1;
        // IsZero(accum[i] - 1); --> tells us we are in the range where we want to write the new array

        indexSelectorFirst[i-1] = IndexSelector(n);
        indexSelectorFirst[i-1].index <== accum_index[i-1];
        indexSelectorFirst[i-1].in <== first_array_to_write_at_index;

        indexSelectorSecond[i-1] = IndexSelector(n);
        indexSelectorSecond[i-1].index <== accum_index[i-1];
        indexSelectorSecond[i-1].in <== second_array_to_write_at_index;
        // When accum is not zero, out is array_to_write_at_index, otherwise it is array_to_write_to

        orsFirst[i-1] = OR();
        orsFirst[i-1].a <== (writeSelector[i-1].out * indexSelectorFirst[i-1].out);
        orsFirst[i-1].b <== (1 - writeSelector[i-1].out) * first_array_to_write_to[i];
        outFirst[i] <== orsFirst[i-1].out;

        orsSecond[i-1] = OR();
        orsSecond[i-1].a <== (writeSelector[i-1].out * indexSelectorSecond[i-1].out);
        orsSecond[i-1].b <== (1 - writeSelector[i-1].out) * second_array_to_write_to[i];
        outSecond[i] <== orsSecond[i-1].out;

        accum_index[i] <== accum_index[i-1] + writeSelector[i-1].out;
    }
}
