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

    // Regroup the plaintext and ciphertext into byte packed form
    var computedCipherText[NUM_CHUNKS][16];
    for(var i = 0 ; i < NUM_CHUNKS ; i++) {
        computedCipherText[i] = aes[i].cipherText;
    }
    signal packedCiphertext[NUM_CHUNKS] <== GenericBytePackArray(NUM_CHUNKS, 16)(cipherText);
    signal packedComputedCiphertext[NUM_CHUNKS] <== GenericBytePackArray(NUM_CHUNKS, 16)(computedCipherText);
    signal packedPlaintext[NUM_CHUNKS] <== GenericBytePackArray(NUM_CHUNKS, 16)(plainText);

    signal plaintext_input_was_zero_chunk[NUM_CHUNKS];
    signal ciphertext_input_was_zero_chunk[NUM_CHUNKS];
    signal both_input_chunks_were_zero[NUM_CHUNKS];
    signal ciphertext_option[NUM_CHUNKS];
    signal ciphertext_equal_check[NUM_CHUNKS];
    for(var i = 0 ; i < NUM_CHUNKS; i++) {
            plaintext_input_was_zero_chunk[i] <== IsZero()(packedPlaintext[i]);   
            ciphertext_input_was_zero_chunk[i] <== IsZero()(packedCiphertext[i]);
            both_input_chunks_were_zero[i] <== plaintext_input_was_zero_chunk[i] * ciphertext_input_was_zero_chunk[i];
            ciphertext_option[i] <== (1 - both_input_chunks_were_zero[i]) * packedComputedCiphertext[i];
            ciphertext_equal_check[i] <== IsEqual()([packedCiphertext[i], ciphertext_option[i]]);
            ciphertext_equal_check[i] === 1;
    }
    step_out[0] <== AESHasher(NUM_CHUNKS)(packedPlaintext, step_in[0]);
}

// TODO (autoparallel): Could probably just have datahasher take in an initial hash as an input, but this was quicker to try first.
template AESHasher(NUM_CHUNKS) {
    // TODO: add this assert back after witnesscalc supports
    // assert(DATA_BYTES % 16 == 0);
    signal input in[NUM_CHUNKS];
    signal input initial_hash;
    signal output out;

    signal not_to_hash[NUM_CHUNKS];
    signal option_hash[NUM_CHUNKS];
    signal hashes[NUM_CHUNKS + 1];
    hashes[0] <== initial_hash;
    for(var i = 0 ; i < NUM_CHUNKS ; i++) {
        not_to_hash[i] <== IsZero()(in[i]);
        option_hash[i] <== PoseidonChainer()([hashes[i],in[i]]);
        hashes[i+1]    <== not_to_hash[i] * (hashes[i] - option_hash[i]) + option_hash[i]; // same as: (1 - not_to_hash[i]) * option_hash[i] + not_to_hash[i] * hash[i];
    }
    out <== hashes[NUM_CHUNKS];
}