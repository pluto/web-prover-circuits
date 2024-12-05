pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "./array.circom";

/// Circuit to calculate Poseidon hash of an arbitrary number of inputs.
/// Splits input into chunks of 16 elements (or less for the last chunk) and hashes them separately
/// Then combines the chunk hashes using a binary tree structure.
///
/// NOTE: from <https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/utils/hash.circom#L49>
///
/// # Parameters
/// - `numElements`: Number of elements in the input array
///
/// # Inputs
/// - `in`: Array of numElements to be hashed
///
/// # Output
/// - `out`: Poseidon hash of the input array
template PoseidonModular(numElements) {
    signal input in[numElements];
    signal output out;

    var chunks = numElements \ 16;
    var last_chunk_size = numElements % 16;
    if (last_chunk_size != 0) {
        chunks += 1;
    }

    var _out;

    for (var i = 0; i < chunks; i++) {
        var start = i * 16;
        var end = start + 16;
        var chunk_hash;

        if (end > numElements) { // last chunk
            end = numElements;
            var last_chunk[last_chunk_size];
            for (var i=start ; i<end ; i++) {
                last_chunk[i-start] = in[i];
            }
            chunk_hash = Poseidon(last_chunk_size)(last_chunk);
        } else {
            var chunk[16];
            for (var i=start ; i<end ; i++) {
                chunk[i-start] = in[i];
            }
            chunk_hash = Poseidon(16)(chunk);
        }

        if (i == 0) {
            _out = chunk_hash;
        } else {
            _out = Poseidon(2)([_out, chunk_hash]);
        }
    }

    out <== _out;
}

template PoseidonChainer() {
    signal input in[2];
    signal output out;

    out <== Poseidon(2)(in);
}

template MaskedStreamDigest(DATA_BYTES) {
    signal input in[DATA_BYTES];
    signal output out;

    signal hashes[DATA_BYTES + 1];
    signal not_to_hash[DATA_BYTES];
    signal option_hash[DATA_BYTES];
    hashes[0] <== 0;
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        not_to_hash[i] <== IsEqual()([in[i], -1]);
        option_hash[i] <== PoseidonChainer()([hashes[i],i]);
        hashes[i+1]    <== not_to_hash[i] * (hashes[i] - option_hash[i]) + option_hash[i]; // same as: (1 - not_to_hash[i]) * option_hash[i] + not_to_hash[i] * hash[i];
    }
    out <== hashes[DATA_BYTES \ 16];
}

// TODO (autoparallel): This could modified to support an arbitrary length while combining 31 bytes at a time instead of 16
template DataHasher(DATA_BYTES) {
    // TODO: add this assert back after witnesscalc supports
    // assert(DATA_BYTES % 16 == 0);
    signal input in[DATA_BYTES];
    signal output out;

    signal not_to_hash[DATA_BYTES \ 16];
    signal option_hash[DATA_BYTES \ 16];
    signal hashes[DATA_BYTES \ 16 + 1];
    signal isPadding[DATA_BYTES];
    hashes[0] <== 0;
    for(var i = 0 ; i < DATA_BYTES \ 16 ; i++) {
        var packedInput = 0;
        var isPaddedChunk = 0;
        for(var j = 0 ; j < 16 ; j++) {
            /* 
            If in[16 * i + j] is ever -1 we get `isPadding[16 * i + j] === 1` and since we add this
            we get zero which does not change `packedInput`.
            */
            isPadding[16 * i + j] <== IsEqual()([in[16 * i + j], -1]);
            isPaddedChunk          += isPadding[16 * i + j];
            packedInput            += (in[16 * i + j] + isPadding[16 * i + j]) * 2**(8*j); 
        }
        not_to_hash[i] <== IsEqual()([isPaddedChunk, 16]);
        option_hash[i] <== PoseidonChainer()([hashes[i],packedInput]);
        hashes[i+1]    <== not_to_hash[i] * (hashes[i] - option_hash[i]) + option_hash[i]; // same as: (1 - not_to_hash[i]) * option_hash[i] + not_to_hash[i] * hash[i];
    }
    out <== hashes[DATA_BYTES \ 16];
}