pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "./array.circom";
include "./functions.circom";

template MaskedByteStreamDigest(DATA_BYTES) {
    signal input in[DATA_BYTES];
    signal output out;

    signal hashes[DATA_BYTES + 1];
    signal option_hash[DATA_BYTES];
    signal not_to_hash[DATA_BYTES];
    hashes[0] <== 0;
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        not_to_hash[i] <== IsEqual()([in[i], -1]);
        option_hash[i] <== Poseidon(2)([hashes[i],in[i]]);
        hashes[i+1]    <== not_to_hash[i] * (hashes[i] - option_hash[i]) + option_hash[i]; // same as: (1 - not_to_hash[i]) * option_hash[i] + not_to_hash[i] * hash[i];
    }
    out <== hashes[DATA_BYTES];
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
        option_hash[i] <== Poseidon(2)([hashes[i],packedInput]);
        hashes[i+1]    <== not_to_hash[i] * (hashes[i] - option_hash[i]) + option_hash[i]; // same as: (1 - not_to_hash[i]) * option_hash[i] + not_to_hash[i] * hash[i];
    }
    out <== hashes[DATA_BYTES \ 16];
}

template PolynomialDigest(N) {
    signal input bytes[N];
    signal input polynomial_input;

    signal output digest;

    signal monomials[N];
    signal terms[N];
    monomials[0] <== 1;
    terms[0]     <== bytes[0] * monomials[0];
    var accumulation = terms[0];
    for(var i = 1 ; i < N ; i++) {
        monomials[i] <== monomials[i - 1] * polynomial_input;
        terms[i]     <== monomials[i] * bytes[i];
        accumulation  += terms[i];
    }
    digest <== accumulation;
}

template PolynomialDigestWithCounter(N) {
    signal input bytes[N];
    signal input polynomial_input;
    signal input counter;

    var logN = log2Ceil(N);

    signal output digest;

    signal monomials[N];
    signal terms[N];

    signal pow_accumulation[N+1];
    pow_accumulation[0] <== 1;
    signal isLessThanCounter[N];
    signal multFactor[N];
    for (var i = 0 ; i < N ; i++) {
        isLessThanCounter[i] <== LessThan(logN)([i, counter]);
        multFactor[i]        <== isLessThanCounter[i] * polynomial_input + (1 - isLessThanCounter[i]);
        pow_accumulation[i+1] <== pow_accumulation[i] * multFactor[i];
    }

    // monomials[0] = polynomial_input ** counter
    monomials[0] <== pow_accumulation[N];
    terms[0]     <== bytes[0] * monomials[0];
    var accumulation = terms[0];
    for(var i = 1 ; i < N ; i++) {
        monomials[i] <== monomials[i - 1] * polynomial_input;
        terms[i]     <== monomials[i] * bytes[i];
        accumulation  += terms[i];
    }
    digest <== accumulation;
}