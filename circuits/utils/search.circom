pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "./hash.circom";
include "./operators.circom";
include "./array.circom";
include "@zk-email/circuits/utils/array.circom";

/*
SubstringSearch

Calculates the index of a substring within a larger string. Uses a probabilistic algorithm to find a substring that is equal to random linear combination of difference between each element of `data` and `key`.

# NOTE
- Is underconstrained and not suitable for standalone usage, i.e. `position` returned can be spoofed by an adversary. Must be verified with a similar template like `SubstringMatch`
- `r` should be equal to Hash(key + data), otherwise this algorithm yields false positives

# Parameters
- `dataLen`: The maximum length of the input string
- `keyLen`: The maximum length of the substring to be matched

# Inputs
- `data` Array of ASCII characters as input string
- `key` Array of ASCII characters as substring to be searched in `data`
- `random_num`: randomiser used to perform random linear summation for string comparison

# Output
- `position`: index of matched `key` in `data`
*/
template SubstringSearch(dataLen, keyLen) {
    signal input data[dataLen];
    signal input key[keyLen];
    signal input random_num;
    signal output position;

    assert(dataLen > 0);
    assert(keyLen > 0);
    assert(dataLen >= keyLen);

    // position accumulator
    signal pos[dataLen-keyLen+2];
    pos[0] <== 0;

    // total matches found so far
    signal num_matches[dataLen-keyLen+2];
    num_matches[0] <== 0;

    // calculate powers of r
    signal r_powers[dataLen];
    r_powers[0] <== random_num;
    for (var i=1 ; i<dataLen ; i++) {
        r_powers[i] <== r_powers[i-1] * random_num;
    }

    signal is_match_found[dataLen-keyLen+1];
    signal is_first_match[dataLen-keyLen+1];
    signal index_at_first_match_and_found[dataLen-keyLen+1];
    signal found[dataLen-keyLen+1][keyLen];

    // iterate through each substring of length `keyLen` in `data` and find substring that matches.
    for (var i = 0; i < dataLen - keyLen + 1; i++) {
        // underconstrained part, any malicious prover can set found to `0` manually
        found[i][0] <-- r_powers[0] * (data[i] - key[0]);
        for (var j=1 ; j < keyLen ; j++) {
            found[i][j] <-- found[i][j-1] + r_powers[j] * (data[i+j]-key[j]);
        }

        // is substring a match?
        is_match_found[i] <== IsZero()(found[i][keyLen-1]);

        // update total number of matches found
        num_matches[i+1] <== num_matches[i] + is_match_found[i];

        // is substring first match?
        is_first_match[i] <== IsEqual()([1, num_matches[i+1]]);

        // n
        // should be only first match
        index_at_first_match_and_found[i] <== Mux1()([0, i], is_match_found[i] * is_first_match[i]);
        pos[i+1] <== pos[i] + index_at_first_match_and_found[i];
    }

    assert(pos[dataLen-keyLen+1] < dataLen - keyLen + 1);
    position <== pos[dataLen-keyLen+1];
}

/*
RLC algorithm for matching substring at index.
- Creates a mask for `data` at `[start, start + keyLen]`
- apply mask to data
- multiply data with powers of `r` to create random linear combination
- multiply key with powers of `r`
- sum of both arrays should be equal

# Parameters
- `dataLen`: The maximum length of the input string
- `keyLen`: The maximum length of the substring to be matched

# Inputs
- `data`: Array of ASCII characters as input string
- `key`: Array of ASCII characters as substring to be searched in `data`
- `position`: Index of `key` in `data`

# Profile
9 * `dataLen` constraints

NOTE: Modified from https://github.com/zkemail/zk-email-verify/tree/main/packages/circuits
*/
template SubstringMatchWithHasher(dataLen, keyLen) {
    signal input data[dataLen];
    signal input key[keyLen];
    signal input r;
    signal input start;

    signal output out;

    // key end index in `data`
    signal end;
    end <== start + keyLen;

    // 2n constraints
    //
    // create start mask from [pos, dataLen-1]
    // | 0 | 0 0 0 0 0 0 |1| 1 1 1 |1| 1 1 |1|
    //   0              start      end   dataLen
    signal startMask[dataLen];
    signal startMaskEq[dataLen];
    startMaskEq[0] <== IsEqual()([0, start]);
    startMask[0] <== startMaskEq[0];
    for (var i = 1 ; i < dataLen ; i++) {
        startMaskEq[i] <== IsEqual()([i, start]);
        startMask[i] <== startMask[i-1] + startMaskEq[i];
    }

    // 3n constraints
    //
    // create end mask from [0, end]
    // | 1 | 1 1 1 1 1 1 |1| 1 1 1 |1| 0 0 |0|
    //   0              start      end   dataLen
    signal endMask[dataLen];
    signal endMaskEq[dataLen];
    endMaskEq[0] <== IsEqual()([0, end]);
    endMask[0] <== 1 - endMaskEq[0];
    for (var i = 1 ; i < dataLen ; i++) {
        endMaskEq[i] <== IsEqual()([i, end]);
        endMask[i] <== endMask[i-1] * (1 - endMaskEq[i]);
    }

    // n constraints
    //
    // combine start mask and end mask
    // | 0 | 0 0 0 0 0 0 |1| 1 1 1 |1| 0 0 |0|
    //   0              start      end   dataLen
    signal mask[dataLen];
    for (var i = 0; i < dataLen; i++) {
        mask[i] <== startMask[i] * endMask[i];
    }

    // n constraints
    //
    // masked data from mask
    signal maskedData[dataLen];
    for (var i = 0 ; i < dataLen ; i++) {
        maskedData[i] <== data[i] * mask[i];
    }

    // n constraints
    //
    // powers of `r` for masked data
    // if (masked data == 1) rDataMasked[i] = rDataMasked[i-1] * r
    // else rDataMasked[i] = rDataMasked[i-1]
    signal rDataMasked[dataLen];
    rDataMasked[0] <== Mux1()([1, r], mask[0]);
    for (var i = 1 ; i < dataLen ; i++) {
        rDataMasked[i] <== Mux1()([rDataMasked[i-1], rDataMasked[i-1] * r], mask[i]);
    }

    // powers of `r` for key
    signal rKeyMasked[keyLen];
    rKeyMasked[0] <== r;
    for (var i = 1; i < keyLen ; i++) {
        rKeyMasked[i] <== rKeyMasked[i-1] * r;
    }

    // n constraints
    //
    // calculate linear combination with random_num for data: data[i] = data[i-1] + (r^i * data[i])
    signal hashMaskedData[dataLen];
    hashMaskedData[0] <== rDataMasked[0] * maskedData[0];
    for (var i = 1; i < dataLen ; i++) {
        hashMaskedData[i] <== hashMaskedData[i-1] + (rDataMasked[i] * maskedData[i]);
    }

    // calculate linear combination with random_num for key: key[i] = key[i-1] + (r^i * key[i])
    signal hashMaskedKey[keyLen];
    hashMaskedKey[0] <== rKeyMasked[0] * key[0];
    for (var i = 1; i < keyLen ; i++) {
        hashMaskedKey[i] <== hashMaskedKey[i-1] + (rKeyMasked[i] * key[i]);
    }

    // final sum for data and key should be equal
    out <== IsZero()(hashMaskedData[dataLen-1]-hashMaskedKey[keyLen-1]);
}

/*
SubstringMatchWithIndex

matching substring at index by selecting a subarray and matching arrays

# Parameters
- `dataLen`: The maximum length of the input string
- `keyLen`: The maximum length of the substring to be matched

# Inputs
- `data`: Array of ASCII characters as input string
- `key`: Array of ASCII characters as substring to be searched in `data`
- `position`: Index of `key` in `data`
*/
template SubstringMatchWithIndex(dataLen, keyLen) {
    signal input data[dataLen];
    signal input key[keyLen];
    signal input start;

    var logDataLen = log2Ceil(dataLen + keyLen + 1);

    signal isStartLessThanMaxLength <== LessThan(logDataLen)([start, dataLen]);
    signal index <== start * isStartLessThanMaxLength;

    signal subarray[keyLen] <== SelectSubArray(dataLen, keyLen)(data, index, keyLen);
    signal isSubarrayMatch <== IsEqualArray(keyLen)([key, subarray]);
    signal output out <== isStartLessThanMaxLength * isSubarrayMatch;
}

template SubstringMatchWithIndexPadded(dataLen, maxKeyLen) {
    signal input data[dataLen];
    signal input key[maxKeyLen];
    signal input keyLen;
    signal input start;

    var logDataLen = log2Ceil(dataLen + maxKeyLen + 1);

    signal isStartLessThanMaxLength <== LessThan(logDataLen)([start, dataLen]);
    signal index <== start * isStartLessThanMaxLength;

    signal subarray[maxKeyLen] <== SelectSubArray(dataLen, maxKeyLen)(data, index, keyLen);
    signal isSubarrayMatch <== IsEqualArray(maxKeyLen)([key, subarray]);
    signal output out <== isStartLessThanMaxLength * isSubarrayMatch;
}

/*
SubstringMatch: Matches a substring with an input string and returns the position

# Parameters
- `dataLen`: maximum length of the input string
- `keyLen`: maximum length of the substring to be matched

# Inputs
- `data`: Array of ASCII characters as input string
- `key`: Array of ASCII characters as substring to be searched in `data`

# Outputs
- `position`: Index of `key` in `data`
*/
template SubstringMatch(dataLen, keyLen) {
    signal input data[dataLen];
    signal input key[keyLen];
    signal output position;

    // r must be secret, so either has to be derived from hash in the circuit or off the circuit
    component rHasher = PoseidonModular(dataLen + keyLen);
    for (var i = 0; i < keyLen; i++) {
        rHasher.in[i] <== key[i];
    }
    for (var i = 0; i < dataLen; i++) {
        rHasher.in[i + keyLen] <== data[i];
    }
    signal r <== rHasher.out;

    // find the start position of `key` first match in `data`
    // NOTE: underconstrained (should be paired with SubstringMatchWithIndex)
    signal start <== SubstringSearch(dataLen, keyLen)(data, key, r);

    // matches a `key` in `data` at `pos`
    // NOTE: constrained verification assures correctness
    signal isMatch <== SubstringMatchWithHasher(dataLen, keyLen)(data, key, r, start);
    isMatch === 1;

    position <== start;
}