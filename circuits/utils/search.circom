pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "./operators.circom";
include "./array.circom";
include "@zk-email/circuits/utils/array.circom";

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
