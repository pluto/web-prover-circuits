pragma circom 2.1.9;

include "./parser/parser.circom";
include "./parser/language.circom";
include "../utils/search.circom";
include "../utils/array.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/utils/functions.circom";
include "@zk-email/circuits/utils/array.circom";

/// Checks if current byte is inside a JSON key or not
///
/// # Arguments
/// - `n`: maximum stack depth
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte is inside a key
template InsideKeyAtTop(n) {
    signal input stack[n][2];
    signal input parsing_string;
    signal input parsing_number;

    signal output out;

    component topOfStack = GetTopOfStack(n);
    topOfStack.stack <== stack;
    _ <== topOfStack.pointer;
    signal currentVal[2] <== topOfStack.value;

    signal parsingStringAndNotNumber <== parsing_string * (1 - parsing_number);
    signal ifParsingKey <== currentVal[0] * (1-currentVal[1]);

    out <== ifParsingKey * parsingStringAndNotNumber;
}

/// Checks if current byte is inside a JSON key or not
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte is inside a key
template InsideKey() {
    signal input stack[2];
    signal input parsing_string;
    signal input parsing_number;

    signal output out;

    signal parsingStringAndNotNumber <== parsing_string * (1 - parsing_number);
    signal ifParsingKey <== stack[0] * (1-stack[1]);

    out <== ifParsingKey * parsingStringAndNotNumber;
}

/// Checks if current byte is inside a JSON value or not
///
/// # Arguments
/// - `n`: maximum stack depth
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte is inside a value
template InsideValueAtTop(n) {
    signal input stack[n][2];
    signal input parsing_string;
    signal input parsing_number;

    signal output out;

    component topOfStack = GetTopOfStack(n);
    topOfStack.stack <== stack;
    signal currentVal[2] <== topOfStack.value;

    signal parsingStringXORNumber <== XOR()(parsing_string, parsing_number);

    signal ifParsingValue <== currentVal[0] * currentVal[1];

    out <== ifParsingValue * parsingStringXORNumber;
}

/// Checks if current byte is inside a JSON value at specified depth
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte is inside a value
template InsideValue() {
    signal input stack[2];
    signal input parsing_string;
    signal input parsing_number;

    signal output out;

    signal ifParsingValue <== stack[0] * stack[1];
    signal parsingStringXORNumber <== XOR()(parsing_string, parsing_number);

    out <== ifParsingValue * parsingStringXORNumber;
}

/// Checks if current byte is inside a JSON value at specified depth
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte is inside a value
template InsideValueObject() {
    signal input prev_stack[2];
    signal input curr_stack[2];
    signal input parsing_string;
    signal input parsing_number;

    signal output out;

    signal insideObject <== IsEqual()([curr_stack[0], 1]);
    signal insideArrayArray <== IsEqual()([curr_stack[0], 2]);

    signal ifParsingValue <== prev_stack[0] * prev_stack[1];
    signal parsingStringXORNumber <== XOR()(parsing_string, parsing_number);
    signal insideObjectXORArray <== XOR()(insideObject, insideArrayArray);
    signal isInsideObjectOrStringValue <== Mux1()([parsingStringXORNumber, insideObjectXORArray], insideObjectXORArray);

    out <== ifParsingValue * isInsideObjectOrStringValue;
}

/// Checks if current byte is inside an array at specified index
///
/// # Arguments
/// - `n`: maximum stack depth
/// - `index`: index of array element
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte represents an array element at `index`
template InsideArrayIndexAtTop(n, index) {
    signal input stack[n][2];
    signal input parsing_string;
    signal input parsing_number;

    signal output out;

    component topOfStack = GetTopOfStack(n);
    topOfStack.stack <== stack;
    signal currentVal[2] <== topOfStack.value;

    signal insideArray <== IsEqual()([currentVal[0], 2]);
    signal insideIndex <== IsEqual()([currentVal[1], index]);
    signal insideArrayIndex <== insideArray * insideIndex;
    signal parsingStringXORNumber <== XOR()(parsing_string, parsing_number);

    out <== insideArrayIndex * parsingStringXORNumber;
}

/// Checks if current byte is inside an array index at specified depth
///
/// # Arguments
/// - `index`: array element index
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte is inside an array index
template InsideArrayIndex(index) {
    signal input stack[2];
    signal input parsing_string;
    signal input parsing_number;

    signal output out;

    signal insideArray <== IsEqual()([stack[0], 2]);
    signal insideIndex <== IsEqual()([stack[1], index]);
    signal insideArrayIndex <== insideArray * insideIndex;
    out <== insideArrayIndex * (parsing_string + parsing_number);
}

/// Checks if current byte is inside an array index at specified depth
///
/// # Arguments
/// - `index`: array element index
///
/// # Inputs
/// - `stack`: current stack state
/// - `parsing_string`: whether current byte is inside a string or not
/// - `parsing_number`: wheter current byte is inside a number or not
///
/// # Output
/// - `out`: Returns `1` if current byte is inside an array index
template InsideArrayIndexObject() {
    signal input prev_stack[2];
    signal input curr_stack[2];
    signal input parsing_string;
    signal input parsing_number;
    signal input index;

    signal output out;

    signal insideArray <== IsEqual()([prev_stack[0], 2]);
    signal insideIndex <== IsEqual()([prev_stack[1], index]);
    signal insideObject <== IsEqual()([curr_stack[0], 1]);
    signal insideArrayArray <== IsEqual()([curr_stack[0], 2]);

    signal parsingStringXORNumber <== XOR()(parsing_string, parsing_number);
    signal insideObjectXORArray <== XOR()(insideObject, insideArrayArray);
    signal isInsideObjectOrStringValue <== Mux1()([parsingStringXORNumber, insideObjectXORArray], insideObjectXORArray);
    signal insideArrayIndex <== insideArray * insideIndex;
    out <== insideArrayIndex * isInsideObjectOrStringValue;
}

/// Returns whether next key-value pair starts.
///
/// # Arguments
/// - `n`: maximum stack depth
///
/// # Inputs
/// - `stack`: current stack state
/// - `curr_byte`: current parsed byte
///
/// # Output
/// - `out`: Returns `1` for next key-value pair.
template NextKVPair(n) {
    signal input stack[n][2];
    signal input currByte;
    signal output out;

    component topOfStack = GetTopOfStack(n);
    topOfStack.stack <== stack;
    signal currentVal[2] <== topOfStack.value;

    signal isNextPair <== IsEqualArray(2)([currentVal, [1, 0]]);

    component syntax = Syntax();
    signal isComma <== IsEqual()([currByte, syntax.COMMA]); // `, -> 44`

    out <== isNextPair*isComma ;
}

/// Returns whether next key-value pair starts.
/// Applies following checks:
/// - get top of stack value and check whether parsing key: `[1, 0]`
/// - current byte = `,`
/// - current stack height is less than the key to be matched (it means that new key has started)
///
/// # Arguments
/// - `n`: maximum stack depth
/// - `depth`: depth of matched key-value pair
///
/// # Inputs
/// - `stack`: current stack state
/// - `curr_byte`: current parsed byte
///
/// # Output
/// - `out`: Returns `1` for next key-value pair at specified depth.
template NextKVPairAtDepth(n) {
    signal input stack[n][2];
    signal input currByte;
    signal input depth;
    signal output out;

    var logMaxDepth = log2Ceil(n+1);

    component topOfStack = GetTopOfStack(n);
    topOfStack.stack <== stack;
    signal currentVal[2] <== topOfStack.value;
    signal pointer <== topOfStack.pointer;

    signal isNextPair <== IsEqualArray(2)([currentVal, [1, 0]]);

    // `,` -> 44
    signal isComma <== IsEqual()([currByte, 44]);
    // pointer <= depth
    // TODO: `LessThan` circuit warning
    signal atLessDepth <== LessEqThan(logMaxDepth)([pointer-1, depth]);
    // current depth is less than key depth
    signal isCommaAtDepthLessThanCurrent <== isComma * atLessDepth;

    out <== isNextPair * isCommaAtDepthLessThanCurrent;
}

/// Matches a JSON key at an `index` using Substring Matching
///
/// # Arguments
/// - `dataLen`: parsed data length
/// - `keyLen`: key length
///
/// # Inputs
/// - `data`: data bytes
/// - `key`: key bytes
/// - `r`: random number for substring matching. **Need to be chosen carefully.**
/// - `index`: data index to match from
/// - `parsing_key`: if current byte is inside a key
///
/// # Output
/// - `out`: Returns `1` if `key` matches `data` at `index`
template KeyMatch(dataLen, keyLen) {
    signal input data[dataLen];
    signal input key[keyLen];
    signal input index;
    signal input parsing_key;

    // `"` -> 34
    signal end_of_key <== IndexSelector(dataLen)(data, index + keyLen);
    signal is_end_of_key_equal_to_quote <== IsEqual()([end_of_key, 34]);

    signal start_of_key <== IndexSelector(dataLen)(data, index - 1);
    signal is_start_of_key_equal_to_quote <== IsEqual()([start_of_key, 34]);

    signal substring_match <== SubstringMatchWithIndex(dataLen, keyLen)(data, key, index);

    signal is_key_between_quotes <== is_start_of_key_equal_to_quote * is_end_of_key_equal_to_quote;
    signal is_parsing_correct_key <== is_key_between_quotes * parsing_key;

    signal output out <== substring_match * is_parsing_correct_key;
}

/// Matches a JSON key at an `index` using Substring Matching at specified depth
///
/// # Arguments
/// - `dataLen`: parsed data length
/// - `n`: maximum stack height
/// - `keyLen`: key length
/// - `depth`: depth of key to be matched
///
/// # Inputs
/// - `data`: data bytes
/// - `key`: key bytes
/// - `r`: random number for substring matching. **Need to be chosen carefully.**
/// - `index`: data index to match from
/// - `parsing_key`: if current byte is inside a key
/// - `stack`: parser stack output
///
/// # Output
/// - `out`: Returns `1` if `key` matches `data` at `index`
template KeyMatchAtDepth(dataLen, n, keyLen, depth) {
    signal input data[dataLen];
    signal input key[keyLen];
    signal input index;
    signal input parsing_key;
    signal input stack[n][2];

    component topOfStack = GetTopOfStack(n);
    topOfStack.stack <== stack;
    signal pointer <== topOfStack.pointer;
    _ <== topOfStack.value;

    // `"` -> 34

    // end of key equals `"`
    signal end_of_key <== IndexSelector(dataLen)(data, index + keyLen);
    signal is_end_of_key_equal_to_quote <== IsEqual()([end_of_key, 34]);

    // start of key equals `"`
    signal start_of_key <== IndexSelector(dataLen)(data, index - 1);
    signal is_start_of_key_equal_to_quote <== IsEqual()([start_of_key, 34]);

    // key matches
    signal substring_match <== SubstringMatchWithIndex(dataLen, keyLen)(data, key, index);

    // key should be a string
    signal is_key_between_quotes <== is_start_of_key_equal_to_quote * is_end_of_key_equal_to_quote;

    // is the index given correct?
    signal is_parsing_correct_key <== is_key_between_quotes * parsing_key;
    // is the key given by index at correct depth?
    signal is_key_at_depth <== IsEqual()([pointer-1, depth]);

    signal is_parsing_correct_key_at_depth <== is_parsing_correct_key * is_key_at_depth;

    signal output out <== substring_match * is_parsing_correct_key_at_depth;
}

template MatchPaddedKey(n) {
    signal input in[2][n];
    signal input keyLen;
    signal output out;

    var accum = 0;
    component equalComponent[n];
    component isPaddedElement[n];

    signal isEndOfKey[n];
    signal isQuote[n];
    signal endOfKeyAccum[n+1];
    endOfKeyAccum[0] <== 0;

    for(var i = 0; i < n; i++) {
        isEndOfKey[i] <== IsEqual()([i, keyLen]);
        isQuote[i] <== IsEqual()([in[1][i], 34]);
        endOfKeyAccum[i+1] <== endOfKeyAccum[i] + isEndOfKey[i] * isQuote[i];

        // TODO: might not be right to check for zero, instead check for -1?
        isPaddedElement[i] = IsZero();
        isPaddedElement[i].in <== in[0][i];

        equalComponent[i] = IsEqual();
        equalComponent[i].in[0] <== in[0][i];
        equalComponent[i].in[1] <== in[1][i] * (1-isPaddedElement[i].out);
        accum += equalComponent[i].out;
    }

    signal isEndOfKeyEqualToQuote <== IsEqual()([endOfKeyAccum[n], 1]);

    component totalEqual = IsEqual();
    totalEqual.in[0] <== n;
    totalEqual.in[1] <== accum;
    out <== totalEqual.out * isEndOfKeyEqualToQuote;
}

/// Matches a JSON key at an `index` using Substring Matching at specified depth
///
/// # Arguments
/// - `dataLen`: parsed data length
/// - `maxKeyLen`: maximum possible key length
/// - `index`: index of key in `data`
///
/// # Inputs
/// - `data`: data bytes
/// - `key`: key bytes
/// - `parsing_key`: if current byte is inside a key
///
/// # Output
/// - `out`: Returns `1` if `key` matches `data` at `index`
template KeyMatchAtIndex(dataLen, maxKeyLen, index) {
    signal input data[dataLen];
    signal input key[maxKeyLen];
    signal input keyLen;
    signal input parsing_key;

    signal paddedKey[maxKeyLen + 1];
    for (var i = 0 ; i < maxKeyLen ; i++) {
        paddedKey[i] <== key[i];
    }
    paddedKey[maxKeyLen] <== 0;
    // `"` -> 34

    // start of key equal to quote
    signal startOfKeyEqualToQuote <== IsEqual()([data[index - 1], 34]);
    signal isParsingCorrectKey <== parsing_key * startOfKeyEqualToQuote;

    // key matches
    component isSubstringMatch       = MatchPaddedKey(maxKeyLen+1);
    isSubstringMatch.in[0] <== paddedKey;
    isSubstringMatch.keyLen <== keyLen;
    for(var matcher_idx = 0; matcher_idx <= maxKeyLen; matcher_idx++) {
        isSubstringMatch.in[1][matcher_idx] <== data[index + matcher_idx];
    }
    _ <== data;

    signal output out <== isSubstringMatch.out * isParsingCorrectKey;
}