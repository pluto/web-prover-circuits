pragma circom 2.1.9;

include "../interpreter.circom";
include "../../utils/array.circom";
include "circomlib/circuits/comparators.circom";

// TODO: should use a MAX_HEADER_NAME_LENGTH and a MAX_HEADER_VALUE_LENGTH
template LockHeader(DATA_BYTES, MAX_STACK_HEIGHT, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    // Total number of variables in the parser for each byte of data
    /* 5 is for the variables:
        next_parsing_start
        next_parsing_header
        next_parsing_field_name
        next_parsing_field_value
        State[i].next_parsing_body
    */
    var TOTAL_BYTES_HTTP_STATE    = DATA_BYTES * (5 + 1); // data + parser vars
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (HttpParseAndLockStartLine or HTTPLockHeader)
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC];
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }
    signal httpParserState[DATA_BYTES * 5];
    for (var i = 0 ; i < DATA_BYTES * 5 ; i++) {
        httpParserState[i] <== step_in[DATA_BYTES + i];
    }

    // TODO: Better naming for these variables
    signal input header[MAX_HEADER_NAME_LENGTH];
    signal input headerNameLength;
    signal input value[MAX_HEADER_VALUE_LENGTH];
    signal input headerValueLength;

    // find header location
    signal headerNameLocation <== FirstStringMatch(DATA_BYTES, MAX_HEADER_NAME_LENGTH)(data, header);

    // This is the assertion that we have locked down the correct header
    signal headerFieldNameValueMatch <==  HeaderFieldNameValueMatchPadded(DATA_BYTES, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH)(data, header, headerNameLength, value, headerValueLength, headerNameLocation);
    headerFieldNameValueMatch === 1;

    // parser state should be parsing header upto 2^10 max headers
    signal isParsingHeader <== IndexSelector(DATA_BYTES * 5)(httpParserState, headerNameLocation * 5 + 1);
    signal parsingHeader <== GreaterThan(10)([isParsingHeader, 0]);
    parsingHeader === 1;

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write out to next NIVC step
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        // add plaintext http input to step_out
        step_out[i] <== step_in[i];

        // add parser state
        step_out[DATA_BYTES + i * 5]     <== step_in[DATA_BYTES + i * 5];
        step_out[DATA_BYTES + i * 5 + 1] <== step_in[DATA_BYTES + i * 5 + 1];
        step_out[DATA_BYTES + i * 5 + 2] <== step_in[DATA_BYTES + i * 5 + 2];
        step_out[DATA_BYTES + i * 5 + 3] <== step_in[DATA_BYTES + i * 5 + 3];
        step_out[DATA_BYTES + i * 5 + 4] <== step_in[DATA_BYTES + i * 5 + 4];
    }
    // Pad remaining with zeros
    for (var i = TOTAL_BYTES_HTTP_STATE ; i < TOTAL_BYTES_ACROSS_NIVC ; i++ ) {
        step_out[i] <== 0;
    }
}

// TODO: Handrolled template that I haven't tested YOLO.
template FirstStringMatch(dataLen, maxKeyLen) {
    signal input data[dataLen];
    signal input key[maxKeyLen];
    signal output position;

    signal paddedData[dataLen + maxKeyLen];
    for (var i = 0 ; i < dataLen ; i++) {
        paddedData[i] <== data[i];
    }
    for (var i = 0 ; i < maxKeyLen ; i++) {
        paddedData[dataLen + i] <== 0;
    }

    signal isMatched[dataLen+1];
    isMatched[0] <== 0;

    var counter = 0;
    component stringMatch[dataLen];
    component hasMatched[dataLen];
    signal isKeyOutOfBounds[maxKeyLen];
    signal isFirstMatchAndInsideBound[dataLen * maxKeyLen];
    for (var i = 0 ; i < maxKeyLen ; i++) {
        isKeyOutOfBounds[i] <== IsZero()(key[i]);
    }

    for (var idx = 0 ; idx < dataLen ; idx++) {
        stringMatch[idx] = IsEqualArray(maxKeyLen);
        stringMatch[idx].in[0] <== key;
        for (var key_idx = 0 ; key_idx < maxKeyLen ; key_idx++) {
            isFirstMatchAndInsideBound[idx * maxKeyLen + key_idx] <== (1 - isMatched[idx]) * (1 - isKeyOutOfBounds[key_idx]);
            stringMatch[idx].in[1][key_idx] <== paddedData[idx + key_idx] * isFirstMatchAndInsideBound[idx * maxKeyLen + key_idx];
        }
        hasMatched[idx] = IsEqual();
        hasMatched[idx].in <== [stringMatch[idx].out, 1];
        isMatched[idx+1] <== isMatched[idx] + hasMatched[idx].out;
        counter += (1 - isMatched[idx+1]); // TODO: Off by one? Move before?
    }
    position <== counter;
}


