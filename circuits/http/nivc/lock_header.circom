pragma circom 2.1.9;

include "../parser/machine.circom";
include "../interpreter.circom";
include "../../utils/array.circom";
include "circomlib/circuits/comparators.circom";

// TODO: should use a MAX_HEADER_NAME_LENGTH and a MAX_HEADER_VALUE_LENGTH
template LockHeader(DATA_BYTES, MAX_HEADER_NAME_LENGTH, MAX_HEADER_VALUE_LENGTH) {
    // ------------------------------------------------------------------------------------------------------------------ //
    var TOTAL_BYTES_ACROSS_NIVC   = DATA_BYTES * 2 + 4; // aes pt/ct + ctr
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    signal input step_in[TOTAL_BYTES_ACROSS_NIVC];
    signal output step_out[TOTAL_BYTES_ACROSS_NIVC];

    // get the plaintext
    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }
    
    // ------------------------------------------------------------------------------------------------------------------ //
    // PARSE
    // Initialze the parser
    component State[DATA_BYTES];
    State[0]                     = HttpStateUpdate();
    State[0].byte                <== data[0];
    State[0].parsing_start       <== 1;
    State[0].parsing_header      <== 0;
    State[0].parsing_field_name  <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body        <== 0;
    State[0].line_status         <== 0;

    // TODO (autoparallel): Redundant as fuck, but I'm doing this quickly sorry. I don't think this actually adds constraints
    signal httpParserState[DATA_BYTES * 5];


    var middle_start_counter = 1;
    var middle_end_counter = 1;
    var final_end_counter = 1;
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                     = HttpStateUpdate();
        State[data_idx].byte                <== data[data_idx];
        State[data_idx].parsing_start       <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header      <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name  <== State[data_idx - 1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx - 1].next_parsing_field_value;
        State[data_idx].parsing_body        <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status         <== State[data_idx - 1].next_line_status;
    }
    // ------------------------------------------------------------------------------------------------------------------ //

    
    // TODO (autoparallel): again bad
    // Get those redundant variables
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        httpParserState[i * 5]     <== State[i].next_parsing_start;
        httpParserState[i * 5 + 1] <== State[i].next_parsing_header;
        httpParserState[i * 5 + 2] <== State[i].next_parsing_field_name;
        httpParserState[i * 5 + 3] <== State[i].next_parsing_field_value;
        httpParserState[i * 5 + 4] <== State[i].next_parsing_body;
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
    // write out the pt again
    for (var i = 0 ; i < TOTAL_BYTES_ACROSS_NIVC ; i++) {
        // add plaintext http input to step_out and ignore the ciphertext
        if(i < DATA_BYTES) {
            step_out[i] <== step_in[i];
        } else {
            step_out[i] <== 0;
        }
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


