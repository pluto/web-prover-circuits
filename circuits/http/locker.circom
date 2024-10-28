pragma circom 2.1.9;

include "interpreter.circom";
include "parser/machine.circom";
include "../utils/bytes.circom";
include "../utils/search.circom";
include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/utils/array.circom";

template LockStartLine(DATA_BYTES, beginningLen, middleLen, finalLen) {
    signal input data[DATA_BYTES];
    signal input beginning[beginningLen];
    signal input middle[middleLen];
    signal input final[finalLen];

    //--------------------------------------------------------------------------------------------//
    //-CONSTRAINTS--------------------------------------------------------------------------------//
    //--------------------------------------------------------------------------------------------//
    component dataASCII = ASCII(DATA_BYTES);
    dataASCII.in <== data;
    //--------------------------------------------------------------------------------------------//

    // Initialze the parser
    component State[DATA_BYTES];
    State[0] = HttpStateUpdate();
    State[0].byte           <== data[0];
    State[0].parsing_start  <== 1;
    State[0].parsing_header <== 0;
    State[0].parsing_field_name <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body   <== 0;
    State[0].line_status    <== 0;

    /*
    Note, because we know a beginning is the very first thing in a request
    we can make this more efficient by just comparing the first `beginningLen` bytes
    of the data ASCII against the beginning ASCII itself.
    */
    // Check first beginning byte
    signal beginningIsEqual[beginningLen];
    beginningIsEqual[0] <== IsEqual()([data[0],beginning[0]]);
    beginningIsEqual[0] === 1;

    // Setup to check middle bytes
    signal startLineMask[DATA_BYTES];
    signal middleMask[DATA_BYTES];
    signal finalMask[DATA_BYTES];

    var middle_start_counter = 1;
    var middle_end_counter = 1;
    var final_end_counter = 1;
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = HttpStateUpdate();
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].parsing_start  <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name <== State[data_idx-1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx-1].next_parsing_field_value;
        State[data_idx].parsing_body   <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status    <== State[data_idx - 1].next_line_status;

        // Check remaining beginning bytes
        if(data_idx < beginningLen) {
            beginningIsEqual[data_idx] <== IsEqual()([data[data_idx], beginning[data_idx]]);
            beginningIsEqual[data_idx] === 1;
        }

        // Middle
        startLineMask[data_idx] <== inStartLine()(State[data_idx].parsing_start);
        middleMask[data_idx] <==  inStartMiddle()(State[data_idx].parsing_start);
        finalMask[data_idx] <== inStartEnd()(State[data_idx].parsing_start);
        middle_start_counter += startLineMask[data_idx] - middleMask[data_idx] - finalMask[data_idx];
        // The end of middle is the start of the final
        middle_end_counter += startLineMask[data_idx] - finalMask[data_idx];
        final_end_counter += startLineMask[data_idx];

        // Debugging
        log("State[", data_idx, "].parsing_start       = ", State[data_idx].parsing_start);
        log("State[", data_idx, "].parsing_header      = ", State[data_idx].parsing_header);
        log("State[", data_idx, "].parsing_field_name  = ", State[data_idx].parsing_field_name);
        log("State[", data_idx, "].parsing_field_value = ", State[data_idx].parsing_field_value);
        log("State[", data_idx, "].parsing_body        = ", State[data_idx].parsing_body);
        log("State[", data_idx, "].line_status         = ", State[data_idx].line_status);
        log("------------------------------------------------");
        log("middle_start_counter                      = ", middle_start_counter);
        log("middle_end_counter                        = ", middle_end_counter);
        log("final_end_counter                       = ", final_end_counter);
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    // Debugging
    log("State[", DATA_BYTES, "].parsing_start      ", "= ", State[DATA_BYTES-1].next_parsing_start);
    log("State[", DATA_BYTES, "].parsing_header     ", "= ", State[DATA_BYTES-1].next_parsing_header);
    log("State[", DATA_BYTES, "].parsing_field_name ", "= ", State[DATA_BYTES-1].parsing_field_name);
    log("State[", DATA_BYTES, "].parsing_field_value", "= ", State[DATA_BYTES-1].parsing_field_value);
    log("State[", DATA_BYTES, "].parsing_body       ", "= ", State[DATA_BYTES-1].next_parsing_body);
    log("State[", DATA_BYTES, "].line_status        ", "= ", State[DATA_BYTES-1].next_line_status);
    log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    // Additionally verify beginning had correct length
    beginningLen === middle_start_counter - 1;

    // Check middle is correct by substring match and length check
    signal middleMatch <== SubstringMatchWithIndex(DATA_BYTES, middleLen)(data, middle, middle_start_counter);
    middleMatch === 1;
    middleLen === middle_end_counter - middle_start_counter - 1;

    // Check final is correct by substring match and length check
    signal finalMatch <== SubstringMatchWithIndex(DATA_BYTES, finalLen)(data, final, middle_end_counter);
    finalMatch === 1;
    // -2 here for the CRLF
    finalLen === final_end_counter - middle_end_counter - 2;
}

template LockHeader(DATA_BYTES, headerNameLen, headerValueLen) {
    signal input data[DATA_BYTES];
    signal input header[headerNameLen];
    signal input value[headerValueLen];

    //--------------------------------------------------------------------------------------------//
    //-CONSTRAINTS--------------------------------------------------------------------------------//
    //--------------------------------------------------------------------------------------------//
    component dataASCII = ASCII(DATA_BYTES);
    dataASCII.in <== data;
    //--------------------------------------------------------------------------------------------//

    // Initialze the parser
    component State[DATA_BYTES];
    State[0] = HttpStateUpdate();
    State[0].byte           <== data[0];
    State[0].parsing_start  <== 1;
    State[0].parsing_header <== 0;
    State[0].parsing_field_name <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body   <== 0;
    State[0].line_status    <== 0;

    component headerFieldNameValueMatch[DATA_BYTES];
    signal isHeaderFieldNameValueMatch[DATA_BYTES];

    isHeaderFieldNameValueMatch[0] <== 0;
    var hasMatched = 0;

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = HttpStateUpdate();
        State[data_idx].byte           <== data[data_idx];
        State[data_idx].parsing_start  <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name <== State[data_idx-1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx-1].next_parsing_field_value;
        State[data_idx].parsing_body   <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status    <== State[data_idx - 1].next_line_status;

        headerFieldNameValueMatch[data_idx] =  HeaderFieldNameValueMatch(DATA_BYTES, headerNameLen, headerValueLen);
        headerFieldNameValueMatch[data_idx].data <== data;
        headerFieldNameValueMatch[data_idx].headerName <== header;
        headerFieldNameValueMatch[data_idx].headerValue <== value;
        headerFieldNameValueMatch[data_idx].index <== data_idx;
        isHeaderFieldNameValueMatch[data_idx] <== isHeaderFieldNameValueMatch[data_idx-1] + headerFieldNameValueMatch[data_idx].out;

        // Debugging
        log("State[", data_idx, "].parsing_start      ", "= ", State[data_idx].parsing_start);
        log("State[", data_idx, "].parsing_header     ", "= ", State[data_idx].parsing_header);
        log("State[", data_idx, "].parsing_field_name ", "= ", State[data_idx].parsing_field_name);
        log("State[", data_idx, "].parsing_field_value", "= ", State[data_idx].parsing_field_value);
        log("State[", data_idx, "].parsing_body       ", "= ", State[data_idx].parsing_body);
        log("State[", data_idx, "].line_status        ", "= ", State[data_idx].line_status);
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    // Debugging
    log("State[", DATA_BYTES, "].parsing_start      ", "= ", State[DATA_BYTES-1].next_parsing_start);
    log("State[", DATA_BYTES, "].parsing_header     ", "= ", State[DATA_BYTES-1].next_parsing_header);
    log("State[", DATA_BYTES, "].parsing_field_name ", "= ", State[DATA_BYTES-1].parsing_field_name);
    log("State[", DATA_BYTES, "].parsing_field_value", "= ", State[DATA_BYTES-1].parsing_field_value);
    log("State[", DATA_BYTES, "].parsing_body       ", "= ", State[DATA_BYTES-1].next_parsing_body);
    log("State[", DATA_BYTES, "].line_status        ", "= ", State[DATA_BYTES-1].next_line_status);
    log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    isHeaderFieldNameValueMatch[DATA_BYTES - 1] === 1;
}