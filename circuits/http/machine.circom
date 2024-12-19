pragma circom 2.1.9;

include "../utils/array.circom";

template HttpStateUpdate() {
    signal input parsing_start; // flag that counts up to 3 for each value in the start line
    signal input parsing_header; // Flag + Counter for what header line we are in
    signal input parsing_field_name; // flag that tells if parsing header field name
    signal input parsing_field_value; // flag that tells if parsing header field value
    signal input parsing_body; // Flag when we are inside body
    signal input line_status; // Flag that counts up to 4 to read a double CRLF
    signal input byte;

    signal output next_parsing_start;
    signal output next_parsing_header;
    signal output next_parsing_field_name;
    signal output next_parsing_field_value;
    signal output next_parsing_body;
    signal output next_line_status;

    //---------------------------------------------------------------------------------//
    // check if we read space: 32 or colon: 58
    component readSP = IsEqual();
    readSP.in <== [byte, 32];
    component readColon = IsEqual();
    readColon.in <== [byte, 58];

    // Check if what we just read is a CR / LF
    component readCR = IsEqual();
    readCR.in      <== [byte, 13];
    component readLF = IsEqual();
    readLF.in      <== [byte, 10];

    signal notCRAndLF <== (1 - readCR.out) * (1 - readLF.out);
    //---------------------------------------------------------------------------------//

    //---------------------------------------------------------------------------------//
    // Check if we had read previously CR / LF or multiple
    component prevReadCR     = IsEqual();
    prevReadCR.in          <== [line_status, 1];
    component prevReadCRLFCR = IsEqual();
    prevReadCRLFCR.in      <== [line_status, 3];

    signal readCRLF     <== prevReadCR.out * readLF.out;
    signal readCRLFCRLF <== prevReadCRLFCR.out * readLF.out;
    //---------------------------------------------------------------------------------//

    //---------------------------------------------------------------------------------//
    // Take current state and CRLF info to update state
    signal state[3]          <== [parsing_start, parsing_header, parsing_field_value];
    component stateChange      = StateChange();
    stateChange.readCRLF     <== readCRLF;
    stateChange.readCRLFCRLF <== readCRLFCRLF;
    stateChange.readSP       <== readSP.out;
    stateChange.readColon    <== readColon.out;
    stateChange.state        <== state;

    component nextState   = ArrayAdd(5);
    nextState.lhs       <== [state[0], state[1], parsing_field_name, parsing_field_value, parsing_body];
    nextState.rhs       <== stateChange.out;
    //---------------------------------------------------------------------------------//

    next_parsing_start       <== nextState.out[0];
    next_parsing_header      <== nextState.out[1];
    next_parsing_field_name  <== nextState.out[2];
    next_parsing_field_value <== nextState.out[3];
    next_parsing_body        <== nextState.out[4];
    next_line_status         <== line_status + readCR.out + readCRLF + readCRLFCRLF - line_status * notCRAndLF;
}

// TODO:
// - multiple space between start line values
// - handle incrementParsingHeader being incremented for header -> body CRLF
// - header value parsing doesn't handle SPACE between colon and actual value
template StateChange() {
    signal input readCRLF;
    signal input readCRLFCRLF;
    signal input readSP;
    signal input readColon;
    signal input state[3];
    signal output out[5];

    // GreaterEqThan(2) because start line can have at most 3 values for request or response
    signal isParsingStart <== GreaterEqThan(2)([state[0], 1]);
    // increment parsing start counter on reading SP
    signal incrementParsingStart <== readSP * isParsingStart;
    // disable parsing start on reading CRLF
    signal disableParsingStart <== readCRLF * state[0];

    // enable parsing header on reading CRLF
    signal enableParsingHeader <== readCRLF * isParsingStart;
    // check if we are parsing header
    // Allows for max headers to be 2^5 = 32
    signal isParsingHeader <== GreaterEqThan(5)([state[1], 1]);
    // increment parsing header counter on CRLF and parsing header
    signal incrementParsingHeader <== readCRLF * isParsingHeader;
    // disable parsing header on reading CRLF-CRLF
    signal disableParsingHeader <== readCRLFCRLF * state[1];
    // parsing field value when parsing header and read Colon `:`
    signal readColonNotInFieldValue <== readColon * (1 - state[2]);
    signal isParsingFieldValue <== isParsingHeader * readColonNotInFieldValue;

    // parsing body when reading CRLF-CRLF and parsing header
    signal enableParsingBody <== readCRLFCRLF * isParsingHeader;

    // parsing_start       = out[0] = enable header (default 1) + increment start - disable start
    // parsing_header      = out[1] = enable header            + increment header  - disable header
    // parsing_field_name  = out[2] = enable header + increment header - parsing field value - parsing body
    // parsing_field_value = out[3] = parsing field value - increment parsing header (zeroed every time new header starts)
    // parsing_body        = out[4] = enable body
    out <== [
            incrementParsingStart - disableParsingStart, 
            enableParsingHeader + incrementParsingHeader - disableParsingHeader,
            enableParsingHeader + incrementParsingHeader - isParsingFieldValue - enableParsingBody,
            isParsingFieldValue - incrementParsingHeader,
            enableParsingBody
            ];
}