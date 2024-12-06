pragma circom 2.1.9;

include "machine.circom";
include "../utils/hash.circom";

template HTTPVerification(DATA_BYTES, MAX_NUMBER_OF_HEADERS) {
    signal input step_in[1];
    signal output step_out[1];

    // Authenticate the plaintext we are passing in
    signal input data[DATA_BYTES];
    signal data_hash <== DataHasher(DATA_BYTES)(data);
    data_hash        === step_in[0];

    // signal input header_digests[MAX_NUMBER_OF_HEADERS]; // We could take this in as a field element and map it to bits for more efficiency
    signal input which_headers[MAX_NUMBER_OF_HEADERS];
    signal input headers_digest; // sum/product? of the header digests (a uniform random variable)
    signal input start_line_digest; // Could probably combine with headers
    signal input body_digest;

    // TODO: could just have a parser template and reduce code here
    component State[DATA_BYTES];
    State[0]                     = HttpStateUpdate();
    State[0].byte                <== data[0];
    State[0].parsing_start       <== 1;
    State[0].parsing_header      <== 0;
    State[0].parsing_field_name  <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body        <== 0;
    State[0].line_status         <== 0;

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

    // // Get the start line shit
    // signal start_line[DATA_BYTES];
    // signal not_start_line_mask[DATA_BYTES];
    // for(var i = 0 ; i < DATA_BYTES ; i++) {
    //     not_start_line_mask[i] <== IsZero()(State[i].parsing_start);
    //     start_line[i]          <== data[i] * (1 - not_start_line_mask[i]);
    // }
    // signal inner_start_line_hash       <== DataHasher(DATA_BYTES)(start_line);
    // signal start_line_hash_equal_check <== IsEqual()([inner_start_line_hash, start_line_hash]);
    // start_line_hash_equal_check        === 1;

    // Mask leaving only selected headers and start line
    for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS ; i++) {
        0 === which_headers[i] * (1 - which_headers[i]); // Assert this is a bit
    }
    signal headers_mask[DATA_BYTES];
    signal include_header[DATA_BYTES];
    signal not_parsing_start[DATA_BYTES];
    signal monomials[DATA_BYTES];
    monomials[0] <== 1;

    signal start_line_mask[DATA_BYTES];
    signal inner_start_line_digest[DATA_BYTES + 1];
    inner_start_line_digest[0] <== 0;
    signal inner_headers_digest[DATA_BYTES + 1];
    inner_headers_digest[0] <== 0;
    signal is_line_change[DATA_BYTES];
    signal was_cleared[DATA_BYTES];
    
    for(var i = 0 ; i < DATA_BYTES - 1 ; i++) {
        log("------------------------------------------------------------------");
        is_line_change[i] <== Contains(2)(data[i + 1], [10, 13]);
        // TODO: use `step_in[0]` in the future, testing with `2` now
        was_cleared[i] <== IsZero()(monomials[i]);
        monomials[i + 1] <==  (1 - is_line_change[i]) * (monomials[i] * 2 + was_cleared[i]);
        log("monomials[", i, "]           =", monomials[i]);

    }
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        not_parsing_start[i] <== IsZero()(State[i].parsing_start);
        start_line_mask[i] <==  (1 - not_parsing_start[i]) * data[i];
        inner_start_line_digest[i + 1] <== inner_start_line_digest[i] + start_line_mask[i] * monomials[i];
        // ^^^ last will be the poly sum                  ^^^ prev term in poly
        log("State[", i, "].parsing_start =", State[i].parsing_start);


        include_header[i] <== IndexSelector(MAX_NUMBER_OF_HEADERS)(which_headers, State[i].parsing_header - 1);
        
        // log("include_header[", i,"]      =", include_header[i]);
        
        headers_mask[i] <== data[i] * include_header[i];
        // log("headers_mask[", i,"]           =", headers_mask[i]);

    }
    log("inner_start_line_digest = ", inner_start_line_digest[DATA_BYTES]);
    inner_start_line_digest[DATA_BYTES] === start_line_digest;

    // signal inner_http_digest <== DataHasher(DATA_BYTES)(http_mask);
    // inner_http_digest === http_digest;
    // signal inner_header_hashes[MAX_NUMBER_OF_HEADERS];
    // signal header_is_unused[MAX_NUMBER_OF_HEADERS]; // If a header hash is passed in as 0, it is not used (no way to compute preimage of 0) 
    // signal header_hashes_equal_check[MAX_NUMBER_OF_HEADERS];
    // for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS ; i++) {
    //     header_is_unused[i]          <== IsZero()(header_hashes[i]);
    //     inner_header_hashes[i]       <== DataHasher(DATA_BYTES)(header[i]);
    //     header_hashes_equal_check[i] <== IsEqual()([(1 - header_is_unused[i]) * inner_header_hashes[i], header_hashes[i]]);
    //     header_hashes_equal_check[i] === 1;
    // }

    // TODO: Just hash all the bytes once? Also could pass in a body hash and all the header hashes we want and just assert that they get hit like we would with JSON. Then we don't have to hash the body and headers separately and can still output body hash
    // we could go through, accumulate a hash, then clear when we change to a new thing. Then just assert that hash is in a list of header/body hashes.

    // Get the body shit
    // signal body[DATA_BYTES];
    // for(var i = 0 ; i < DATA_BYTES ; i++) {
    //     body[i] <== data[i] * State[i].parsing_body;
    // }
    // signal inner_body_digest       <== MaskedByteStreamDigest(DATA_BYTES)(body);
    // signal body_digest_equal_check <== IsEqual()([inner_body_digest, body_digest]);
    // body_digest_equal_check        === 1;

    // step_out[0] <== inner_body_digest;

    // Verify machine ends in a valid state
    State[DATA_BYTES - 1].next_parsing_start       === 0;
    State[DATA_BYTES - 1].next_parsing_header      === 0;
    State[DATA_BYTES - 1].next_parsing_field_name  === 0;
    State[DATA_BYTES - 1].next_parsing_field_value === 0;
    State[DATA_BYTES - 1].next_parsing_body        === 1;
    State[DATA_BYTES - 1].next_line_status         === 0;
}
