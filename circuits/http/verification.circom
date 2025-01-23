pragma circom 2.1.9;

include "machine.circom";
include "../utils/hash.circom";

// TODO:
// - add `if body { PD(b[p]) }` to step_ou[0]
template HTTPVerification(DATA_BYTES, MAX_NUMBER_OF_HEADERS, PUBLIC_IO_LENGTH) {
    signal input step_in[PUBLIC_IO_LENGTH];
    signal output step_out[PUBLIC_IO_LENGTH];

    // next_parsing_start, next_parsing_header, next_parsing_field_name, next_parsing_field_value, next_parsing_body, next_line_status
    signal input machine_state[6];

    signal input ciphertext_digest;

    // step_in[2] is the combined length of the data
    var data_length = step_in[2];

    signal input data[DATA_BYTES];
    signal isPadding[DATA_BYTES]; // == 1 in the case we hit padding number
    signal zeroed_data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
      isPadding[i]   <== IsEqual()([data[i], -1]);
      zeroed_data[i] <== (1 - isPadding[i]) * data[i];
      data_length   += 1 - isPadding[i];
    }
    signal pt_digest <== PolynomialDigestWithCounter(DATA_BYTES)(zeroed_data, ciphertext_digest, data_length);

    // Contains digests of start line and all intended headers (up to `MAX_NUMBER_OF_HEADERS`)
    signal input main_digests[MAX_NUMBER_OF_HEADERS + 1];
    signal not_contained[MAX_NUMBER_OF_HEADERS + 1];
    var num_to_match = MAX_NUMBER_OF_HEADERS + 1;
    for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS + 1 ; i++) {
        not_contained[i] <== IsZero()(main_digests[i]);
        num_to_match -= not_contained[i];
    }


    // assertions:
    // - check step_in[3] = machine state hash digest
    signal machine_state_digest <== PolynomialDigest(6)(machine_state, ciphertext_digest);
    step_in[3] === machine_state_digest;
    // - check step_in[4] = start line hash digest + all header hash digests
    signal option_hash[MAX_NUMBER_OF_HEADERS + 1];
    signal main_digests_hashed[MAX_NUMBER_OF_HEADERS + 1];
    var accumulated_main_digests_hashed = 0;
    for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS + 1 ; i++) {
        option_hash[i] <== Poseidon(1)([main_digests[i]]);
        main_digests_hashed[i] <== (1 - not_contained[i]) * option_hash[i];
        accumulated_main_digests_hashed +=  main_digests_hashed[i];
    }
    step_in[4] === accumulated_main_digests_hashed;

    // populate the state machine with the previous state
    component State[DATA_BYTES];
    State[0]                     = HttpStateUpdate();
    State[0].byte                <== data[0];
    State[0].parsing_start       <== machine_state[0];
    State[0].parsing_header      <== machine_state[1];
    State[0].parsing_field_name  <== machine_state[2];
    State[0].parsing_field_value <== machine_state[3];
    State[0].parsing_body        <== machine_state[4];
    State[0].line_status         <== machine_state[5];
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


    signal main_monomials[DATA_BYTES];
    main_monomials[0] <== 1;

    signal is_line_change[DATA_BYTES-1];
    signal was_cleared[DATA_BYTES-1];
    signal not_body_and_not_line_change[DATA_BYTES-1];

    signal rescaled_or_was_cleared[DATA_BYTES-1];
    for(var i = 0 ; i < DATA_BYTES - 1 ; i++) {
        is_line_change[i]               <== Contains(2)(data[i + 1], [10, 13]); // capture if we hit an end line sequence
        was_cleared[i]                  <== IsZero()(main_monomials[i]);
        not_body_and_not_line_change[i] <== (1 - State[i + 1].parsing_body) * (1 - is_line_change[i]);
        rescaled_or_was_cleared[i]      <== (main_monomials[i] * ciphertext_digest + was_cleared[i]);
        main_monomials[i + 1]           <==  not_body_and_not_line_change[i] * rescaled_or_was_cleared[i];
    }

    signal is_match[DATA_BYTES];
    signal contains[DATA_BYTES];
    signal is_zero[DATA_BYTES];
    signal monomial_is_zero[DATA_BYTES];
    signal accum_prev[DATA_BYTES];
    var num_matched = 0;
    signal inner_main_digest[DATA_BYTES + 1];
    inner_main_digest[0] <== 0;
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        monomial_is_zero[i]    <== IsZero()(main_monomials[i]);
        accum_prev[i]          <== (1 - monomial_is_zero[i]) * inner_main_digest[i];
        inner_main_digest[i+1] <== accum_prev[i] + data[i] * main_monomials[i];
        is_zero[i]             <== IsZero()(inner_main_digest[i+1]);
        contains[i]            <== Contains(MAX_NUMBER_OF_HEADERS + 1)(inner_main_digest[i+1], main_digests);
        is_match[i]            <== (1 - is_zero[i]) * contains[i];
        num_matched             += is_match[i];
    }
    num_matched === num_to_match;

    // BODY
    signal body_monomials[DATA_BYTES];
    signal body_accum[DATA_BYTES];
    signal body_switch[DATA_BYTES -1];
    signal body_digest[DATA_BYTES];
    body_monomials[0] <== 0;
    body_accum[0]     <== 0;
    body_digest[0]    <== 0;
    for(var i = 0 ; i < DATA_BYTES - 1 ; i++) {
        body_accum[i + 1]        <== body_accum[i] + State[i + 1].parsing_body;
        body_switch[i]           <== IsEqual()([body_accum[i + 1], 1]);
        body_monomials[i + 1]    <== body_monomials[i] * ciphertext_digest + body_switch[i];
        body_digest[i + 1]       <== body_digest[i] + body_monomials[i + 1] * zeroed_data[i + 1];
    }



    // subtract all the header digests here and also wrap them in poseidon.
    signal body_digest_hashed <== Poseidon(1)([body_digest[DATA_BYTES - 1]]);

    // TODO: removed body_digest_hashed from step_out[0], add PD(b[p]) if body
    step_out[0] <== step_in[0] - pt_digest;
    step_out[1] <== step_in[1];
    step_out[2] <== data_length;
    // pass machine state to next iteration
    step_out[3] <== PolynomialDigest(6)([State[DATA_BYTES - 1].next_parsing_start, State[DATA_BYTES - 1].next_parsing_header, State[DATA_BYTES - 1].next_parsing_field_name, State[DATA_BYTES - 1].next_parsing_field_value, State[DATA_BYTES - 1].next_parsing_body, State[DATA_BYTES - 1].next_line_status], ciphertext_digest);
    step_out[4] <== step_in[4];
    step_out[5] <== step_in[5] - num_matched;
    for (var i = 6 ; i < PUBLIC_IO_LENGTH ; i++) {
        step_out[i] <== step_in[i];
    }
}
