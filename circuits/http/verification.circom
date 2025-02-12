pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "machine.circom";
include "../utils/hash.circom";

template HTTPVerification(DATA_BYTES, MAX_NUMBER_OF_HEADERS, PUBLIC_IO_LENGTH) {
    signal input step_in[PUBLIC_IO_LENGTH];
    signal output step_out[PUBLIC_IO_LENGTH];

    // next_parsing_start, next_parsing_header, next_parsing_field_name, next_parsing_field_value, next_parsing_body, next_line_status, line_digest, main_monomial
    signal input machine_state[8];

    signal input ciphertext_digest;

    // step_in[2] = ciphertext_digest ** plaintext_ctr
    signal ciphertext_digest_pow[DATA_BYTES+1];
    ciphertext_digest_pow[0] <== step_in[2];
    signal mult_factor[DATA_BYTES];

    signal input data[DATA_BYTES];
    signal isPadding[DATA_BYTES]; // == 1 in the case we hit padding number
    signal zeroed_data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        isPadding[i]   <== IsEqual()([data[i], -1]);
        zeroed_data[i] <== (1 - isPadding[i]) * data[i];
        mult_factor[i] <== (1 - isPadding[i]) * ciphertext_digest + isPadding[i];
        ciphertext_digest_pow[i+1] <== ciphertext_digest_pow[i] * mult_factor[i];
    }
    signal pt_digest <== PolynomialDigestWithCounter(DATA_BYTES)(zeroed_data, ciphertext_digest, step_in[2]);
    // log("inner plaintext_digest: ", pt_digest);

    // Contains digests of start line and all intended headers (up to `MAX_NUMBER_OF_HEADERS`)
    signal input main_digests[MAX_NUMBER_OF_HEADERS + 1];
    signal not_contained[MAX_NUMBER_OF_HEADERS + 1];
    for(var i = 0 ; i < MAX_NUMBER_OF_HEADERS + 1 ; i++) {
        not_contained[i] <== IsZero()(main_digests[i]);
    }

    // assertions:
    // - check step_in[3] = machine state hash digest
    signal machine_state_digest <== PolynomialDigest(8)(machine_state, ciphertext_digest);
    step_in[3] === machine_state_digest;
    // - check step_in[4] = start line hash digest + all header hash digests
    // TODO: I don't like this `MAX_NUMBER_OF_HEADERS + 1` now. It should just be `NUMBER_OF_STATEMENTS_TO_LOCK` or something
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
    main_monomials[0] <== machine_state[7];

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
    signal line_digest[DATA_BYTES + 1];
    // Set this to what the previous digest was
    line_digest[0] <== machine_state[6];
    for(var i = 0 ; i < DATA_BYTES ; i++) {
        monomial_is_zero[i]    <== IsZero()(main_monomials[i]);
        accum_prev[i]          <== (1 - monomial_is_zero[i]) * line_digest[i];
        line_digest[i+1]       <== accum_prev[i] + data[i] * main_monomials[i];
        is_zero[i]             <== IsZero()(line_digest[i+1]);
        contains[i]            <== Contains(MAX_NUMBER_OF_HEADERS + 1)(line_digest[i+1], main_digests);
        is_match[i]            <== (1 - is_zero[i]) * contains[i];
        num_matched             += is_match[i];
    }

    // BODY
    // step_in[6] is the (ciphertext digest ** body_ctr)
    signal body_ctr_is_zero <== IsEqual()([step_in[6], 0]);
    signal initial_pow_accumulation <== step_in[6] * ciphertext_digest;
    signal pow_accumulation <== initial_pow_accumulation + body_ctr_is_zero * State[0].parsing_body; // pow_accumulation = 0 if we are not in the body

    // log("pow_accumulation: ", pow_accumulation);
    signal body_monomials_pow_accumulation[DATA_BYTES]; // power of monomials for the body
    signal body_monomials[DATA_BYTES]; // power of monomials for the body
    signal body_ctr[DATA_BYTES]; // body counter
    signal body_switch[DATA_BYTES -1]; // switch to add the previous monomial or not
    signal body_digest[DATA_BYTES]; // body digest
    body_monomials[0] <== pow_accumulation; // (ciphertext_digest ** body_ctr) * State.parsing_body (0 if we are not in the body)
    body_ctr[0]     <== body_ctr_is_zero * State[0].parsing_body + (1 - body_ctr_is_zero); // checks if we are in the body
    // log("body_ctr[0] = ", body_ctr[0]);
    // Set this to what the previous digest was
    body_digest[0]    <== body_monomials[0] * zeroed_data[0];
    for(var i = 0 ; i < DATA_BYTES - 1 ; i++) {
        // log("State[",i+1,"].parsing_body: ", State[i+1].parsing_body);
        body_ctr[i + 1]        <== body_ctr[i] + State[i + 1].parsing_body * (1 - isPadding[i + 1]);
        body_switch[i]           <== IsEqual()([body_ctr[i + 1], 1]); // check if we are in the body
        // log("body_switch[",i,"] = ", body_switch[i]);
        body_monomials_pow_accumulation[i] <== body_monomials[i] * ciphertext_digest + body_switch[i]; // add the previous monomial if we are in the body
        body_monomials[i + 1]    <== (body_monomials[i] - body_monomials_pow_accumulation[i]) * isPadding[i + 1] + body_monomials_pow_accumulation[i]; // do not update monomials if padding
        body_digest[i + 1]       <== body_digest[i] + body_monomials[i + 1] * zeroed_data[i + 1]; // add the monomial to the digest
        // log("body_digest[",i+1,"] = ", body_digest[i+1]);
    }

    // Note: This body digest computed here is just a diff since we added the other component before
    step_out[0] <== step_in[0] - pt_digest + body_digest[DATA_BYTES - 1];
    step_out[1] <== step_in[1];
    step_out[2] <== ciphertext_digest_pow[DATA_BYTES];
    // pass machine state to next iteration
    step_out[3] <== PolynomialDigest(8)(
        [State[DATA_BYTES - 1].next_parsing_start,
         State[DATA_BYTES - 1].next_parsing_header,
         State[DATA_BYTES - 1].next_parsing_field_name,
         State[DATA_BYTES - 1].next_parsing_field_value,
         State[DATA_BYTES - 1].next_parsing_body,
         State[DATA_BYTES - 1].next_line_status,
         line_digest[DATA_BYTES],
         main_monomials[DATA_BYTES - 1] * ciphertext_digest
        ],
        ciphertext_digest
    );
    step_out[4] <== step_in[4];
    step_out[5] <== step_in[5] - num_matched; // No longer check above, subtract here so circuits later check
    step_out[6] <== body_monomials[DATA_BYTES - 1];

    step_out[7] <== 1; // TODO: can i continue this counter?
    step_out[8] <== 0; // TODO: This is a hack to make the circuit work. We should remove this in the future
    for (var i = 9 ; i < PUBLIC_IO_LENGTH ; i++) {
        step_out[i] <== step_in[i];
    }

    // log("next_parsing_start: ", State[DATA_BYTES - 1].next_parsing_start);
    // log("next_parsing_header: ", State[DATA_BYTES - 1].next_parsing_header);
    // log("next_parsing_field_name: ", State[DATA_BYTES - 1].next_parsing_field_name);
    // log("next_parsing_field_value: ", State[DATA_BYTES - 1].next_parsing_field_value);
    // log("next_parsing_body: ", State[DATA_BYTES - 1].next_parsing_body);
    // log("next_line_status: ", State[DATA_BYTES - 1].next_line_status);
    // log("line_digest: ", line_digest[DATA_BYTES]);
    // log("main_monomial: ", main_monomials[DATA_BYTES - 1] * ciphertext_digest);
    // log("body_digest: ", body_digest[DATA_BYTES - 1]);

    // for (var i = 0 ; i < PUBLIC_IO_LENGTH ; i++) {
    //     log("step_out[",i,"] = ", step_out[i]);
    // }
    // log("xxxxx HTTP Verification Done xxxxx");
}
