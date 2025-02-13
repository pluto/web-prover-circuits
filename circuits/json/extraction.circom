pragma circom 2.1.9;

include "../utils/bits.circom";
include "hash_machine.circom";

template JSONExtraction(DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH) {
    signal input data[DATA_BYTES];
    signal input ciphertext_digest;
    signal input sequence_digest; // todo(sambhav): should sequence digest be 0 for first json circuit?
    signal input value_digest;
    signal input state[MAX_STACK_HEIGHT * 4 + 4];

    signal input step_in[PUBLIC_IO_LENGTH];
    signal output step_out[PUBLIC_IO_LENGTH];

    //--------------------------------------------------------------------------------------------//

    // assertions:
    // step_in[5] === 0; // HTTP statements matched // TODO: either remove this or send a public io var
    signal input_state_digest <== PolynomialDigest(MAX_STACK_HEIGHT * 4 + 4)(state, ciphertext_digest);
    step_in[8] === input_state_digest;
    signal sequence_digest_hashed <== Poseidon(1)([sequence_digest]);
    step_in[9] === sequence_digest_hashed;


    component State[DATA_BYTES];

    // Set up monomials for stack/tree digesting
    signal monomials[3 * MAX_STACK_HEIGHT];
    monomials[0] <== 1;
    for(var i = 1 ; i < 3 * MAX_STACK_HEIGHT ; i++) {
        monomials[i] <== monomials[i - 1] * ciphertext_digest;
    }
    signal intermediate_digest[DATA_BYTES][3 * MAX_STACK_HEIGHT];
    signal state_digest[DATA_BYTES];

    var total_matches = 0;
    signal sequence_is_matched[DATA_BYTES];
    signal value_is_matched[DATA_BYTES];
    signal sequence_and_value_matched[DATA_BYTES];
    for(var data_idx = 0; data_idx < DATA_BYTES; data_idx++) {
        if(data_idx == 0) {
            State[0] = StateUpdateHasher(MAX_STACK_HEIGHT);
            for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
                State[0].stack[i]     <== [state[i*2],state[i*2+1]];
                State[0].tree_hash[i] <== [state[MAX_STACK_HEIGHT*2 + i*2],state[MAX_STACK_HEIGHT*2 + i*2 + 1]];
            }
            State[0].byte             <== data[0];
            State[0].polynomial_input <== ciphertext_digest;
            State[0].monomial         <== state[MAX_STACK_HEIGHT*4];
            State[0].parsing_string   <== state[MAX_STACK_HEIGHT*4 + 1];
            State[0].parsing_primitive   <== state[MAX_STACK_HEIGHT*4 + 2];
            State[0].escaped          <== state[MAX_STACK_HEIGHT*4 + 3];
        } else {
            State[data_idx]                    = StateUpdateHasher(MAX_STACK_HEIGHT);
            State[data_idx].byte             <== data[data_idx];
            State[data_idx].polynomial_input <== ciphertext_digest;
            State[data_idx].stack            <== State[data_idx - 1].next_stack;
            State[data_idx].tree_hash        <== State[data_idx - 1].next_tree_hash;
            State[data_idx].monomial         <== State[data_idx - 1].next_monomial;
            State[data_idx].parsing_string   <== State[data_idx - 1].next_parsing_string;
            State[data_idx].parsing_primitive   <== State[data_idx - 1].next_parsing_primitive;
            State[data_idx].escaped          <== State[data_idx - 1].next_escaped;
        }

        // Digest the whole stack and key tree hash
        var accumulator = 0;
        for(var i = 0 ; i < MAX_STACK_HEIGHT ; i++) {
            intermediate_digest[data_idx][3 * i]     <== State[data_idx].next_stack[i][0] * monomials[3 * i];
            intermediate_digest[data_idx][3 * i + 1] <== State[data_idx].next_stack[i][1] * monomials[3 * i + 1];
            intermediate_digest[data_idx][3 * i + 2] <== State[data_idx].next_tree_hash[i][0] * monomials[3 * i + 2];
            accumulator += intermediate_digest[data_idx][3 * i] + intermediate_digest[data_idx][3 * i + 1] + intermediate_digest[data_idx][3 * i + 2];
        }
        state_digest[data_idx] <== accumulator;
        sequence_is_matched[data_idx] <== IsEqual()([state_digest[data_idx], sequence_digest]);

        // Now check for if the value digest appears
        var value_digest_in_stack = 0;
        for(var i = 0 ; i < MAX_STACK_HEIGHT ; i++) {
            // A single value can be present only, and it is on index 1, so we can just accum
            value_digest_in_stack += State[data_idx].next_tree_hash[i][1];
        }
        value_is_matched[data_idx] <== IsEqual()([value_digest, value_digest_in_stack]);
        sequence_and_value_matched[data_idx] <== sequence_is_matched[data_idx] * value_is_matched[data_idx];
        total_matches += sequence_and_value_matched[data_idx];

        // Debugging
        // log("State[", data_idx, "].byte               =", State[data_idx].byte);
        // for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
        //     log("State[", data_idx, "].next_stack[", i,"]     = [",State[data_idx].next_stack[i][0], "][", State[data_idx].next_stack[i][1],"]" );
        // }
        // for(var i = 0; i<MAX_STACK_HEIGHT; i++) {
        //     log("State[", data_idx, "].next_tree_hash[", i,"] = [",State[data_idx].next_tree_hash[i][0], "][", State[data_idx].next_tree_hash[i][1],"]" );
        // }
        // log("State[", data_idx, "].next_monomial       =", State[data_idx].next_monomial);
        // log("State[", data_idx, "].next_parsing_string =", State[data_idx].next_parsing_string);
        // log("State[", data_idx, "].next_parsing_primitive =", State[data_idx].next_parsing_primitive);
        // log("State[", data_idx, "].next_escaped        =", State[data_idx].next_escaped);
        // log("++++++++++++++++++++++++++++++++++++++++++++++++");
        // log("state_digest[", data_idx,"]              = ", state_digest[data_idx]);
        // log("total_matches                   = ", total_matches);
        // log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    signal new_state[MAX_STACK_HEIGHT*4 + 4];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        new_state[i*2] <== State[DATA_BYTES - 1].next_stack[i][0];
        new_state[i*2+1] <== State[DATA_BYTES - 1].next_stack[i][1];
        new_state[MAX_STACK_HEIGHT*2 + i*2] <== State[DATA_BYTES - 1].next_tree_hash[i][0];
        new_state[MAX_STACK_HEIGHT*2 + i*2 + 1] <== State[DATA_BYTES - 1].next_tree_hash[i][1];
    }
    new_state[MAX_STACK_HEIGHT*4]     <== State[DATA_BYTES - 1].next_monomial;
    new_state[MAX_STACK_HEIGHT*4 + 1] <== State[DATA_BYTES - 1].next_parsing_string;
    new_state[MAX_STACK_HEIGHT*4 + 2] <== State[DATA_BYTES - 1].next_parsing_primitive;
    new_state[MAX_STACK_HEIGHT*4 + 3] <== State[DATA_BYTES - 1].next_escaped;
    signal new_state_digest <== PolynomialDigest(MAX_STACK_HEIGHT * 4 + 4)(new_state, ciphertext_digest);

    // for (var i = 0 ; i < MAX_STACK_HEIGHT * 2 + 2 ; i++) {
    //     log("new_state[", i, "] = ", new_state[i*2], new_state[i*2 + 1]);
    // }

    // Verify we have now processed all the data properly
    signal ciphertext_digest_pow[DATA_BYTES+1]; // ciphertext_digest ** i (Accumulates the polynomial_input)
    signal mult_factor[DATA_BYTES]; // 1 if we padding, ciphertext_digest if we are not
    ciphertext_digest_pow[0] <== step_in[7]; // ciphertext_digest ** previous_data_bytes
    signal isPadding[DATA_BYTES]; // == 1 in the case we hit padding number
    signal zeroed_data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        isPadding[i]   <== IsEqual()([data[i], -1]);
        zeroed_data[i] <== (1 - isPadding[i]) * data[i];
        mult_factor[i] <== (1 - isPadding[i]) * ciphertext_digest + isPadding[i];
        ciphertext_digest_pow[i+1] <== ciphertext_digest_pow[i] * mult_factor[i];
    }

    signal data_digest <== PolynomialDigestWithCounter(DATA_BYTES)(zeroed_data, ciphertext_digest, step_in[7]);

    // Set the output to the digest of the intended value
    step_out[0] <== step_in[0] - data_digest + value_digest * total_matches;

    // value_digest should be non-zero
    signal is_value_digest_zero <== IsEqual()([value_digest, 0]);
    // both should be 0 or 1 together
    signal is_new_state_digest_zero <== IsEqual()([new_state_digest, 0]);
    signal is_step_out_zero_matched <== IsEqual()([step_out[0], value_digest]);
    0 === (1 - is_value_digest_zero) * (is_new_state_digest_zero - is_step_out_zero_matched); // verify final value matches

    step_out[1] <== step_in[1];
    step_out[2] <== step_in[2];
    step_out[3] <== step_in[3];
    step_out[4] <== step_in[4];
    step_out[5] <== step_in[5];
    step_out[6] <== step_in[6];
    step_out[7] <== ciphertext_digest_pow[DATA_BYTES];
    step_out[8] <== new_state_digest;
    step_out[9] <== step_in[9];
    step_out[10] <== step_in[10];

    step_out[1] === step_out[2]; // assert http and plaintext parsed same amount

    // for (var i = 0 ; i < PUBLIC_IO_LENGTH ; i++) {
    //     log("step_out[", i, "] = ", step_out[i]);
    // }
    // log("xxxxxx JSON Extraction Done xxxxxx");
}
