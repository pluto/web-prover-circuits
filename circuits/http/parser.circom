include "machine.circom";

template Parser(DATA_BYTES) {
    signal input data[DATA_BYTES];

    component State[DATA_BYTES];
    State[0]                     = HttpStateUpdate();
    State[0].byte                <== data[0];
    State[0].parsing_start       <== 1;
    State[0].parsing_header      <== 0;
    State[0].parsing_field_name  <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body        <== 0;
    State[0].line_status         <== 0;

        log("-------------------------------------------------");
        log("byte: ", data[0]);
        log("-------------------------------------------------");
        log("State[", 0, "].parsing_start       =", State[0].parsing_start);
        log("State[", 0, "].parsing_header      =", State[0].parsing_header);
        log("State[", 0, "].parsing_field_name  =", State[0].parsing_field_name);
        log("State[", 0, "].parsing_field_value =", State[0].parsing_field_value);
        log("State[", 0, "].parsing_body        =", State[0].parsing_body);
        log("State[", 0, "].line_status         =", State[0].line_status);
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                     = HttpStateUpdate();
        State[data_idx].byte                <== data[data_idx];
        State[data_idx].parsing_start       <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header      <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name  <== State[data_idx - 1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx - 1].next_parsing_field_value;
        State[data_idx].parsing_body        <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status         <== State[data_idx - 1].next_line_status;
        log("-------------------------------------------------");
        log("byte: ", data[data_idx]);
        log("-------------------------------------------------");
        log("State[", data_idx, "].parsing_start       =", State[data_idx].parsing_start);
        log("State[", data_idx, "].parsing_header      =", State[data_idx].parsing_header);
        log("State[", data_idx, "].parsing_field_name  =", State[data_idx].parsing_field_name);
        log("State[", data_idx, "].parsing_field_value =", State[data_idx].parsing_field_value);
        log("State[", data_idx, "].parsing_body        =", State[data_idx].parsing_body);
        log("State[", data_idx, "].line_status         =", State[data_idx].line_status);
        log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    // Verify machine ends in a valid state
    State[DATA_BYTES - 1].next_parsing_start       === 0;
    State[DATA_BYTES - 1].next_parsing_header      === 0;
    State[DATA_BYTES - 1].next_parsing_field_name  === 0;
    State[DATA_BYTES - 1].next_parsing_field_value === 0;
    State[DATA_BYTES - 1].next_parsing_body        === 1;
    State[DATA_BYTES - 1].next_line_status         === 0;

}