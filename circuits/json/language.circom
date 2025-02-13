pragma circom 2.1.9;

template Syntax() {
    //-Delimeters---------------------------------------------------------------------------------//
    // - ASCII char: `{`
    signal output START_BRACE   <== 123;
    // - ASCII char: `}`
    signal output END_BRACE     <== 125;
    // - ASCII char `[`
    signal output START_BRACKET <== 91;
    // - ASCII char `]`
    signal output END_BRACKET   <== 93;
    // - ASCII char `"`
    signal output QUOTE         <== 34;
    // - ASCII char `:`
    signal output COLON         <== 58;
    // - ASCII char `,`
    signal output COMMA         <== 44;
    //-White_space--------------------------------------------------------------------------------//
    // - ASCII char: `\n`
    // signal output NEWLINE       <== 10;
    // - ASCII char: ` `
    // signal output SPACE         <== 32;
    //-Escape-------------------------------------------------------------------------------------//
    // - ASCII char: `\`
    signal output ESCAPE        <== 92;
    // - Primitive Trigers -----------------------------------------------------------------------//
    signal output ZERO <== 48;
    signal output ONE  <== 49;
    signal output TWO  <== 50;
    signal output THREE <== 51;
    signal output FOUR <== 52;
    signal output FIVE <== 53;
    signal output SIX  <== 54;
    signal output SEVEN <== 55;
    signal output EIGHT <== 56;
    signal output NINE  <== 57;
    // `null`, `true`, `false`
    signal output n     <== 110;
    signal output u     <== 117;
    signal output l     <== 108;
    signal output f     <== 102;
    signal output a     <== 97;
    signal output s     <== 115;
    signal output e     <== 101;
    signal output t     <== 116;
    signal output r     <== 114;
    // Scientific notation
    signal output PERIOD <== 46;
    signal output E      <== 69; // lol
    signal output PLUS   <== 43;
    signal output MINUS  <== 45;
    // - Numeric Range ---------------------------------------------------------------------------//
    signal output NUMBER_START <== 48;
    signal output NUMBER_END   <== 57;
}

template Command() {
    //            STATE              = [read_write_value, parsing_string, parsing_number, escape]
    signal output START_BRACE[3]   <== [1,                0,              0             ]; // Command returned by switch if we hit a start brace `{`
    signal output END_BRACE[3]     <== [-1,               0,              -1            ]; // Command returned by switch if we hit a end brace `}`
    signal output START_BRACKET[3] <== [2,                0,              0             ]; // Command returned by switch if we hit a start bracket `[`
    signal output END_BRACKET[3]   <== [-2,               0,              -1            ]; // Command returned by switch if we hit a start bracket `]`
    signal output QUOTE[3]         <== [0,                1,              0             ]; // Command returned by switch if we hit a quote `"`
    signal output COLON[3]         <== [3,                0,              0             ]; // Command returned by switch if we hit a colon `:`
    signal output COMMA[3]         <== [4,                0,              -1            ]; // Command returned by switch if we hit a comma `,`
    signal output NUMBER[3]        <== [256,              0,              1             ]; // Command returned by switch if we hit some decimal number (e.g., ASCII 48-57)
}