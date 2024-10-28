pragma circom 2.1.9;

// All the possible request methods: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods

template HttpSyntax() {
    //-Delimeters---------------------------------------------------------------------------------//
    // - ASCII char `:`
    signal output COLON     <== 58;
    // - ASCII char `;`
    signal output SEMICOLON <== 59;
    // - ASCII char `,`
    signal output COMMA     <== 44;
    // - ASCII char `"`
    signal output QUOTE     <== 34;
    //-White_space--------------------------------------------------------------------------------//
    // https://www.rfc-editor.org/rfc/rfc2616#section-2.2
    // https://www.rfc-editor.org/rfc/rfc7230#section-3.5
    // - ASCII char `\r` (carriage return)
    signal output CR        <== 13;
    // - ASCII char `\n` (line feed)
    signal output LF        <== 10;
    // - ASCII char: ` `
    signal output SPACE     <== 32;
    //-Escape-------------------------------------------------------------------------------------//
    // - ASCII char: `\`
    signal output ESCAPE    <== 92;
}