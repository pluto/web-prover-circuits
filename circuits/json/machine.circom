/*
# `machine`
This module consists of the core parsing components for generating proofs of selective disclosure in JSON.

## Layout
The key ingredients of `parser` are:
 - `StateUpdate`: has as input a current state of a stack-machine parser.
    Also takes in a `byte` as input which combines with the current state
    to produce the `next_*` states.
 - `StateToMask`: Reads the current state to decide whether accept instruction tokens
    or ignore them for the current task (e.g., ignore `[` if `parsing_string == 1`).
 - `GetTopOfStack`: Helper function that yields the topmost allocated stack value
    and a pointer (index) to that value.
 - `RewriteStack`: Combines all the above data and produces the `next_stack`.

`parser` brings in many functions from the `utils` module and `language`.
The inclusion of `langauge` allows for this file to (eventually) be generic over
a grammar for different applications (e.g., HTTP, YAML, TOML, etc.).

## Testing
Tests for this module are located in the files: `circuits/test/parser/*.test.ts
*/

pragma circom 2.1.9;

include "../utils/array.circom";
include "../utils/operators.circom";
include "language.circom";

/*
This template is for updating the state of the parser from a current state to a next state.

# Params:
 - `MAX_STACK_HEIGHT`: the maximum stack height that can be used before triggering overflow.

# Inputs:
 - `byte`                      : the byte value of ASCII that was read by the parser.
 - `stack[MAX_STACK_HEIGHT][2]`: the stack machine's current stack.
 - `parsing_number`            : a bool flag that indicates whether the parser is currently parsing a string or not.
 - `parsing_number`            : a bool flag that indicates whether the parser is currently parsing a number or not.

# Outputs:
 - `next_stack[MAX_STACK_HEIGHT][2]`: the stack machine's stack after reading `byte`.
 - `next_parsing_number`            : a bool flag that indicates whether the parser is currently parsing a string or not after reading `byte`.
 - `next_parsing_number`            : a bool flag that indicates whether the parser is currently parsing a number or not after reading `byte`.
*/
template StateUpdate(MAX_STACK_HEIGHT) {
    signal input byte; // TODO: Does this need to be constrained within here?

    signal input stack[MAX_STACK_HEIGHT][2];
    signal input parsing_string;
    signal input parsing_number;

    signal output next_stack[MAX_STACK_HEIGHT][2];
    signal output next_parsing_string;
    signal output next_parsing_number;

    component Command = Command();
    component Syntax  = Syntax();

    //--------------------------------------------------------------------------------------------//
    // Break down what was read
    // * read in a start brace `{` *
    component readStartBrace   = IsEqual();
    readStartBrace.in        <== [byte, Syntax.START_BRACE];
    // * read in an end brace `}` *
    component readEndBrace     = IsEqual();
    readEndBrace.in          <== [byte, Syntax.END_BRACE];
    // * read in a start bracket `[` *
    component readStartBracket = IsEqual();
    readStartBracket.in      <== [byte, Syntax.START_BRACKET];
    // * read in an end bracket `]` *
    component readEndBracket   = IsEqual();
    readEndBracket.in        <== [byte, Syntax.END_BRACKET];
    // * read in a colon `:` *
    component readColon        = IsEqual();
    readColon.in             <== [byte, Syntax.COLON];
    // * read in a comma `,` *
    component readComma        = IsEqual();
    readComma.in             <== [byte, Syntax.COMMA];
    // * read in some delimeter *
    signal readDelimeter     <== readStartBrace.out + readEndBrace.out + readStartBracket.out + readEndBracket.out
                               + readColon.out + readComma.out;
    // * read in some number *
    component readNumber       = InRange(8);
    readNumber.in            <== byte;
    readNumber.range         <== [Syntax.NUMBER_START, Syntax.NUMBER_END]; // This is the range where ASCII digits are
    // * read in a quote `"` *
    component readQuote        = IsEqual();
    readQuote.in             <== [byte, Syntax.QUOTE];
    component readOther        = IsZero();
    readOther.in             <== readDelimeter + readNumber.out + readQuote.out;
    //--------------------------------------------------------------------------------------------//
    // Yield instruction based on what byte we read *
    component readStartBraceInstruction   = ScalarArrayMul(3);
    readStartBraceInstruction.scalar    <== readStartBrace.out;
    readStartBraceInstruction.array     <== Command.START_BRACE;
    component readEndBraceInstruction     = ScalarArrayMul(3);
    readEndBraceInstruction.scalar      <== readEndBrace.out;
    readEndBraceInstruction.array       <== Command.END_BRACE;
    component readStartBracketInstruction = ScalarArrayMul(3);
    readStartBracketInstruction.scalar  <== readStartBracket.out;
    readStartBracketInstruction.array   <== Command.START_BRACKET;
    component readEndBracketInstruction   = ScalarArrayMul(3);
    readEndBracketInstruction.scalar    <== readEndBracket.out;
    readEndBracketInstruction.array     <== Command.END_BRACKET;
    component readColonInstruction        = ScalarArrayMul(3);
    readColonInstruction.scalar         <== readColon.out;
    readColonInstruction.array          <== Command.COLON;
    component readCommaInstruction        = ScalarArrayMul(3);
    readCommaInstruction.scalar         <== readComma.out;
    readCommaInstruction.array          <== Command.COMMA;
    component readNumberInstruction       = ScalarArrayMul(3);
    readNumberInstruction.scalar        <== readNumber.out;
    readNumberInstruction.array         <== Command.NUMBER;
    component readQuoteInstruction        = ScalarArrayMul(3);
    readQuoteInstruction.scalar         <== readQuote.out;
    readQuoteInstruction.array          <== Command.QUOTE;

    component Instruction                 = GenericArrayAdd(3,8);
    Instruction.arrays                  <== [readStartBraceInstruction.out, readEndBraceInstruction.out,
                                             readStartBracketInstruction.out, readEndBracketInstruction.out,
                                             readColonInstruction.out, readCommaInstruction.out,
                                             readNumberInstruction.out, readQuoteInstruction.out];
    //--------------------------------------------------------------------------------------------//
    // Apply state changing data
    // * get the instruction mask based on current state *
    component mask              = StateToMask(MAX_STACK_HEIGHT);
    mask.readDelimeter        <== readDelimeter;
    mask.readNumber           <== readNumber.out;
    mask.parsing_string       <== parsing_string;
    mask.parsing_number       <== parsing_number;
    // * multiply the mask array elementwise with the instruction array *
    component mulMaskAndOut    = ArrayMul(3);
    mulMaskAndOut.lhs        <== mask.out;
    mulMaskAndOut.rhs        <== [Instruction.out[0], Instruction.out[1], Instruction.out[2]  - readOther.out];
    // * compute the new stack *
    component newStack         = RewriteStack(MAX_STACK_HEIGHT);
    newStack.stack            <== stack;
    newStack.read_write_value <== mulMaskAndOut.out[0];
    newStack.readStartBrace   <== readStartBrace.out;
    newStack.readStartBracket <== readStartBracket.out;
    newStack.readEndBrace     <== readEndBrace.out;
    newStack.readEndBracket   <== readEndBracket.out;
    newStack.readColon        <== readColon.out;
    newStack.readComma        <== readComma.out;
    // * set all the next state of the parser *
    next_stack                <== newStack.next_stack;
    next_parsing_string       <== parsing_string + mulMaskAndOut.out[1];
    next_parsing_number       <== parsing_number + mulMaskAndOut.out[2];
    //--------------------------------------------------------------------------------------------//
}

/*
This template is for updating the state of the parser from a current state to a next state.

# Params:
 - `n`: tunable parameter for the number of `parsing_states` needed (TODO: could be removed).

# Inputs:
 - `readDelimeter` : a bool flag that indicates whether the byte value read was a delimeter.
 - `readNumber`    : a bool flag that indicates whether the byte value read was a number.
 - `parsing_number`: a bool flag that indicates whether the parser is currently parsing a string or not.
 - `parsing_number`: a bool flag that indicates whether the parser is currently parsing a number or not.

# Outputs:
 - `out[3]`: an array of values fed to update the stack and the parsing state flags.
    - 0: mask for `read_write_value`
    - 1: mask for `parsing_string`
    - 2: mask for `parsing_number`
*/
template StateToMask(n) {
    // TODO: Probably need to assert things are bits where necessary.
    signal input readDelimeter;
    signal input readNumber;
    signal input parsing_string;
    signal input parsing_number;
    signal output out[3];


    // `read_write_value`can change: IF NOT `parsing_string`
    out[0] <== (1 - parsing_string);

    // `parsing_string` can change:
    out[1] <== 1 - 2 * parsing_string;


    //--------------------------------------------------------------------------------------------//
    // `parsing_number` is more complicated to deal with
    /* We have the possible relevant states below:
    [isParsingString, isParsingNumber, readNumber, readDelimeter];
             1                2             4             8
    Above is the binary value for each if is individually enabled
    This is a total of 2^4 states
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1,  0,  0,  0,  0,   0];
    and the above is what we want to set `next_parsing_number` to given those
    possible.
    Below is an optimized version that could instead be done with a `Switch`
    */
    signal parsingNumberReadDelimeter <== parsing_number * (readDelimeter);
    signal readNumberNotParsingNumber <== (1 - parsing_number) * readNumber;
    signal notParsingStringAndParsingNumberReadDelimeterOrReadNumberNotParsingNumber <== (1 - parsing_string) * (parsingNumberReadDelimeter + readNumberNotParsingNumber);
    //                                                                                                           10 above ^^^^^^^^^^^^^^^^^   4 above ^^^^^^^^^^^^^^^^^^
    signal parsingNumberNotReadNumber <== parsing_number * (1 - readNumber) ;
    signal parsingNumberNotReadNumberNotReadDelimeter <== parsingNumberNotReadNumber * (1-readDelimeter);
    out[2] <== notParsingStringAndParsingNumberReadDelimeterOrReadNumberNotParsingNumber + parsingNumberNotReadNumberNotReadDelimeter;
    // Sorry about the long names, but they hopefully read clearly!
}

// TODO: Check if underconstrained
/*
This template is for getting the values at the top of the stack as well as the pointer to the top.

# Params:
 - `n`: tunable parameter for the stack height.

# Inputs:
 - `stack[n][2]` : the stack to get the values and pointer of.

# Outputs:
 - `value[2]`: the value at the top of the stack
 - `pointer` : the pointer for the top of stack index
*/
template GetTopOfStack(n) {
    signal input stack[n][2];
    signal output value[2];
    signal output pointer;

    component isUnallocated[n];
    component atTop = SwitchArray(n,2);
    var selector = 0;
    for(var i = 0; i < n; i++) {
        isUnallocated[i]         = IsEqualArray(2);
        isUnallocated[i].in[0] <== [0,0];
        isUnallocated[i].in[1] <== stack[i];
        selector += (1 - isUnallocated[i].out);
        atTop.branches[i] <== i + 1;
        atTop.vals[i]     <== stack[i];
    }
    atTop.case <== selector;
    _ <== atTop.match;
    value      <== atTop.out;
    pointer    <== selector;
}

// TODO: IMPORTANT NOTE, THE STACK IS CONSTRAINED TO 2**8 so the InRange work (could be changed)
/*
This template is for updating the stack given the current stack and the byte we read in `StateUpdate`.

# Params:
 - `n`: tunable parameter for the number of bits needed to represent the `MAX_STACK_HEIGHT`.

# Inputs:
 - `read_write_value` : what value should be pushed to or popped from the stack.
 - `readStartBrace`   : a bool flag that indicates whether the byte value read was a start brace `{`.
 - `readEndBrace`     : a bool flag that indicates whether the byte value read was a end brace `}`.
 - `readStartBracket` : a bool flag that indicates whether the byte value read was a start bracket `[`.
 - `readEndBracket`   : a bool flag that indicates whether the byte value read was a end bracket `]`.
 - `readColon`        : a bool flag that indicates whether the byte value read was a colon `:`.
 - `readComma`        : a bool flag that indicates whether the byte value read was a comma `,`.

# Outputs:
 - `next_stack[n][2]`: the next stack of the parser.
*/
template RewriteStack(n) {
    assert(n < 2**8);
    signal input stack[n][2];
    signal input read_write_value;
    signal input readStartBrace;
    signal input readStartBracket;
    signal input readEndBrace;
    signal input readEndBracket;
    signal input readColon;
    signal input readComma;

    signal output next_stack[n][2];

    //--------------------------------------------------------------------------------------------//
    // * scan value on top of stack *
    component topOfStack      = GetTopOfStack(n);
    topOfStack.stack        <== stack;
    signal pointer          <== topOfStack.pointer;
    signal current_value[2] <== topOfStack.value;
    // * check if we are currently in a value of an object *
    // * check if value indicates currently in an array *
    component inArray         = IsEqual();
    inArray.in[0]           <== current_value[0];
    inArray.in[1]           <== 2;
    //--------------------------------------------------------------------------------------------//

    //--------------------------------------------------------------------------------------------//
    // * composite signals *
    signal readCommaInArray    <== readComma * inArray.out;
    signal readCommaNotInArray <== readComma * (1 - inArray.out);
    //--------------------------------------------------------------------------------------------//

    //--------------------------------------------------------------------------------------------//
    // * determine whether we are pushing or popping from the stack *
    component isPush       = IsEqual();
    isPush.in            <== [readStartBrace + readStartBracket, 1];
    component isPop        = IsEqual();
    isPop.in             <== [readEndBrace + readEndBracket, 1];
    // * set an indicator array for where we are pushing to or popping from*
    component indicator[n];
    for(var i = 0; i < n; i++) {
        // Points
        indicator[i]       = IsZero();
        indicator[i].in  <== pointer - isPop.out - readColon - readComma - i; // Note, pointer points to unallocated region!
    }
    //--------------------------------------------------------------------------------------------//

    //--------------------------------------------------------------------------------------------//
    // * loop to modify the stack by rebuilding it *
    signal stack_change_value[2] <== [(isPush.out + isPop.out) * read_write_value, readColon + readCommaInArray - readCommaNotInArray];
    signal second_index_clear[n];
    for(var i = 0; i < n; i++) {
        next_stack[i][0]         <== stack[i][0] + indicator[i].out * stack_change_value[0];
        second_index_clear[i]    <== stack[i][1] * (readEndBrace + readEndBracket); // Checking if we read some end char
        next_stack[i][1]         <== stack[i][1] + indicator[i].out * (stack_change_value[1] - second_index_clear[i]);
    }
    //--------------------------------------------------------------------------------------------//

    //--------------------------------------------------------------------------------------------//
    // * check for under or overflow
    component isUnderflowOrOverflow = InRange(8);
    isUnderflowOrOverflow.in     <== pointer - isPop.out + isPush.out;
    isUnderflowOrOverflow.range  <== [0,n];
    isUnderflowOrOverflow.out    === 1;
    //--------------------------------------------------------------------------------------------//
}