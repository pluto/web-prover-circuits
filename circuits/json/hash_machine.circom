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
include "../utils/bits.circom";
include "../utils/operators.circom";
include "../utils/hash.circom";
include "language.circom";

/*
This template is for updating the state of the parser from a current state to a next state.

# Params:
 - `MAX_STACK_HEIGHT`: the maximum stack height that can be used before triggering overflow.

# Inputs:
 - `byte`                      : the byte value of ASCII that was read by the parser.
 - `stack[MAX_STACK_HEIGHT][2]`: the stack machine's current stack.
 - `parsing_string`            : a bool flag that indicates whether the parser is currently parsing a string or not.
 - `parsing_primitive`            : a bool flag that indicates whether the parser is currently parsing a number or not.

# Outputs:
 - `next_stack[MAX_STACK_HEIGHT][2]`: the stack machine's stack after reading `byte`.
 - `next_parsing_string`            : a bool flag that indicates whether the parser is currently parsing a string or not after reading `byte`.
 - `next_parsing_primitive`            : a bool flag that indicates whether the parser is currently parsing a number or not after reading `byte`.
*/
template StateUpdateHasher(MAX_STACK_HEIGHT) {
    signal input byte;

    signal input stack[MAX_STACK_HEIGHT][2];
    signal input parsing_string;
    signal input parsing_primitive;
    signal input polynomial_input;
    signal input monomial;
    signal input tree_hash[MAX_STACK_HEIGHT][2];
    signal input escaped;

    signal output next_stack[MAX_STACK_HEIGHT][2];
    signal output next_parsing_string;
    signal output next_parsing_primitive;
    signal output next_monomial;
    signal output next_tree_hash[MAX_STACK_HEIGHT][2];
    signal output next_escaped;

    component Command = Command();
    component Syntax = Syntax();

    // log("--------------------------------");
    // log("byte:         ", byte);
    // log("--------------------------------");

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
    component readPrimitive       = Contains(23);
    readPrimitive.in            <== byte;
    readPrimitive.array         <== [Syntax.ZERO, Syntax.ONE, Syntax.TWO,Syntax.THREE, Syntax.FOUR, Syntax.FIVE, Syntax.SIX, Syntax.SEVEN, Syntax.EIGHT, Syntax.NINE, Syntax.n,Syntax.u,Syntax.l,Syntax.f,Syntax.a,Syntax.s,Syntax.e,Syntax.t,Syntax.r, Syntax.PERIOD, Syntax.E, Syntax.PLUS, Syntax.MINUS];
    // * read in a quote `"` *
    component readQuote        = IsEqual();
    readQuote.in             <== [byte, Syntax.QUOTE];
    // * read in a escape `\` *
    component readEscape       = IsEqual();
    readEscape.in            <== [byte, Syntax.ESCAPE];

    component readOther        = IsZero();
    readOther.in             <== readDelimeter + readPrimitive.out + readQuote.out;
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
    component readPrimitiveInstruction       = ScalarArrayMul(3);
    readPrimitiveInstruction.scalar        <== readPrimitive.out;
    readPrimitiveInstruction.array         <== Command.NUMBER;
    component readQuoteInstruction        = ScalarArrayMul(3);
    readQuoteInstruction.scalar         <== readQuote.out;
    readQuoteInstruction.array          <== Command.QUOTE;

    component Instruction                 = GenericArrayAdd(3,8);
    Instruction.arrays                  <== [readStartBraceInstruction.out, readEndBraceInstruction.out,
                                             readStartBracketInstruction.out, readEndBracketInstruction.out,
                                             readColonInstruction.out, readCommaInstruction.out,
                                             readPrimitiveInstruction.out, readQuoteInstruction.out];
    //--------------------------------------------------------------------------------------------//
    // Apply state changing data
    // * get the instruction mask based on current state *
    component mask              = StateToMask(MAX_STACK_HEIGHT);
    mask.readDelimeter        <== readDelimeter;
    mask.readPrimitive           <== readPrimitive.out;
    mask.parsing_string       <== parsing_string;
    mask.parsing_primitive       <== parsing_primitive;
    // * multiply the mask array elementwise with the instruction array *
    component mulMaskAndOut    = ArrayMul(3);
    mulMaskAndOut.lhs        <== mask.out;
    mulMaskAndOut.rhs        <== [Instruction.out[0], Instruction.out[1], Instruction.out[2]  - readOther.out];

    next_parsing_string       <== escaped * (parsing_string - (parsing_string + mulMaskAndOut.out[1])) + (parsing_string + mulMaskAndOut.out[1]);
    next_parsing_primitive       <== parsing_primitive + mulMaskAndOut.out[2];

    component newStack          = RewriteStack(MAX_STACK_HEIGHT);
    newStack.stack            <== stack;
    newStack.tree_hash        <== tree_hash;
    newStack.read_write_value <== mulMaskAndOut.out[0];
    newStack.readStartBrace   <== readStartBrace.out;
    newStack.readStartBracket <== readStartBracket.out;
    newStack.readEndBrace     <== readEndBrace.out;
    newStack.readEndBracket   <== readEndBracket.out;
    newStack.readColon        <== readColon.out;
    newStack.readComma        <== readComma.out;
    newStack.readQuote        <== readQuote.out;
    newStack.parsing_string   <== parsing_string;
    newStack.parsing_primitive      <== parsing_primitive;
    newStack.monomial            <== monomial;
    newStack.next_parsing_string <== next_parsing_string;
    newStack.next_parsing_primitive <== next_parsing_primitive;
    newStack.byte                <== byte;
    newStack.polynomial_input    <== polynomial_input;
    newStack.escaped             <== escaped;
    // * set all the next state of the parser using the escaped toggle *
    // Toggle escaped if read
    next_escaped              <== readEscape.out * (1 - escaped);
    for(var i = 0 ; i < MAX_STACK_HEIGHT ; i++) {
        next_stack[i][0] <== next_escaped * (stack[i][0] - newStack.next_stack[i][0]) + newStack.next_stack[i][0];
        next_stack[i][1] <== next_escaped * (stack[i][1] - newStack.next_stack[i][1]) + newStack.next_stack[i][1];
        next_tree_hash[i][0] <== next_escaped * (tree_hash[i][0] - newStack.next_tree_hash[i][0]) + newStack.next_tree_hash[i][0];
        next_tree_hash[i][1] <== next_escaped * (tree_hash[i][1] - newStack.next_tree_hash[i][1]) + newStack.next_tree_hash[i][1];
    }
    next_monomial             <== next_escaped * (monomial - newStack.next_monomial) + newStack.next_monomial;
}

/*
This template is for updating the state of the parser from a current state to a next state.

# Params:
 - `n`: tunable parameter for the number of `parsing_states` needed (TODO: could be removed).

# Inputs:
 - `readDelimeter` : a bool flag that indicates whether the byte value read was a delimeter.
 - `readPrimitive`    : a bool flag that indicates whether the byte value read was for a primitive value.
 - `parsing_primitive`: a bool flag that indicates whether the parser is currently parsing a string or not.
 - `parsing_primitive`: a bool flag that indicates whether the parser is currently parsing a number or not.

# Outputs:
 - `out[3]`: an array of values fed to update the stack and the parsing state flags.
    - 0: mask for `read_write_value`
    - 1: mask for `parsing_string`
    - 2: mask for `parsing_primitive`
*/
template StateToMask(n) {
    // TODO: Probably need to assert things are bits where necessary.
    signal input readDelimeter;
    signal input readPrimitive;
    signal input parsing_string;
    signal input parsing_primitive;
    signal output out[3];


    // `read_write_value`can change: IF NOT `parsing_string`
    out[0] <== (1 - parsing_string);

    // `parsing_string` can change:
    out[1] <== 1 - 2 * parsing_string;


    //--------------------------------------------------------------------------------------------//
    // `parsing_primitive` is more complicated to deal with
    /* We have the possible relevant states below:
    [isParsingString, isParsingNumber, readPrimitive, readDelimeter];
             1                2             4             8
    Above is the binary value for each if is individually enabled
    This is a total of 2^4 states
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1,  0,  0,  0,  0,   0];
    and the above is what we want to set `next_parsing_primitive` to given those
    possible.
    Below is an optimized version that could instead be done with a `Switch`
    */
    signal parsingNumberReadDelimeter <== parsing_primitive * (readDelimeter);
    signal readPrimitiveNotParsingNumber <== (1 - parsing_primitive) * readPrimitive;
    signal notParsingStringAndParsingNumberReadDelimeterOrreadPrimitiveNotParsingNumber <== (1 - parsing_string) * (parsingNumberReadDelimeter + readPrimitiveNotParsingNumber);
    //                                                                                                           10 above ^^^^^^^^^^^^^^^^^   4 above ^^^^^^^^^^^^^^^^^^
    signal parsingNumberNotreadPrimitive <== parsing_primitive * (1 - readPrimitive) ;
    signal parsingNumberNotreadPrimitiveNotReadDelimeter <== parsingNumberNotreadPrimitive * (1-readDelimeter);
    out[2] <== notParsingStringAndParsingNumberReadDelimeterOrreadPrimitiveNotParsingNumber + parsingNumberNotreadPrimitiveNotReadDelimeter;
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
    signal input tree_hash[n][2];
    signal input read_write_value;
    signal input readStartBrace;
    signal input readStartBracket;
    signal input readEndBrace;
    signal input readEndBracket;
    signal input readColon;
    signal input readComma;
    signal input readQuote;
    signal input escaped;

    signal input parsing_primitive;
    signal input parsing_string;
    signal input next_parsing_string;
    signal input next_parsing_primitive;
    signal input byte;
    signal input polynomial_input;
    signal input monomial;

    signal output next_monomial;
    signal output next_stack[n][2];
    signal output next_tree_hash[n][2];

    signal readColonAndNotParsingString <== readColon * (1 - parsing_string);
    signal readCommaAndNotParsingString <== readComma * (1 - parsing_string);
    //--------------------------------------------------------------------------------------------//
    // * scan value on top of stack *
    component topOfStack      = GetTopOfStack(n);
    topOfStack.stack        <== stack;
    signal pointer          <== topOfStack.pointer;
    signal current_value[2] <== topOfStack.value;
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
    signal isPush      <== IsEqual()([readStartBrace + readStartBracket, 1]);
    signal isPop       <== IsEqual()([readEndBrace + readEndBracket, 1]);
    signal nextPointer <== pointer + isPush - isPop;
    // // * set an indicator array for where we are pushing to or popping from *
    signal indicator[n];
    signal tree_hash_indicator[n];
    for(var i = 0; i < n; i++) {
        indicator[i] <== IsZero()(pointer - isPop - readColonAndNotParsingString - readCommaAndNotParsingString - i); // Note, pointer points to unallocated region!
        tree_hash_indicator[i] <== IsZero()(pointer - i - 1);
    }
    //--------------------------------------------------------------------------------------------//

    //--------------------------------------------------------------------------------------------//
    // Hash the next_* states to produce hash we need
    // TODO: This could be optimized -- we don't really need to do the index selector, we can just accumulate elsewhere
    component stateHash[2];
    stateHash[0] = IndexSelector(n);
    stateHash[0].index <== pointer - 1;
    stateHash[1] = IndexSelector(n);
    stateHash[1].index <== pointer - 1;
    for(var i = 0 ; i < n ; i++) {
        stateHash[0].in[i] <== tree_hash[i][0];
        stateHash[1].in[i] <== tree_hash[i][1];
    }

    signal is_object_key   <== IsEqualArray(2)([current_value,[1,0]]);
    signal is_object_value <== IsEqualArray(2)([current_value,[1,1]]);
    signal is_array        <== IsEqual()([current_value[0], 2]);

    signal not_to_hash <== IsZero()(parsing_string * next_parsing_string + next_parsing_primitive);
    signal hash_0      <== is_object_key * stateHash[0].out; // TODO: I think these may not be needed
    signal hash_1      <== (is_object_value + is_array) * stateHash[1].out; // TODO: I think these may not be needed

    signal monomial_is_zero <== IsZero()(monomial);
    signal increased_power  <== monomial * polynomial_input;
    next_monomial           <== (1 - not_to_hash) * (monomial_is_zero + increased_power); // if monomial is zero and to_hash, then this treats monomial as if it is 1, else we increment the monomial
    signal option_hash      <== hash_0 + hash_1 + byte * next_monomial;

    signal next_state_hash[2];
    next_state_hash[0] <== not_to_hash * (stateHash[0].out - option_hash) + option_hash; // same as: (1 - not_to_hash[i]) * option_hash[i] + not_to_hash[i] * hash[i];
    next_state_hash[1] <== not_to_hash * (stateHash[1].out - option_hash) + option_hash;
    // ^^^^ next_state_hash is the previous value (state_hash) or it is the newly computed value (option_hash)
    //--------------------------------------------------------------------------------------------//

    //--------------------------------------------------------------------------------------------//
    // * loop to modify the stack and tree hash by rebuilding it *
    signal stack_change_value[2] <== [(isPush + isPop) * read_write_value, readColonAndNotParsingString + readCommaInArray - readCommaNotInArray];
    signal second_index_clear[n];

    signal still_parsing_string <== parsing_string * next_parsing_string;
    signal still_parsing_object_key     <== still_parsing_string * is_object_key;
    signal end_kv               <== (1 - parsing_string) * (readCommaAndNotParsingString + readEndBrace + readEndBracket);
    // signal not_array_and_not_object_value <== (1 - is_array) * (1 - is_object_value);
    // signal not_array_and_not_object_value_and_not_end_kv <== not_array_and_not_object_value * (1 - end_kv);
    // signal not_array_and_not_end_kv <== (1 - is_array) * (1 - end_kv);
    signal to_change_zeroth         <== (1 - is_array) * still_parsing_object_key + end_kv;

    signal not_end_char_for_first    <== IsZero()(readColonAndNotParsingString + readCommaAndNotParsingString + readQuote + (1-next_parsing_primitive));
    signal maintain_zeroth           <== is_object_value * stateHash[0].out;
    signal to_change_first           <== is_object_value + is_array;
    // signal tree_hash_change_value[2] <== [not_array_and_not_object_value_and_not_end_kv * next_state_hash[0], to_change_first * next_state_hash[1]];

    signal to_clear_zeroth <== end_kv;
    signal stopped_parsing_primitive <== IsEqual()([(parsing_primitive - next_parsing_primitive), 1]);
    signal read_quote_not_escaped <== readQuote * (1 - escaped);
    signal not_to_clear_first <== IsZero()(end_kv + read_quote_not_escaped * parsing_string + stopped_parsing_primitive);
    signal to_clear_first <== (1 - not_to_clear_first);
    signal tree_hash_change_value[2] <== [(1 - to_clear_zeroth) * next_state_hash[0], (1 - to_clear_first) * next_state_hash[1]];

    signal to_update_hash[n][2];
    for(var i = 0 ; i < n ; i++) {
        to_update_hash[i][0] <== tree_hash_indicator[i] * to_change_zeroth;
        to_update_hash[i][1] <== tree_hash_indicator[i] * to_change_first;
    }
    /*
    NOTE:
    - The thing to do now is to make this so it clears off the value when we want and update it when we want.
    - Let's us a "to_change_zeroth" and "to_clear_zeroth" together. You will need both to clear, just "change" to update
    */
    for(var i = 0; i < n; i++) {
        next_stack[i][0]      <== stack[i][0] + indicator[i] * stack_change_value[0];
        second_index_clear[i] <== stack[i][1] * (readEndBrace + readEndBracket); // Checking if we read some end char
        next_stack[i][1]      <== stack[i][1] + indicator[i] * (stack_change_value[1] - second_index_clear[i]);

        next_tree_hash[i][0]  <== tree_hash[i][0] + to_update_hash[i][0] * (tree_hash_change_value[0] - tree_hash[i][0]);
        next_tree_hash[i][1]  <== tree_hash[i][1] + to_update_hash[i][1] * (tree_hash_change_value[1] - tree_hash[i][1]);
    }
    //--------------------------------------------------------------------------------------------//

    // log("to_clear_zeroth  = ", to_clear_zeroth);
    // log("to_clear_first   = ", to_clear_first);
    // log("to_change_zeroth = ", to_change_zeroth);
    // log("to_change_first  = ", to_change_first);
    // log("--------------------------------");

    //--------------------------------------------------------------------------------------------//
    // * check for under or overflow
    signal isUnderflowOrOverflow <== InRange(8)(pointer - isPop + isPush, [0,n]);
    isUnderflowOrOverflow        === 1;
    //--------------------------------------------------------------------------------------------//
}
