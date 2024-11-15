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

include "../../utils/array.circom";
include "../../utils/bytes.circom";
include "../../utils/operators.circom";
include "../../utils/hash.circom";
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
template StateUpdateHasher(MAX_STACK_HEIGHT) {
    signal input byte; 
    
    signal input stack[MAX_STACK_HEIGHT][2];
    signal input parsing_string;
    signal input parsing_number;
    signal input tree_hasher[MAX_STACK_HEIGHT][2];

    signal output next_stack[MAX_STACK_HEIGHT][2];
    signal output next_parsing_string;
    signal output next_parsing_number;
    signal output next_tree_hasher[MAX_STACK_HEIGHT][2];

    component Command = Command();

    //--------------------------------------------------------------------------------------------//
    // Break down what was read
    // * read in a start brace `{` *
    component readStartBrace   = IsEqual();
    readStartBrace.in        <== [byte, 123];
    // * read in an end brace `}` *
    component readEndBrace     = IsEqual();
    readEndBrace.in          <== [byte, 125];
    // * read in a start bracket `[` *
    component readStartBracket = IsEqual();
    readStartBracket.in      <== [byte, 91];
    // * read in an end bracket `]` *
    component readEndBracket   = IsEqual();
    readEndBracket.in        <== [byte, 93];
    // * read in a colon `:` *
    component readColon        = IsEqual();
    readColon.in             <== [byte, 58];
    // * read in a comma `,` *
    component readComma        = IsEqual();
    readComma.in             <== [byte, 44];
    // * read in some delimeter *
    signal readDelimeter     <== readStartBrace.out + readEndBrace.out + readStartBracket.out + readEndBracket.out
                               + readColon.out + readComma.out;
    // * read in some number *
    component readNumber       = InRange(8);
    readNumber.in            <== byte;
    readNumber.range         <== [48, 57]; // This is the range where ASCII digits are
    // * read in a quote `"` *
    component readQuote        = IsEqual();
    readQuote.in             <== [byte, 34];
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
    component topOfStack      = GetTopOfStack(MAX_STACK_HEIGHT);
    topOfStack.stack        <== stack;
    signal pointer          <== topOfStack.pointer;
    signal current_value[2] <== topOfStack.value;
    component newStack          = RewriteStack(MAX_STACK_HEIGHT);
    newStack.stack            <== stack;
    newStack.tree_hasher      <== tree_hasher;
    newStack.byte             <== byte;
    newStack.pointer          <== pointer;
    newStack.current_value    <== current_value;
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
    next_tree_hasher          <== newStack.next_tree_hasher;
    //--------------------------------------------------------------------------------------------//

    // //--------------------------------------------------------------------------------------------//
    // // Get the next tree hasher state
    // /*
    //     Idea: 
    //     We basically want a hasher that only hashes the KVs in a tree structure, so we have it
    //     store a hash array for the KV hash at a given depth. We will have to accumulate bytes
    //     into the hasher state while reading a value, so ultimately we want to check the hash array
    //     pointer changes right after we get a hash match on the key byte sequence.

    //     To start, let's just get something that hashes into the array like a buffer.
    // */
    // // Get the next state hash
    // component packedState = GenericBytePackArray(4,1);
    // packedState.in <== [ [byte], [pointer], [current_value[0]], [current_value[1]] ];
    // signal state_hash      <== IndexSelector(MAX_STACK_HEIGHT)(tree_hasher, pointer - 1);
    // signal next_state_hash <== PoseidonChainer()([state_hash, packedState.out[0]]);

    // // TODO: can probably output these from rewrite stack
    // // Now, use this to know how to modify the tree_hasher
    // signal is_push <== IsZero()(next_pointer - (pointer + 1));
    // signal is_pop <== IsZero()(next_pointer - (pointer - 1));


    // // signal was_write <== parsing_number + parsing_string; // only write to slot if we are parsing a value type 
    // // signal is_next_write <== next_parsing_number + next_parsing_string; // only write to slot if we are parsing a value type
    // // signal is_write <== was_write * is_next_write;

    // signal was_and_is_parsing_string <== parsing_string * next_parsing_string;
    // signal is_write <== was_and_is_parsing_string + next_parsing_number;

    // // signal what_to_write <== is_write * next_state_hash;
    // // signal where_to_write_at[MAX_STACK_HEIGHT];
    // // signal what_to_write_at[MAX_STACK_HEIGHT];
    // // for(var i = 0 ; i < MAX_STACK_HEIGHT ; i++) {
    // //     what_to_write_at[i] <== what_to_write
    // // }

    // // for(var i = 0 ; i < MAX_STACK_HEIGHT ; i++) {
    // //     next_tree_hasher[i] <== tree_hasher[i] * (1 - is_pop) + what_to_write_at[i]; // Rewrite the array, replacing at `i` 
    // // }
    
    // signal stack_hashes[MAX_STACK_HEIGHT];
    // for(var i = 0 ; i < MAX_STACK_HEIGHT ; i++){
    //     stack_hashes[i] <== PoseidonChainer()(next_stack[i]);
    // }
    // // signal base_hashes[MAX_STACK_HEIGHT] <== ArrayAdd(MAX_STACK_HEIGHT)(stack_hashes, tree_hasher);
    // component writeTo = WriteToIndex(MAX_STACK_HEIGHT, 1);
    // writeTo.array_to_write_to <== stack_hashes;
    // /* 
    //     IDEA:
    //     if push, we write `[state_hash, 0]` at pointer
    //     if pop, we write `[0,0]` at pointer
    //     if neither, we write `[next_state_hash IF is_write ELSE 0, 0 ]

    // */
    
    // signal to_write_if_is_write <== next_state_hash * is_write;
    // signal to_write_if_is_push  <== state_hash * is_push;
    // writeTo.array_to_write_at_index <== [to_write_if_is_write + to_write_if_is_push];
    // writeTo.index <== next_pointer;
    // next_tree_hasher <== writeTo.out;
    log("--------------------------------");
    // log("state_hash:   ", state_hash);
    // log("pointer:      ", pointer);
    // log("next_pointer: ", next_pointer);
    log("byte:         ", byte);
    log("--------------------------------");
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
    signal input tree_hasher[n][2];
    signal input pointer;
    signal input current_value[2];

    signal input byte;

    signal input read_write_value;
    signal input readStartBrace;
    signal input readStartBracket;
    signal input readEndBrace;
    signal input readEndBracket;
    signal input readColon;
    signal input readComma;

    signal output next_stack[n][2];
    signal output next_tree_hasher[n][2];

    //--------------------------------------------------------------------------------------------//
    // * scan value on top of stack *
    // TODO: We do this outside rn
    // component topOfStack      = GetTopOfStack(n);
    // topOfStack.stack        <== stack;
    // signal pointer          <== topOfStack.pointer;
    // signal current_value[2] <== topOfStack.value;
    // * check if we are currently in a value of an object *
    // * check if value indicates currently in an array *
    component inArray         = IsEqual();
    inArray.in[0]           <== current_value[0];
    inArray.in[1]           <== 2;


    // TODO: doing the same now for tree hasher
    component topOfTreeHasher = GetTopOfStack(n);
    topOfTreeHasher.stack <== tree_hasher;
    signal tree_hasher_current_value[2] <== topOfTreeHasher.value;
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
    // // * set an indicator array for where we are pushing to or popping from*
    signal indicator[n];
    for(var i = 0; i < n; i++) {
        indicator[i] <== IsZero()(pointer - isPop - readColon - readComma - i); // Note, pointer points to unallocated region!
    }
    //--------------------------------------------------------------------------------------------//

    /* TODO: Okay, for sake of simplicity, it would probably be much easier to just use the
     WriteToIndex here for both the stack and tree hasher. Much more ergonomic and can probably 
     replace a good amount of this.
    */
    // signal stack0[n];
    // signal stack1[n];
    // for(var i = 0 ; i < n ; i++) {
    //     stack0[i] <== stack[i][0];
    //     stack1[i] <== stack[i][1];
    // }

    // signal stack0Change[2] <== [isPush * current_value[0], isPop * 0 + current_value[0]];
    // signal newStack0[n] <== WriteToIndex(n, 2)(stack0, stack0Change, pointer);

    // signal stack1Change[2] <== [isPush * current_value[1], isPop * 0 + current_value[1]];
    // signal newStack1[n] <== WriteToIndex(n, 2)(stack1, stack1Change, pointer);

    //--------------------------------------------------------------------------------------------//
    // * loop to modify the stack by rebuilding it *

    signal stack_change_value[2] <== [(isPush + isPop) * read_write_value, readColon + readCommaInArray - readCommaNotInArray];
    // signal tree_hash_change_value[2] <== [(isPush + isPop), readColon + readCommaInArray - readCommaNotInArray];
    signal second_index_clear[n];
    signal tree_hash_index_clear[2] <== [tree_hasher_current_value[0] * isPop, tree_hasher_current_value[1] * isPop];
    signal tree_hash_index_add[2] <== [(isPush + isPop) * byte, (readColon + readCommaInArray - readCommaNotInArray) * byte];
    for(var i = 0; i < n; i++) {
        next_stack[i][0]         <== stack[i][0] + indicator[i] * stack_change_value[0];
        second_index_clear[i]    <== stack[i][1] * (readEndBrace + readEndBracket); // Checking if we read some end char
        next_stack[i][1]         <== stack[i][1] + indicator[i] * (stack_change_value[1] - second_index_clear[i]);

        next_tree_hasher[i][0]   <== tree_hasher[i][0] + indicator[i] * (tree_hash_index_add[0] - tree_hash_index_clear[0]);
        next_tree_hasher[i][1]   <== tree_hasher[i][1] + indicator[i] * (tree_hash_index_add[1] - tree_hash_index_clear[1]);
    }
    //--------------------------------------------------------------------------------------------//

    //--------------------------------------------------------------------------------------------//
    // * check for under or overflow
    signal isUnderflowOrOverflow <== InRange(8)(pointer - isPop + isPush, [0,n]);
    isUnderflowOrOverflow        === 1;
    //--------------------------------------------------------------------------------------------//
}