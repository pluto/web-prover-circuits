pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/mux1.circom";

/*
This template is an indicator for two equal array inputs.

# Params:
 - `n`: the length of arrays to compare

# Inputs:
 - `in[2][n]`: two arrays of `n` numbers

# Outputs:
 - `out`: either `0` or `1`
    - `1` if `in[0]` is equal to `in[1]` as arrays (i.e., component by component)
    - `0` otherwise
*/
template IsEqualArray(n) {
    signal input in[2][n];
    signal output out;

    var accum = 0;
    component equalComponent[n];

    for(var i = 0; i < n; i++) {
        equalComponent[i] = IsEqual();
        equalComponent[i].in[0] <== in[0][i];
        equalComponent[i].in[1] <== in[1][i];
        accum += equalComponent[i].out;
    }

    component totalEqual = IsEqual();
    totalEqual.in[0] <== n;
    totalEqual.in[1] <== accum;
    out <== totalEqual.out;
}

template IsEqualArrayPaddedLHS(n) {
    signal input in[2][n];
    signal output out;

    var accum = 0;
    component equalComponent[n];
    component isPaddedElement[n];

    for(var i = 0; i < n; i++) {
        isPaddedElement[i] = IsZero();
        isPaddedElement[i].in <== in[0][i];
        equalComponent[i] = IsEqual();
        equalComponent[i].in[0] <== in[0][i];
        equalComponent[i].in[1] <== in[1][i] * (1-isPaddedElement[i].out);
        accum += equalComponent[i].out;
    }

    component totalEqual = IsEqual();
    totalEqual.in[0] <== n;
    totalEqual.in[1] <== accum;
    out <== totalEqual.out;
}

// TODO: There should be a way to have the below assertion come from the field itself.
/*
This template is an indicator for if an array contains an element.

# Params:
 - `n`: the size of the array to search through

# Inputs:
 - `in`: a number
 - `array[n]`: the array we want to search through

# Outputs:
 - `out`: either `0` or `1`
    - `1` if `in` is found inside `array`
    - `0` otherwise
*/
template Contains(n) {
    assert(n > 0);
    /*
    If `n = p` for this large `p`, then it could be that this template
    returns the wrong value if every element in `array` was equal to `in`.
    This is EXTREMELY unlikely and iterating this high is impossible anyway.
    But it is better to check than miss something, so we bound it by `2**254` for now.
    */
    assert(n < 2**254);
    signal input in;
    signal input array[n];
    signal output out;

    var accum = 0;
    component equalComponent[n];
    for(var i = 0; i < n; i++) {
        equalComponent[i] = IsEqual();
        equalComponent[i].in[0] <== in;
        equalComponent[i].in[1] <== array[i];
        accum = accum + equalComponent[i].out;
    }

    component someEqual = IsZero();
    someEqual.in <== accum;

    // Apply `not` to this by 1-x
    out <== 1 - someEqual.out;
}

/*
This template adds two arrays component by component.

# Params:
 - `n`: the length of arrays to compare

# Inputs:
 - `in[2][n]`: two arrays of `n` numbers

# Outputs:
 - `out[n]`: the array sum value
*/
template ArrayAdd(n) {
    signal input lhs[n];
    signal input rhs[n];
    signal output out[n];

    for(var i = 0; i < n; i++) {
        out[i] <== lhs[i] + rhs[i];
    }
}

/*
This template multiplies two arrays component by component.

# Params:
 - `n`: the length of arrays to compare

# Inputs:
 - `in[2][n]`: two arrays of `n` numbers

# Outputs:
 - `out[n]`: the array multiplication value
*/
template ArrayMul(n) {
    signal input lhs[n];
    signal input rhs[n];
    signal output out[n];

    for(var i = 0; i < n; i++) {
        out[i] <== lhs[i] * rhs[i];
    }
}

/*
This template multiplies two arrays component by component.

# Params:
 - `m`: the length of the arrays to add
 - `n`: the number of arrays to add

# Inputs:
 - `arrays[m][n]`: `n` arrays of `m` numbers

# Outputs:
 - `out[m]`: the sum of all the arrays
*/
template GenericArrayAdd(m,n) {
    signal input arrays[n][m];
    signal output out[m];

    var accum[m];
    for(var i = 0; i < m; i++) {
        for(var j = 0; j < n; j++) {
            accum[i] += arrays[j][i];
        }
    }
    out <== accum;
}

/*
This template multiplies each component of an array by a scalar value.

# Params:
 - `n`: the length of the array

# Inputs:
 - `array[n]`: an array of `n` numbers

# Outputs:
 - `out[n]`: the scalar multiplied array
*/
template ScalarArrayMul(n) {
    signal input array[n];
    signal input scalar;
    signal output out[n];

    for(var i = 0; i < n; i++) {
        out[i] <== scalar * array[i];
    }
}

/*
This template sums over the elements in an array
# Params:
 - `n`: the length of the array

# Inputs:
 - `array[n]`: an array of `n` numbers

# Outputs:
 - `sum`: the sum of the array elements
*/
template SumMultiple(n) {
    signal input nums[n];
    signal output sum;

    signal sums[n];
    sums[0] <== nums[0];

    for(var i=1; i<n; i++) {
        sums[i] <== sums[i-1] + nums[i];
    }

    sum <== sums[n-1];
}

/*
This template selects a the value of an array at an index
# Params:
 - `n`: the length of the array

# Inputs:
 - `index`: the index to select

# Outputs:
 - `out`: the value of the array at this index
*/
template IndexSelector(total) {
    signal input in[total];
    signal input index;
    signal output out;

    //maybe add (index<total) check later when we decide number of bits

    component calcTotal = SumMultiple(total);
    component equality[total];

    for(var i=0; i<total; i++){
        equality[i] = IsEqual();
        equality[i].in[0] <== i;
        equality[i].in[1] <== index;
        calcTotal.nums[i] <== equality[i].out * in[i];
    }

    out <== calcTotal.sum;
}

/*
This template selects an array in a mxn matrix
# Params:
 - `m`: the row dimensions
 - `n`: the column dimensions

# Inputs:
 - `index`: the index to select

# Outputs:
 - `out`: the array at index
*/
template ArraySelector(m, n) {
    signal input in[m][n];
    signal input index;
    signal output out[n];
    assert(index >= 0 && index < m);

    signal selector[m];
    component Equal[m];
    for (var i = 0; i < m; i++) {
        selector[i] <== IsEqual()([index, i]);
    }

    var sum = 0;
    for (var i = 0; i < m; i++) {
        sum += selector[i];
    }
    sum === 1;

    signal sums[n][m+1];
    for (var j = 0; j < n; j++) {
        sums[j][0] <== 0;
        for (var i = 0; i < m; i++) {
            sums[j][i+1] <== sums[j][i] + in[i][j] * selector[i];
        }
        out[j] <== sums[j][m];
    }
}

/*
This template is multiplexer for two arrays of length n
# Params:
 - `n`: the array length

# Inputs:
 - `a`: the first array
 - `b`: the second array
 - `sel`: the selector (1 or 0)

# Outputs:
 - `out`: the array selected
*/
template ArrayMux(n) {
    signal input a[n]; 
    signal input b[n];    
    signal input sel;      
    signal output out[n];  

    for (var i = 0; i < n; i++) {
        out[i] <== (b[i] - a[i]) * sel + a[i];
    }
}

/*
This template writes one array to a larger array of fixed size starting at an index
E.g., given an array of m=160, we want to write at `index` to the n=16 bytes at that index.
This is used to write to nivc signals that are incrementally written to on each fold.
# Params:
 - `m`: the length of the array writing to
 - `n`: the array be written

# Inputs:
 - `array_to_write_to`: the array we of length m we are writing to
 - `array_to_write_at_index`: the array of length n we are writing to the array of length m
 - `index`: the index we are writing to `array_to_write_to`

# Outputs:
 - `out`: the new array
*/
template WriteToIndex(m, n) {
    signal input array_to_write_to[m];
    signal input array_to_write_at_index[n]; 
    signal input index;

    signal output out[m];

    assert(m >= n);

    // Note: this is underconstrained, we need to constrain that index + n <= m
    // Need to constrain that index + n <= m -- can't be an assertion, because uses a signal
    // ------------------------- //

    // Here, we get an array of ALL zeros, except at the `index` AND `index + n`
    //                                    beginning-------^^^^^ end---^^^^^^^^^  
    signal indexMatched[m];
    component indexBegining[m];
    component indexEnding[m];
    for(var i = 0 ; i < m ; i++) {
        indexBegining[i] = IsZero();
        indexBegining[i].in <== i - index; 
        indexEnding[i] = IsZero();
        indexEnding[i].in <== i - (index + n);
        indexMatched[i] <== indexBegining[i].out + indexEnding[i].out;
    }

    // E.g., index == 31, m == 160, n == 16
    // => indexMatch[31] == 1;
    // => indexMatch[47] == 1;
    // => otherwise, all 0. 

    signal accum[m];
    accum[0] <== indexMatched[0]; 

    component writeAt = IsZero();
    writeAt.in <== accum[0] - 1;

    component or = OR();
    or.a <== (writeAt.out * array_to_write_at_index[0]);
    or.b <== (1 - writeAt.out) * array_to_write_to[0];
    out[0] <== or.out;
    //          IF accum == 1 then { array_to_write_at } ELSE IF accum != 1 then { array to write_to }
    var accum_index = accum[0];

    component writeSelector[m - 1];
    component indexSelector[m - 1];
    component ors[m-1];
    for(var i = 1 ; i < m ; i++) {
        // accum will be 1 at all indices where we want to write the new array
        accum[i] <== accum[i-1] + indexMatched[i];
        writeSelector[i-1] = IsZero();
        writeSelector[i-1].in <== accum[i] - 1;
        // IsZero(accum[i] - 1); --> tells us we are in the range where we want to write the new array

        indexSelector[i-1] = IndexSelector(n);
        indexSelector[i-1].index <== accum_index;
        indexSelector[i-1].in <== array_to_write_at_index;
        // When accum is not zero, out is array_to_write_at_index, otherwise it is array_to_write_to

        ors[i-1] = OR();
        ors[i-1].a <== (writeSelector[i-1].out * indexSelector[i-1].out);
        ors[i-1].b <== (1 - writeSelector[i-1].out) * array_to_write_to[i];
        out[i] <== ors[i-1].out;
        accum_index += writeSelector[i-1].out;
    }
}


/*
Convert stream of plain text to blocks of 16 bytes
# Params:
 - `l`: the length of the byte stream

# Inputs:
 - `stream`: the stream of bytes of length l

# Outputs:
 - `out`: n 4x4 blocks representing 16 bytes
*/
template ToBlocks(l){
        signal input stream[l];

        var n = l\16;
        if(l%16 > 0){
                n = n + 1;
        }
        signal output blocks[n][4][4];

        var i, j, k;

        for (var idx = 0; idx < l; idx++) {
                blocks[i][k][j] <== stream[idx];
                k = k + 1;
                if (k == 4){
                        k = 0;
                        j = j + 1;
                        if (j == 4){
                                j = 0;
                                i = i + 1;
                        }
                }
        }

        if (l%16 > 0){
               blocks[i][k][j] <== 1;
               k = k + 1;
        }
}


/*
convert blocks of 16 bytes to stream of bytes
# Params:
 - `l`: the length of the byte stream
 - `n`: the number of blocks

# Inputs:
 - `blocks`: n 4x4 blocks representing 16 bytes

# Outputs:
 - `out`: the stream of bytes of length l
*/
template ToStream(n,l){
        signal input blocks[n][4][4];

        signal output stream[l];

        var i, j, k;

        while(i*16 + j*4 + k < l){
                stream[i*16 + j*4 + k] <== blocks[i][k][j];
                k = k + 1;
                if (k == 4){
                        k = 0;
                        j = j + 1;
                        if (j == 4){
                                j = 0;
                                i = i + 1;
                        }
                }
        }
}

/*
Increment a 32-bit word, represented as a 4-byte array
# Inputs:
 - `in`: a 4 byte word

# Outputs:
 - `out`: an incremented 4 byte word
*/
template IncrementWord() {
    signal input in[4];
    signal output out[4];
    signal carry[4];
    carry[3] <== 1;

    component IsGreaterThan[4];
    component mux[4];
    for (var i = 3; i >= 0; i--) {
        // check to carry overflow
        IsGreaterThan[i] = GreaterThan(8);
        IsGreaterThan[i].in[0] <== in[i] + carry[i];
        IsGreaterThan[i].in[1] <== 0xFF;

        // multiplexer to select the output
        mux[i] = Mux1();
        mux[i].c[0] <== in[i] + carry[i];
        mux[i].c[1] <== 0x00;
        mux[i].s <== IsGreaterThan[i].out;
        out[i] <== mux[i].out;

        // propagate the carry to the next bit
        if (i > 0) {
            carry[i - 1] <== IsGreaterThan[i].out;
        }
    }
}