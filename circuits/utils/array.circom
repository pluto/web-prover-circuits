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

// // from little endian to 32 bit words
// // example:   
//   0, 1, 0, 1, 0, 0, 0, 0, => 80
//   0, 1, 0, 1, 0, 1, 0, 0, => 84
//   0, 1, 0, 1, 0, 1, 0, 0, => 84
//   0, 1, 0, 0, 1, 0, 0, 0, => 72 
// shoud be encoded as
// 72, 84, 84, 80
template fromLittleEndianToWords32() {
    signal input data[32];
    signal output words[4];
    component Bits2Num[4];
    for(var i = 3; i >= 0; i--) {
        Bits2Num[i] = Bits2Num(8);
        for(var j = 7; j >= 0; j--) {
            Bits2Num[i].in[7-j] <== data[i*8 + j];
        }
        words[3-i] <== Bits2Num[i].out;
    }
}
template fromWords32ToLittleEndian() {
    signal input words[4];
    signal output data[32];
    component Num2Bits[4];

    for(var i = 3; i >= 0; i--) {
        Num2Bits[i] = Num2Bits(8);
        Num2Bits[i].in <== words[3-i];
        
        for(var j = 7; j >= 0; j--) {
            data[i*8 + j] <== Num2Bits[i].out[7-j];
        }
    }
}

template AccumulateUnpadded(N) {
    signal input in[N];
    signal output out;

    var total = 0;
    for(var i = 0 ; i < N ; i++) {
        for(var j = 0 ; j < i ; j++) {
            total += in[i] != -1 ? in[i] : 0; 
        }
    }
    out <-- total;
}

// template pushToFront(N) {
//     signal input in[N];
//     signal output out[N];
//     // tally up start positions and lengths?
//     signal isPadding[N];
//     for (var i = 0 ; i < N ; i++) {
//         isPadding[i] <== IsEqual()([in[i], -1]);

//         // can we do this in an unconstrained way then verify we get back a correct thing?
//     }
// }

// template CompactBytes(n) {
//     signal input arr[n];
//     signal output out[n];
    
//     // Array to track if each position is masked
//     signal isMasked[n];
//     for (var i = 0; i < n; i++) {
//         isMasked[i] <== IsEqual()([arr[i], -1]);
//     }
    
//     // Count total non-masked elements
//     var validCount = 0;
//     for (var i = 0; i < n; i++) {
//         validCount += (1 - isMasked[i]);
//     }
    
//     // Place non-masked elements at the front
//     var nextPos = 0;
//     for (var i = 0; i < n; i++) {
//         // If current element is not masked, put it at nextPos
//         out[nextPos] <-- isMasked[i] == 0 ? arr[i] : out[nextPos];
//         nextPos += (1 - isMasked[i]);
//     }
    
//     // // Fill remaining positions with -1
//     // for (var i = validCount; i < n; i++) {
//     //     out[i] <-- -1;
//     // }
    
//     // // Constraints to ensure correctness
    
//     // // 1. Verify all output values are either valid bytes or -1
//     // signal outIsMasked[n];
//     // for (var i = 0; i < n; i++) {
//     //     outIsMasked[i] <== IsEqual()([out[i], -1]);
//     // }
    
//     // // 2. Verify same number of masked/unmasked values
//     // var inMaskedCount = 0;
//     // var outMaskedCount = 0;
//     // for (var i = 0; i < n; i++) {
//     //     inMaskedCount += isMasked[i];
//     //     outMaskedCount += outIsMasked[i];
//     // }
//     // signal sameCount;
//     // sameCount <== inMaskedCount - outMaskedCount;
//     // sameCount === 0;
    
//     // // 3. Verify relative order of non-masked values is preserved
//     // // For each non-masked value in input, find its position in output
//     // signal positions[n];
//     // for (var i = 0; i < n; i++) {
//     //     var found = 0;
//     //     var pos = 0;
//     //     if (isMasked[i] == 0) {
//     //         for (var j = 0; j < n; j++) {
//     //             if (arr[i] == out[j]) {
//     //                 found += 1;
//     //                 pos += j;
//     //             }
//     //         }
//     //         positions[i] <-- pos;
//     //     } else {
//     //         positions[i] <-- 0;
//     //     }
//     // }
    
//     // // Check that positions are monotonically increasing for non-masked values
//     // for (var i = 1; i < n; i++) {
//     //     signal orderCheck[n-1];
//     //     orderCheck[i-1] <-- 
//     //         (isMasked[i-1] == 0 && isMasked[i] == 0) ? 
//     //         (positions[i] > positions[i-1] ? 1 : 0) : 1;
//     //     orderCheck[i-1] === 1;
//     // }
// }