/*
# `utils`
This module consists of helper templates for convencience.
It mostly extends the `bitify` and `comparators` modules from Circomlib.

## Layout
The key ingredients of `utils` are:
 - `ASCII`: Verify if a an input array contains valid ASCII values (e.g., u8 vals).
 - `IsEqualArray`: Check if two arrays are equal component by component.
 - `Contains`: Check if an element is contained in a given array.
 - `ArrayAdd`: Add two arrays together component by component.
 - `ArrayMul`: Multiply two arrays together component by component.
 - `GenericArrayAdd`: Add together an arbitrary amount of arrays.
 - `ScalarArrayMul`: Multiply each array element by a scalar value.
 - `InRange`: Check if a given number is in a given range.
 - `Switch`: Return a scalar value given a specific case.
 - `SwitchArray`: Return an array given a specific case.


## Testing
Tests for this module are located in the file: `./test/utils/utils.test.ts`
*/

pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "array.circom";


/*
This template checks if a given `n`-bit value is contained in a range of `n`-bit values

# Params:
 - `n`: the number of bits to use

# Inputs:
 - `range[2]`: the lower and upper bound of the array, respectively

# Outputs:
 - `out`: either `0` or `1`
    - `1` if `in` is within the range
    - `0` otherwise
*/
template InRange(n) {
    signal input in;
    signal input range[2];
    signal output out;

    component gte = GreaterEqThan(n);
    gte.in <== [in, range[0]];

    component lte = LessEqThan(n);
    lte.in <== [in, range[1]];

    out <== gte.out * lte.out;
}

/*
This template is creates an exhaustive switch statement from a list of branch values.
# Params:
 - `n`: the number of switch cases

# Inputs:
 - `case`: which case of the switch to select
 - `branches[n]`: the values that enable taking different branches in the switch
    (e.g., if `branch[i] == 10` then if `case == 10` we set `out == `vals[i]`)
 - `vals[n]`: the value that is emitted for a given switch case
    (e.g., `val[i]` array is emitted on `case == `branch[i]`)

# Outputs
 - `match`: is set to `0` if `case` does not match on any of `branches`
 - `out[n]`: the selected output value if one of `branches` is selected (will be `0` otherwise)
    ^^^^^^ BEWARE OF THIS FACT ABOVE!
*/
template Switch(n) {
    assert(n > 0);
    signal input case;
    signal input branches[n];
    signal input vals[n];
    signal output match;
    signal output out;


    // Verify that the `case` is in the possible set of branches
    component indicator[n];
    component matchChecker = Contains(n);
    signal temp_val[n];
    var sum;
    for(var i = 0; i < n; i++) {
        indicator[i] = IsZero();
        indicator[i].in <== case - branches[i];
        matchChecker.array[i] <== 1 - indicator[i].out;
        temp_val[i] <== indicator[i].out * vals[i];
        sum += temp_val[i];
    }
    matchChecker.in <== 0;
    match <== matchChecker.out;

    out <== sum;
}

/*
This template is creates an exhaustive switch statement from a list of branch values.
# Params:
 - `m`: the number of switch cases
 - `n`: the output array length

# Inputs:

 - `case`: which case of the switch to select
 - `branches[m]`: the values that enable taking different branches in the switch
    (e.g., if `branch[i] == 10` then if `case == 10` we set `out == `vals[i]`)
 - `vals[m][n]`: the value that is emitted for a given switch case
    (e.g., `val[i]` array is emitted on `case == `branch[i]`)

# Outputs
 - `match`: is set to `0` if `case` does not match on any of `branches`
 - `out[n]`: the selected output value if one of `branches` is selected (will be `[0,0,...]` otherwise)
    ^^^^^^ BEWARE OF THIS FACT ABOVE!
*/
template SwitchArray(m, n) {
    assert(m > 0);
    assert(n > 0);
    signal input case;
    signal input branches[m];
    signal input vals[m][n];
    signal output match;
    signal output out[n];


    // Verify that the `case` is in the possible set of branches
    component indicator[m];
    component matchChecker = Contains(m);
    signal component_out[m][n];
    var sum[n];
    for(var i = 0; i < m; i++) {
        indicator[i] = IsZero();
        indicator[i].in <== case - branches[i];
        matchChecker.array[i] <== 1 - indicator[i].out;
        for(var j = 0; j < n; j++) {
            component_out[i][j] <== indicator[i].out * vals[i][j];
            sum[j] += component_out[i][j];
        }
    }
    matchChecker.in <== 0;
    match <== matchChecker.out;

    out <== sum;
}

