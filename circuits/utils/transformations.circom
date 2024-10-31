pragma circom 2.1.9;
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";


//convert stream of plain text to blocks of 16 bytes
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

// convert blocks of 16 bytes to stream of bytes
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

// Increment a 32-bit word, represented as a 4-byte array
//
//    \  :  /       \  :  /       \  :  /       \  :  /       \  :  /
// `. __/ \__ .' `. __/ \__ .' `. __/ \__ .' `. __/ \__ .' `. __/ \__ .'
// _ _\     /_ _ _ _\     /_ _ _ _\     /_ _ _ _\     /_ _ _ _\     /_ _
//    /_   _\       /_   _\       /_   _\       /_   _\       /_   _\
//  .'  \ /  `.   .'  \ /  `.   .'  \ /  `.   .'  \ /  `.   .'  \ /  `.
//    /  |  \       /  :  \       /  :  \       /  :  \       /  |  \
//       |                                                       |
//    \  |  /                                                 \  |  /
// `. __/ \__ .'                                           `. __/ \__ .'
// _ _\     /_ _                                           _ _\     /_ _
//    /_   _\                            __                   /_   _\
//  .'  \ /  `.               .-.       /  |                .'  \ /  `.
//    /  |  \               __| |__     `| |                  /  |  \
//       |                 |__   __|     | |
//    \  |  /                 | |       _| |_                 \  |  /
// `. __/ \__ .'              '-'      |_____|             `. __/ \__ .'
// _ _\     /_ _                                           _ _\     /_ _
//    /_   _\                                                 /_   _\
//  .'  \ /  `.                                             .'  \ /  `.
//    /  |  \                                                 /  |  \
//       |                                                       |
//    \  |  /       \  :  /       \  :  /       \  :  /       \  |  /
// `. __/ \__ .' `. __/ \__ .' `. __/ \__ .' `. __/ \__ .' `. __/ \__ .'
// _ _\     /_ _ _ _\     /_ _ _ _\     /_ _ _ _\     /_ _ _ _\     /_ _
//    /_   _\       /_   _\       /_   _\       /_   _\       /_   _\
//  .'  \ /  `.   .'  \ /  `.   .'  \ /  `.   .'  \ /  `.   .'  \ /  `.
//    /  :  \       /  :  \       /  :  \       /  :  \       /  :  \
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