// initially from https://github.com/reclaimprotocol/zk-symmetric-crypto
// modified for our needs
pragma circom 2.1.9;

include "../chacha-round.circom";
include "../chacha-qr.circom";
include "../../utils/generics-bits.circom";
include "../../utils/hash.circom";
include "../../utils/array.circom";


/** ChaCha20 in counter mode */
// Chacha20 opperates a 4x4 matrix of 32-bit words where the first 4 words are constants: C
// and the next 8 words are the 256 bit key: K. The next 2 words are the block counter: #
//  and the last 2 words are the nonce: N.
// +---+---+---+---+
// | C | C | C | C |
// +---+---+---+---+
// | K | K | K | K |
// +---+---+---+---+
// | K | K | K | K |
// +---+---+---+---+
// | # | N | N | N |
// +---+---+---+---+
// paramaterized by n which is the number of 32-bit words to encrypt
template ChaCha20_NIVC(N) {
	// key => 8 32-bit words = 32 bytes
	signal input key[8][32];
	// nonce => 3 32-bit words = 12 bytes
	signal input nonce[3][32];
	// counter => 32-bit word to apply w nonce
	signal input counter[32];

	// the below can be both ciphertext or plaintext depending on the direction
	// in => N 32-bit words => N 4 byte words
	signal input plainText[N][32];
	// out => N 32-bit words => N 4 byte words
	signal input cipherText[N][32];

	signal input step_in[1];
	signal output step_out[1];

	var tmp[16][32] = [
		[
			// constant 0x61707865
			0, 1, 1, 0, 0, 0, 0, 1, 0,
			1, 1, 1, 0, 0, 0, 0, 0, 1,
			1, 1, 1, 0, 0, 0, 0, 1, 1,
			0, 0, 1, 0, 1
		],
		[
			// constant 0x3320646e
			0, 0, 1, 1, 0, 0, 1, 1, 0,
			0, 1, 0, 0, 0, 0, 0, 0, 1,
			1, 0, 0, 1, 0, 0, 0, 1, 1,
			0, 1, 1, 1, 0
		],
		[
			// constant 0x79622d32
			0, 1, 1, 1, 1, 0, 0, 1, 0,
			1, 1, 0, 0, 0, 1, 0, 0, 0,
			1, 0, 1, 1, 0, 1, 0, 0, 1,
			1, 0, 0, 1, 0
		],
		[
			// constant 0x6b206574
			0, 1, 1, 0, 1, 0, 1, 1, 0,
			0, 1, 0, 0, 0, 0, 0, 0, 1,
			1, 0, 0, 1, 0, 1, 0, 1, 1,
			1, 0, 1, 0, 0
		],
		key[0], key[1], key[2], key[3], 
		key[4], key[5], key[6], key[7],
		counter, nonce[0], nonce[1], nonce[2]
	];

	// 1 in 32-bit words
	signal one[32];
	one <== [
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1
	];

	var i = 0;
	var j = 0;

	// do the ChaCha20 rounds
    // rounds opperates on 4 words at a time
	component rounds[N/16];
	component xors[N];
	component counter_adder[N/16 - 1];

    signal computedCipherText[N][32];

	for(i = 0; i < N/16; i++) {
		rounds[i] = Round();
		rounds[i].in <== tmp;
		// XOR block with input
		for(j = 0; j < 16; j++) {
			xors[i*16 + j] = XorBits(32);
			xors[i*16 + j].a <== plainText[i*16 + j];
			xors[i*16 + j].b <== rounds[i].out[j];
			computedCipherText[i*16 + j] <== xors[i*16 + j].out;
		}

		if(i < N/16 - 1) {
			counter_adder[i] = AddBits(32);
			counter_adder[i].a <== tmp[12];
			counter_adder[i].b <== one;

			// increment the counter
			tmp[12] = counter_adder[i].out;
		}
	}

	signal ciphertext_equal_check[N][32];
    for(var i = 0 ; i < N; i++) {
        for(var j = 0 ; j < 32 ; j++) {
            ciphertext_equal_check[i][j] <== IsEqual()([computedCipherText[i][j], cipherText[i][j]]);
            ciphertext_equal_check[i][j] === 1;
        }
    }

    var packedPlaintext[N];  // Each element will be a 32-bit word
    for(var i = 0; i < N; i++) {
        packedPlaintext[i] = 0;
        for(var j = 0; j < 32; j++) {  // Loop through all 32 bits
            packedPlaintext[i] += plainText[i][j] * 2**j;  // Now we shift by single bits
        }
    }

    signal hash[N];
    hash[0] <== PoseidonChainer()([step_in[0], packedPlaintext[0]]);
    for(var i = 1 ; i < N ; i++) {
        hash[i] <== PoseidonChainer()([hash[i-1], packedPlaintext[i]]);
    }
    step_out[0] <== hash[N-1];
}