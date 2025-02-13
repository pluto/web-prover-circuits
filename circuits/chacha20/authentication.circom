// initially from https://github.com/reclaimprotocol/zk-symmetric-crypto
// modified for our needs
pragma circom 2.1.9;

include "chacha-round.circom";
include "chacha-qr.circom";
include "../utils/bits.circom";
include "../utils/hash.circom";
include "../utils/array.circom";
include "circomlib/circuits/poseidon.circom";


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
// paramaterized by `DATA_BYTES` which is the plaintext length in bytes
template PlaintextAuthentication(DATA_BYTES, PUBLIC_IO_LENGTH) {
  // key => 8 32-bit words = 32 bytes
  signal input key[8][32];
  // nonce => 3 32-bit words = 12 bytes
  signal input nonce[3][32];
  // counter => 32-bit word to apply w nonce
  signal input counter[32];

  // the below can be both ciphertext or plaintext depending on the direction
  // in => N 32-bit words => N 4 byte words
  signal input plaintext[DATA_BYTES];

  signal input ciphertext_digest;

  // step_in should be the ciphertext digest + the HTTP digests + JSON seq digest
  signal input step_in[PUBLIC_IO_LENGTH];

  // step_out should be the plaintext digest
  signal output step_out[PUBLIC_IO_LENGTH];

  signal isPadding[DATA_BYTES]; // == 1 in the case we hit padding number
  signal plaintextBits[DATA_BYTES / 4][32];
  component toBits[DATA_BYTES / 4];
  for (var i = 0 ; i < DATA_BYTES / 4 ; i++) {
    toBits[i] = fromWords32ToLittleEndian();
    for (var j = 0 ; j < 4 ; j++) {
      isPadding[i * 4 + j]         <== IsEqual()([plaintext[i * 4 + j], -1]);
      toBits[i].words[j] <== (1 - isPadding[i * 4 + j]) * plaintext[i*4 + j];
    }
    plaintextBits[i] <== toBits[i].data;
  }

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
  component rounds[DATA_BYTES / 64];
  component xors[DATA_BYTES];
  component counter_adder[DATA_BYTES / 64 - 1];

  signal cipherText[DATA_BYTES / 4][32];

  for(i = 0; i < DATA_BYTES / 64; i++) {
    rounds[i] = Round();
    rounds[i].in <== tmp;
    // XOR block with input
    for(j = 0; j < 16; j++) {
      xors[i*16 + j] = XorBits(32);
      xors[i*16 + j].a <== plaintextBits[i*16 + j];
      xors[i*16 + j].b <== rounds[i].out[j];
      cipherText[i*16 + j] <== xors[i*16 + j].out;
    }

    if(i < DATA_BYTES / 64 - 1) {
      counter_adder[i] = AddBits(32);
      counter_adder[i].a <== tmp[12];
      counter_adder[i].b <== one;

      // increment the counter
      tmp[12] = counter_adder[i].out;
    }
  }

  component toCiphertextBytes[DATA_BYTES / 4];
  signal bigEndianCiphertext[DATA_BYTES];

  for (var i = 0 ; i < DATA_BYTES / 4 ; i++) {
    toCiphertextBytes[i] = fromLittleEndianToWords32();
    for (var j = 0 ; j < 32 ; j++) {
      toCiphertextBytes[i].data[j] <== cipherText[i][j];
    }
    for (var j = 0 ; j < 4 ; j++) {
      bigEndianCiphertext[i*4 + j] <== isPadding[i * 4 + j] * (-1 - toCiphertextBytes[i].words[j]) + toCiphertextBytes[i].words[j]; // equal to: (isPadding[i * 4 + j] * (-1)) + (1 - isPadding[i * 4 + j]) * toCiphertextBytes[i].words[j];
    }
  }

  // for (var i = 0 ; i < DATA_BYTES ; i++) {
  //   log("bigEndianCiphertext[",i,"]", bigEndianCiphertext[i]);
  // }

  // Count the number of non-padding bytes
  signal ciphertext_digest_pow[DATA_BYTES+1];
  ciphertext_digest_pow[0] <== step_in[1];
  signal mult_factor[DATA_BYTES];
  // Sets any padding bytes to zero (which are presumably at the end) so they don't accum into the poly hash
  signal zeroed_plaintext[DATA_BYTES];
  for(var i = 0 ; i < DATA_BYTES ; i++) {
    zeroed_plaintext[i] <== (1 - isPadding[i]) * plaintext[i];
    mult_factor[i] <== (1 - isPadding[i]) * ciphertext_digest + isPadding[i];
    ciphertext_digest_pow[i+1] <== ciphertext_digest_pow[i] * mult_factor[i];
  }
  signal part_ciphertext_digest <== DataHasherWithSeed(DATA_BYTES)(step_in[10],bigEndianCiphertext);

  // log("part_ciphertext_digest: ", part_ciphertext_digest);

  signal plaintext_digest   <== PolynomialDigestWithCounter(DATA_BYTES)(zeroed_plaintext, ciphertext_digest, step_in[1]);

  // log("plaintext_digest: ", plaintext_digest);

  step_out[0] <== step_in[0] + step_in[10] - part_ciphertext_digest + plaintext_digest;
  step_out[1] <== ciphertext_digest_pow[DATA_BYTES];
  // TODO: I was lazy and put this at the end instead of in a better spot
  step_out[10] <== part_ciphertext_digest;

  // reset HTTP Verification inputs
  step_out[2] <== step_in[2]; // Ciphertext digest POW accumulator
  step_out[3] <== PolynomialDigest(8)([1, 0, 0, 0, 0, 0, 0, 1], ciphertext_digest); // default Machine state digest
  for (var i = 4 ; i < PUBLIC_IO_LENGTH - 1 ; i++) {
    if (i == 6) {
      step_out[i] <== 0; // Body ciphertext digest pow counter
    } else {
      step_out[i] <== step_in[i];
    }
  }

  // for (var i = 0; i < PUBLIC_IO_LENGTH ; i++) {
  //   log("step_out[",i,"]", step_out[i]);
  // }
  // log("xxxxxx Authentication Done xxxxxx");
}