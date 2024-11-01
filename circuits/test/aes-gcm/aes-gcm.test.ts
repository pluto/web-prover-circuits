import { assert } from "chai";
import { WitnessTester } from "circomkit";
import { circomkit, hexBytesToBigInt, hexToBytes } from "../common";

describe("aes-gcm", () => {
  let circuit: WitnessTester<["key", "iv", "plainText", "aad"], ["cipherText", "tag"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester(`aes-gcm`, {
      file: "aes-gcm/aes-gcm",
      template: "AESGCM",
      params: [16],
    });
  });

  it("should have correct output", async () => {
    let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let plainText = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let expected_output = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];

    const witness = await circuit.compute({ key: key, iv: iv, plainText: plainText, aad: aad }, ["cipherText", "authTag"])

    assert.deepEqual(witness.cipherText, hexBytesToBigInt(expected_output))
  });

  it("should work for self generated test case", async () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText", "aad"], ["cipherText", "tag"]>;
    circuit_one_block = await circomkit.WitnessTester(`aes-gcm`, {
      file: "aes-gcm/aes-gcm",
      template: "AESGCM",
      params: [16],
    });

    const key = hexToBytes('31313131313131313131313131313131');
    const iv = hexToBytes('313131313131313131313131');
    const msg = hexToBytes('7465737468656c6c6f30303030303030');
    const aad = hexToBytes('00000000000000000000000000000000')
    const ct = hexToBytes('2929d2bb1ae94804402b8e776e0d3356');
    const auth_tag = hexToBytes('0cab39e1a491b092185965f7b554aea0');

    const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: msg, aad: aad }, ["cipherText", "authTag"])

    assert.deepEqual(witness.cipherText, hexBytesToBigInt(ct))
  });

  it("should work for multiple blocks", async () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText", "aad"], ["cipherText", "tag"]>;
    circuit_one_block = await circomkit.WitnessTester(`aes-gcm`, {
      file: "aes-gcm/aes-gcm",
      template: "AESGCM",
      params: [32],
    });

    const key = hexToBytes('31313131313131313131313131313131');
    const iv = hexToBytes('313131313131313131313131');
    const msg = hexToBytes('7465737468656c6c6f303030303030307465737468656c6c6f30303030303030');
    const aad = hexToBytes('00000000000000000000000000000000')
    const ct = hexToBytes('2929d2bb1ae94804402b8e776e0d335626756530713e4c065af1d3c4f56e0204');
    const auth_tag = hexToBytes('438542d7f387568c84d23df60b223ecb');

    const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: msg, aad: aad }, ["cipherText", "authTag"])

    assert.deepEqual(witness.cipherText, hexBytesToBigInt(ct))
  });
});