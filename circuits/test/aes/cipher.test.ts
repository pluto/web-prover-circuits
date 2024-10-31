import { WitnessTester } from "circomkit";
import { circomkit } from "../common";

describe("Cipher", () => {
  let circuit: WitnessTester<["block", "key"], ["cipher"]>;
  it("should perform Cipher#1", async () => {
    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "aes-gcm/aes/cipher",
      template: "Cipher",
    });

    await circuit.expectPass(
      {
        block: [
          [0x32, 0x88, 0x31, 0xe0],
          [0x43, 0x5a, 0x31, 0x37],
          [0xf6, 0x30, 0x98, 0x07],
          [0xa8, 0x8d, 0xa2, 0x34],
        ],
        key: [
          0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
          0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ],
      },
      {
        cipher: [
          [0x39, 0x02, 0xdc, 0x19],
          [0x25, 0xdc, 0x11, 0x6a],
          [0x84, 0x09, 0x85, 0x0b],
          [0x1d, 0xfb, 0x97, 0x32],
        ],
      }
    );
  });

  // in  : f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  // out : ec8cdf7398607cb0f2d21675ea9ea1e4
  // key : 2b7e151628aed2a6abf7158809cf4f3c
  it("should perform Cipher#2", async () => {
    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "aes-gcm/aes/cipher",
      template: "Cipher",
    });

    await circuit.expectPass(
      {
        block: [
          [0xf0, 0xf4, 0xf8, 0xfc],
          [0xf1, 0xf5, 0xf9, 0xfd],
          [0xf2, 0xf6, 0xfa, 0xfe],
          [0xf3, 0xf7, 0xfb, 0xff],
        ],
        key: [
          0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
          0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ],
      },
      {
        cipher: [
          [0xec, 0x98, 0xf2, 0xea],
          [0x8c, 0x60, 0xd2, 0x9e],
          [0xdf, 0x7c, 0x16, 0xa1],
          [0x73, 0xb0, 0x75, 0xe4],
        ],
      }
    );
  });
  describe("AddRoundKey", () => {
    let circuit: WitnessTester<["state", "roundKey"], ["newState"]>;
    it("should perform AddRoundKey", async () => {
      circuit = await circomkit.WitnessTester(`AddRoundKey`, {
        file: "aes-gcm/aes/cipher",
        template: "AddRoundKey",
      });

      // 0x57 . 2 = 0xae
      await circuit.expectPass(
        {
          state: [
            [4, 224, 72, 40],
            [102, 203, 248, 6],
            [129, 25, 211, 38],
            [229, 154, 122, 76],
          ],
          roundKey: [
            [160, 250, 254, 23],
            [136, 84, 44, 177],
            [35, 163, 57, 57],
            [42, 108, 118, 5],
          ],
        },
        {
          newState: [
            [164, 104, 107, 2],
            [156, 159, 91, 106],
            [127, 53, 234, 80],
            [242, 43, 67, 73],
          ],
        }
      );
    });
  });

  describe("NextRound", () => {
    async function generatePassCase(
      round: number,
      key: number[][],
      expectedKey: number[][]
    ) {
      circuit = await circomkit.WitnessTester(`NextRound_${4}_${4}`, {
        file: "aes-gcm/aes/cipher",
        template: "NextRound",
      });
    }

    it("should compute correctly", async () => {
      const key = [
        [0x2b, 0x7e, 0x15, 0x16],
        [0x28, 0xae, 0xd2, 0xa6],
        [0xab, 0xf7, 0x15, 0x88],
        [0x09, 0xcf, 0x4f, 0x3c],
      ];

      const expectedNextKey = [
        [0xa0, 0xfa, 0xfe, 0x17],
        [0x88, 0x54, 0x2c, 0xb1],
        [0x23, 0xa3, 0x39, 0x39],
        [0x2a, 0x6c, 0x76, 0x05],
      ];

      await generatePassCase(1, key, expectedNextKey);
    });
  });

  describe("SubBlock", () => {
    let circuit: WitnessTester<["state"], ["newState"]>;
    it("should perform SubBlock", async () => {
      circuit = await circomkit.WitnessTester(`SubBlock`, {
        file: "aes-gcm/aes/cipher",
        template: "SubBlock",
      });
      // 0x57 . 2 = 0xae
      await circuit.expectPass(
        {
          state: [
            [25, 160, 154, 233],
            [61, 244, 198, 248],
            [227, 226, 141, 72],
            [190, 43, 42, 8],
          ],
        },
        {
          newState: [
            [212, 224, 184, 30],
            [39, 191, 180, 65],
            [17, 152, 93, 82],
            [174, 241, 229, 48],
          ],
        }
      );
    });
  });

  describe("ShiftRows", () => {
    let circuit: WitnessTester<["state"], ["newState"]>;
    it("should perform ShiftRows", async () => {
      circuit = await circomkit.WitnessTester(`ShiftRows`, {
        file: "aes-gcm/aes/cipher",
        template: "ShiftRows",
        params: [],
      });
      // 0x57 . 2 = 0xae
      await circuit.expectPass(
        {
          state: [
            [212, 224, 184, 30],
            [39, 191, 180, 65],
            [17, 152, 93, 82],
            [174, 241, 229, 48],
          ],
        },
        {
          newState: [
            [212, 224, 184, 30],
            [191, 180, 65, 39],
            [93, 82, 17, 152],
            [48, 174, 241, 229],
          ],
        }
      );
    });
  });
});
