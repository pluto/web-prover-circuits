import { WitnessTester } from "circomkit";
import { circomkit } from "../common";

describe("MixColumns", () => {
  it("s0 should compute correctly", async () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    circuit = await circomkit.WitnessTester(`s0`, {
      file: "aes-gcm/aes/mix_columns",
      template: "S0",
      params: [],
    });

    await circuit.expectPass({ in: [0xd4, 0xbf, 0x5d, 0x30] }, { out: 0x04 });
  });

  it("s1 should compute correctly", async () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    circuit = await circomkit.WitnessTester(`s1`, {
      file: "aes-gcm/aes/mix_columns",
      template: "S1",
      params: [],
    });

    await circuit.expectPass({ in: [0xd4, 0xbf, 0x5d, 0x30] }, { out: 0x66 });
  });

  it("s2 should compute correctly", async () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    circuit = await circomkit.WitnessTester(`s2`, {
      file: "aes-gcm/aes/mix_columns",
      template: "S2",
      params: [],
    });

    await circuit.expectPass({ in: [0xd4, 0xbf, 0x5d, 0x30] }, { out: 0x81 });
  });

  it("s3 should compute correctly", async () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    circuit = await circomkit.WitnessTester(`s3`, {
      file: "aes-gcm/aes/mix_columns",
      template: "S3",
      params: [],
    });

    await circuit.expectPass({ in: [0xd4, 0xbf, 0x5d, 0x30] }, { out: 0xe5 });
  });

  it("s4 should compute correctly", async () => {
    let circuit: WitnessTester<["state"], ["out"]>;
    circuit = await circomkit.WitnessTester(`MixColumns`, {
      file: "aes-gcm/aes/mix_columns",
      template: "MixColumns",
      params: [],
    });
    const state = [
      [0xd4, 0xe0, 0xb8, 0x1e],
      [0xbf, 0xb4, 0x41, 0x27],
      [0x5d, 0x52, 0x11, 0x98],
      [0x30, 0xae, 0xf1, 0xe5],
    ];

    const out = [
      [0x04, 0xe0, 0x48, 0x28],
      [0x66, 0xcb, 0xf8, 0x06],
      [0x81, 0x19, 0xd3, 0x26],
      [0xe5, 0x9a, 0x7a, 0x4c],
    ];

    await circuit.expectPass({ state }, { out });
  });
});


