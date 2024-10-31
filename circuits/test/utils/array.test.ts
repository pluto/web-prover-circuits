import { circomkit, WitnessTester } from "../common";
describe("IsEqualArray", () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`IsEqualArray`, {
            file: "utils/array",
            template: "IsEqualArray",
            params: [3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: [[0,0,0],[0,0,0]]", async () => {
        await circuit.expectPass(
            { in: [[0, 0, 0], [0, 0, 0]] },
            { out: 1 }
        );
    });

    it("witness: [[1,420,69],[1,420,69]]", async () => {
        await circuit.expectPass(
            { in: [[1, 420, 69], [1, 420, 69]] },
            { out: 1 },
        );
    });

    it("witness: [[0,0,0],[1,420,69]]", async () => {
        await circuit.expectPass(
            { in: [[0, 0, 0], [1, 420, 69]] },
            { out: 0 },
        );
    });

    it("witness: [[1,420,0],[1,420,69]]", async () => {
        await circuit.expectPass(
            { in: [[1, 420, 0], [1, 420, 69]] },
            { out: 0 },
        );
    });

    it("witness: [[1,0,69],[1,420,69]]", async () => {
        await circuit.expectPass(
            { in: [[1, 0, 69], [1, 420, 69]] },
            { out: 0 },
        );
    });

    it("witness: [[0,420,69],[1,420,69]]", async () => {
        await circuit.expectPass(
            { in: [[0, 420, 69], [1, 420, 69]] },
            { out: 0 },
        );
    });
});

describe("Contains", () => {
    let circuit: WitnessTester<["in", "array"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`Contains`, {
            file: "utils/array",
            template: "Contains",
            params: [3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: in = 0, array = [0,1,2]", async () => {
        await circuit.expectPass(
            { in: 0, array: [0, 1, 2] },
            { out: 1 }
        );
    });

    it("witness: in = 1, array = [0,1,2]", async () => {
        await circuit.expectPass(
            { in: 1, array: [0, 1, 2] },
            { out: 1 }
        );
    });

    it("witness: in = 2, array = [0,1,2]", async () => {
        await circuit.expectPass(
            { in: 2, array: [0, 1, 2] },
            { out: 1 }
        );
    });

    it("witness: in = 42069, array = [0,1,2]", async () => {
        await circuit.expectPass(
            { in: 42069, array: [0, 1, 2] },
            { out: 0 }
        );
    });

});

describe("ArrayAdd", () => {
    let circuit: WitnessTester<["lhs", "rhs"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`ArrayAdd`, {
            file: "utils/array",
            template: "ArrayAdd",
            params: [3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: lhs = [0,1,2], rhs = [3,5,7]", async () => {
        await circuit.expectPass(
            { lhs: [0, 1, 2], rhs: [3, 5, 7] },
            { out: [3, 6, 9] }
        );
    });

});

describe("ArrayMul", () => {
    let circuit: WitnessTester<["lhs", "rhs"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`ArrayMul`, {
            file: "utils/array",
            template: "ArrayMul",
            params: [3],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: lhs = [0,1,2], rhs = [3,5,7]", async () => {
        await circuit.expectPass(
            { lhs: [0, 1, 2], rhs: [3, 5, 7] },
            { out: [0, 5, 14] }
        );
    });

});

describe("GenericArrayAdd", () => {
    let circuit: WitnessTester<["arrays"], ["out"]>;
    before(async () => {
        circuit = await circomkit.WitnessTester(`ArrayAdd`, {
            file: "utils/array",
            template: "GenericArrayAdd",
            params: [3, 2],
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("witness: arrays = [[0,1,2],[3,5,7]]", async () => {
        await circuit.expectPass(
            { arrays: [[0, 1, 2], [3, 5, 7]] },
            { out: [3, 6, 9] }
        );
    });

});

describe("array_builder", () => {
    it("test array builder", async () => {
      let circuit: WitnessTester<["array_to_write_to", "array_to_write_at_index", "index"], ["out"]>;
      circuit = await circomkit.WitnessTester(`ArrayBuilder`, {
        file: "aes-gcm/utils",
        template: "WriteToIndex",
        params: [160, 16],
      });
  
      let array_to_write_to = new Array(160).fill(0x00);
      let array_to_write_at_index = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
      let expected = array_to_write_at_index.concat(new Array(160 - array_to_write_at_index.length).fill(0x00));
      let index = 0;
  
      await circuit.expectPass(
        {
          array_to_write_to: array_to_write_to,
          array_to_write_at_index: array_to_write_at_index,
          index: index
        },
        {
          out: expected
        }
      );
    });
    it("test array builder", async () => {
      let circuit: WitnessTester<["array_to_write_to", "array_to_write_at_index", "index"], ["out"]>;
      circuit = await circomkit.WitnessTester(`ArrayBuilder`, {
        file: "aes-gcm/utils",
        template: "WriteToIndex",
        params: [160, 16],
      });
  
      let array_to_write_to = new Array(160).fill(0x00);
      let array_to_write_at_index = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
      let expected = [0x00].concat(array_to_write_at_index).concat(new Array(160 - array_to_write_at_index.length - 1).fill(0x00));
      let index = 1;
  
      await circuit.expectPass(
        {
          array_to_write_to: array_to_write_to,
          array_to_write_at_index: array_to_write_at_index,
          index: index
        },
        {
          out: expected
        }
      );
    });
    it("test array builder", async () => {
      let circuit: WitnessTester<["array_to_write_to", "array_to_write_at_index", "index"], ["out"]>;
      circuit = await circomkit.WitnessTester(`ArrayBuilder`, {
        file: "aes-gcm/utils",
        template: "WriteToIndex",
        params: [160, 16],
      });
  
      let array_to_write_to = new Array(160).fill(0x00);
      let array_to_write_at_index = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
      let expected = [0x00, 0x00].concat(array_to_write_at_index).concat(new Array(160 - array_to_write_at_index.length - 2).fill(0x00));
      let index = 2;
  
      await circuit.expectPass(
        {
          array_to_write_to: array_to_write_to,
          array_to_write_at_index: array_to_write_at_index,
          index: index
        },
        {
          out: expected
        }
      );
    });
    it("test array builder with index = n", async () => {
      let circuit: WitnessTester<["array_to_write_to", "array_to_write_at_index", "index"], ["out"]>;
      circuit = await circomkit.WitnessTester(`ArrayBuilder`, {
        file: "aes-gcm/utils",
        template: "WriteToIndex",
        params: [37, 16],
      });
  
      let array_to_write_to = new Array(37).fill(0x00);
      let array_to_write_at_index = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
      let expected = new Array(16).fill(0x00).concat(array_to_write_at_index).concat(new Array(37 - array_to_write_at_index.length - 16).fill(0x00));
      let index = 16;
  
      await circuit.expectConstraintPass(
        {
          array_to_write_to: array_to_write_to,
          array_to_write_at_index: array_to_write_at_index,
          index: index
        },
        {
            out: expected
        }
      );
    });
  
    it("test array builder with index > n", async () => {
      let circuit: WitnessTester<["array_to_write_to", "array_to_write_at_index", "index"], ["out"]>;
      circuit = await circomkit.WitnessTester(`ArrayBuilder`, {
        file: "aes-gcm/utils",
        template: "WriteToIndex",
        params: [37, 4],
      });
  
      let array_to_write_to = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78,
        0x00, 0x00, 0x00, 0x00, 0x00
      ];
      let array_to_write_at_index = [0x00, 0x00, 0x00, 0x01];
      let expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78,
        0x00, 0x00, 0x00, 0x01, 0x00
      ];
      let index = 32;
  
      let witness = await circuit.compute(
        {
          array_to_write_to: array_to_write_to,
          array_to_write_at_index: array_to_write_at_index,
          index: index
        },
        ["out"]
      );
      assert.deepEqual(witness.out, expected.map(BigInt));
    });
    
  });