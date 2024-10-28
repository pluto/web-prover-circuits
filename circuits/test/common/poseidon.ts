import { poseidon1, poseidon10, poseidon11, poseidon12, poseidon3, poseidon4, poseidon5, poseidon6, poseidon7, poseidon8, poseidon9, poseidon13, poseidon14, poseidon15, poseidon16, poseidon2 } from "poseidon-lite";

export function PoseidonModular(input: Array<number | string | bigint>): bigint {
    let chunks = Math.ceil(input.length / 16);
    let result: bigint = BigInt(0);

    for (var i = 0; i < chunks; i++) {
        let chunk_hash: bigint = BigInt(0);
        if (i == chunks - 1) {
            switch (input.length % 16) {
                case 0:
                    chunk_hash = poseidon16(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 1:
                    chunk_hash = poseidon1(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 2:
                    chunk_hash = poseidon2(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 3:
                    chunk_hash = poseidon3(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 4:
                    chunk_hash = poseidon4(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 5:
                    chunk_hash = poseidon5(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 6:
                    chunk_hash = poseidon6(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 7:
                    chunk_hash = poseidon7(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 8:
                    chunk_hash = poseidon8(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 9:
                    chunk_hash = poseidon9(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 10:
                    chunk_hash = poseidon10(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 11:
                    chunk_hash = poseidon11(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 12:
                    chunk_hash = poseidon12(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 13:
                    chunk_hash = poseidon13(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 14:
                    chunk_hash = poseidon14(input.slice(i * 16, (i + 1) * 16));
                    break;
                case 15:
                    chunk_hash = poseidon15(input.slice(i * 16, (i + 1) * 16));
                    break;

                default:
                    break;
            }
        } else {
            chunk_hash = poseidon16(input.slice(i * 16, (i + 1) * 16));
        }
        if (i == 0) {
            result = chunk_hash;
        } else {
            result = poseidon2([result, chunk_hash]);
        }
    }

    return result;
}