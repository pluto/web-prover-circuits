export function to_nonce(iv: Uint8Array, seq: number): Uint8Array {
  let nonce = new Uint8Array(12);
  nonce.fill(0);

  //   nonce[4..].copy_from_slice(&seq.to_be_bytes());
  const seqBytes = new Uint8Array(new BigUint64Array([BigInt(seq)]).buffer).reverse();
  nonce.set(seqBytes, 4);

  nonce.forEach((_, i) => {
    nonce[i] ^= iv[i];
  });

  return nonce;
}