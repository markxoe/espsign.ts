import { crc32 } from "crc";
import { doStuffToMakeTarget, Vn } from "./utils";
import crypto from "crypto";
import forge from "node-forge";

export const sign_block_size = 1216;

export const construct_sign_block = (
  sha256: Vn,
  rsa_n: Vn,
  rsa_e: Vn,
  rsa_R: Vn,
  rsa_M: Vn,
  sig: Vn
) => {
  let output = [] as Vn;
  output.push(0xe7); // Magic byte
  output.push(0x02); // Version 0x02 for RSA
  output.push(...Array(2).fill(0)); // 2 byte padding
  console.assert(sha256.length == 32, "Sha256 length in unexpected");
  output.push(...sha256); // sha256 hash of the original data

  // RSA stuff
  console.assert(rsa_n.length == 384, "n length must be 384 bytes");
  output.push(...rsa_n);
  console.assert(rsa_e.length == 4, "e length must be 4 bytes");
  output.push(...rsa_e);
  console.assert(rsa_R.length == 384, "R length must be 384 bytes");
  output.push(...rsa_R);
  console.assert(rsa_M.length == 4, "M length must be 4 bytes");
  output.push(...rsa_M);

  // Signature
  console.assert(sig.length == 384, "Signature length must be 384 bytes");
  output.push(...sig);

  // CRC
  const c = crc32(Buffer.from(output)) & 0xffffffff;
  output.push(c & 0xff);
  output.push((c >> 8) & 0xff);
  output.push((c >> 16) & 0xff);
  output.push((c >> 24) & 0xff); // CRC32 of the sign block

  // End padding
  output.push(...Array(16).fill(0));
  return output;
};

export const make_sign_block = (pem: string, hash: Vn, data: Vn) => {
  const key = forge.pki.privateKeyFromPem(pem);

  const rsa_n = key.n
    .toByteArray()
    .reverse()
    .map((i) => (i + 0x100) % 0x100);
  const rsa_e = key.e.toByteArray().reverse();

  const rsa_m = key.n
    .modInverse(new forge.jsbn.BigInteger("4294967296", null as any as number)) // 1 << 32
    .negate()
    .toByteArray()
    .reverse()
    .map((i) => (i + 0x100) % 0x100);

  const rsa_r = forge.jsbn.BigInteger.ONE.shiftLeft(3072 * 2) // 1 << 3072*2
    .mod(key.n)
    .toByteArray()
    .reverse()
    .map((i) => (i + 0x100) % 0x100);

  const sig = crypto
    .sign("RSA-SHA256", Buffer.from(data), {
      key: crypto.createPrivateKey(pem),
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    })
    .reverse();

  return construct_sign_block(
    hash,
    doStuffToMakeTarget(rsa_n, 384),
    doStuffToMakeTarget(rsa_e, 4),
    doStuffToMakeTarget(rsa_r, 384),
    doStuffToMakeTarget(rsa_m, 4),
    Array.from(sig)
  );
};
