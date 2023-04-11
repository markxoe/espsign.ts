import crypto from "crypto";

const AESXTSaddressToIV = (address: number) => {
  const convertedAddress = address & ~0x7f;
  const addressbuffer = Array(4).fill(0);
  for (let i = 0; i < 4; ++i)
    addressbuffer[i] = (convertedAddress >> (i * 8)) & 0xff;

  return [...addressbuffer, ...Array(12).fill(0)];
};

const encryptBlockAESXTS = (
  key: Buffer,
  blockdata: Array<number>,
  address: number
) =>
  Array.from(
    crypto
      .createCipheriv(
        "aes-128-xts",
        key,
        Buffer.from(AESXTSaddressToIV(address))
      )
      .update(Buffer.from(blockdata.reverse()))
      .reverse()
  );

export const encryptAESXTS = (key: Buffer, data: Buffer, address: number) => {
  if (address % 16 != 0) return null;
  let dataCopy = Array.from(data);

  const pad_left = address % 0x80;
  dataCopy = [...Array(pad_left).fill(0), ...data];

  let pad_right = data.length % 0x80;
  if (pad_right > 0) pad_right = 0x80 - pad_right;
  dataCopy = [...dataCopy, ...Array(pad_right).fill(0)];

  const output: number[] = [];
  for (let i = 0; i < dataCopy.length; i += 0x80) {
    const block = dataCopy.slice(i, i + 0x80);
    output.push(...encryptBlockAESXTS(key, block, i + address));
  }

  if (pad_right != 0) output.splice(output.length - pad_right);
  if (pad_left != 0) output.splice(0, pad_left);

  return Buffer.from(output);
};
