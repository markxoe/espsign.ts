import crypto from "crypto";
import { make_sign_block } from "./sign";

const sector_size = 4096;

export const composeSignature = (imageContent: Buffer, keys: string[]) => {
  const padding = Array(sector_size - (imageContent.length % sector_size)).fill(
    0xff
  ) as number[];

  const outputImage = [...Array.from(imageContent), ...padding];
  const inputImagePadded = [...outputImage];

  const hash = Array.from(
    crypto.createHash("sha256").update(Buffer.from(outputImage)).digest()
  );
  for (const key of keys)
    outputImage.push(...make_sign_block(key, hash, inputImagePadded));
  outputImage.push(
    ...Array(sector_size - (outputImage.length % sector_size)).fill(0xff)
  );

  return Buffer.from(outputImage);
};
