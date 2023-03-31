/// <reference types="jest" />

import fs from "fs";
import path from "path";
import crypto from "crypto";
import childProcess from "child_process";
import { composeSignature } from "../src";

const tmp = path.join(__dirname, "tmp");
const firmware = path.join(__dirname, "firmware.bin");
const firmwareSigned = path.join(tmp, "firmware.signed.bin");
const keysFolder = tmp;
const keyFileName = (i: number) => path.join(keysFolder, `key${i + 1}.pem`);
let keys: string[];

const invokeESPSecureVerify = (keys: number[]) => {
  return childProcess
    .execSync(
      `espsecure.py verify_signature ${firmwareSigned} -v 2 ${keys
        .map((i) => keyFileName(i))
        .map((n) => `-k ${n}`)
        .join(" ")}`
    )
    .toString();
};

describe("V2 RSA", () => {
  beforeAll(() => {
    if (fs.existsSync(tmp)) fs.rmSync(tmp, { recursive: true });
    fs.mkdirSync(tmp);
    keys = Array(3)
      .fill(0)
      .map(
        () =>
          crypto
            .generateKeyPairSync("rsa", { modulusLength: 3072 })
            .privateKey.export({ type: "pkcs1", format: "pem" }) as string
      );

    keys.forEach((key, i) => {
      fs.writeFileSync(keyFileName(i), Buffer.from(key));
    });
  });

  const runForXKeys = (n: number) => {
    const keysNs = Array(n)
      .fill(0)
      .map((_, i) => i);
    fs.writeFileSync(
      firmwareSigned,
      composeSignature(
        fs.readFileSync(firmware),
        keysNs.map((i) => keys[i])
      )
    );

    for (const keyN of keysNs)
      expect(invokeESPSecureVerify([keyN])).toContain(
        `Signature block ${keyN} is valid (RSA).
Signature block ${keyN} verification successful using the supplied key (RSA).`
      );
  };

  for (const key of [1, 2, 3])
    test(`${key} key${key != 1 ? "s" : ""}`, () => {
      runForXKeys(key);
    });
});
