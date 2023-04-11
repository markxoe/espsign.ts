/// <reference types="jest" />

import fs from "fs";
import path from "path";
import crypto from "crypto";
import childProcess from "child_process";
import { encryptAESXTS } from "../src";

const tmp = path.join(__dirname, "tmp");
const firmware = path.join(__dirname, "firmware.bin");
const firmwareencrypted = path.join(tmp, "firmware.bin.encrypted");
const keyFileName = path.join(tmp, `enckey.bin`);
const key = crypto.randomBytes(32);

const invokeESPSecure = (args: string) => {
  return childProcess.execSync(`espsecure.py ${args}`).toString();
};

describe("AES XTS", () => {
  beforeAll(() => {
    if (fs.existsSync(tmp)) fs.rmSync(tmp, { recursive: true });
    fs.mkdirSync(tmp);
    fs.writeFileSync(keyFileName, key);
  });

  test("At 0x8000", () => {
    invokeESPSecure(
      `encrypt_flash_data --aes_xts -k ${keyFileName} ${firmware} -a 0x8000 -o ${firmwareencrypted}`
    );

    expect(fs.readFileSync(firmwareencrypted)).toStrictEqual(
      encryptAESXTS(key, fs.readFileSync(firmware), 0x8000)
    );
  });

  test("At 0x8020", () => {
    invokeESPSecure(
      `encrypt_flash_data --aes_xts -k ${keyFileName} ${firmware} -a 0x8020 -o ${firmwareencrypted}`
    );

    expect(fs.readFileSync(firmwareencrypted)).toStrictEqual(
      encryptAESXTS(key, fs.readFileSync(firmware), 0x8020)
    );
  });

  test("At 0x8021", () => {
    expect(encryptAESXTS(key, fs.readFileSync(firmware), 0x8021)).toBeFalsy();
  });
});
