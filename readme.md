# espsign.ts

Secure Boot V2 signing implemented in typescript.

Sign ESP32 images for Secure Boot V2 RSA (e.g. for secure OTA updates).

Note: The tests use espsecure.py to verify the functionality

Note: espsign currently does not recognize existing signature blocks

## Examples

espsecure command: `espsecure.py sign_data firmware.bin -v 2 -k key1.pem -o out.bin`

```ts
import espsign from "espsign";

const output = espsign.composeSignature(fs.readFileSync("firmware.bin"), [
  fs.readFileSync("key1.pem").toString(),
]);

fs.writeFileSync("out.bin", output);
```

espsecure command: `espsecure.py digest_sbv2_public_key -k key1.pem -o out.bin`

```ts
import espsign from "espsign";

const output = espsign.getKeyDigest(fs.readFileSync("key1.pem").toString());

fs.writeFileSync("out.bin", Buffer.from(output, "hex"));
```
