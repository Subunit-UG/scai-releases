// Sealed boxes as GitHub expects them for secrets: an ephemeral X25519 key, XSalsa20-Poly1305,
// and a nonce derived with BLAKE2b from both public keys. Output: ephemeral key, tag, ciphertext.
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, timingSafeEqual } from "node:crypto";

const SPKI = Buffer.from("302a300506032b656e032100", "hex");
const PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const publicKeyOf = (raw) => createPublicKey({ key: Buffer.concat([SPKI, raw]), format: "der", type: "spki" });
const privateKeyOf = (raw) => createPrivateKey({ key: Buffer.concat([PKCS8, raw]), format: "der", type: "pkcs8" });
const rawPublic = (key) => Buffer.from(key.export({ format: "der", type: "spki" }).subarray(-32));

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const rotl = (value, count) => (value << count) | (value >>> (32 - count));

function rounds(x) {
  const quarter = (a, b, c, d) => {
    x[b] ^= rotl((x[a] + x[d]) | 0, 7);
    x[c] ^= rotl((x[b] + x[a]) | 0, 9);
    x[d] ^= rotl((x[c] + x[b]) | 0, 13);
    x[a] ^= rotl((x[d] + x[c]) | 0, 18);
  };
  for (let round = 0; round < 10; round += 1) {
    quarter(0, 4, 8, 12); quarter(5, 9, 13, 1); quarter(10, 14, 2, 6); quarter(15, 3, 7, 11);
    quarter(0, 1, 2, 3); quarter(5, 6, 7, 4); quarter(10, 11, 8, 9); quarter(15, 12, 13, 14);
  }
}

function state(key, middle) {
  const x = new Uint32Array(16);
  x[0] = SIGMA[0]; x[5] = SIGMA[1]; x[10] = SIGMA[2]; x[15] = SIGMA[3];
  for (let i = 0; i < 4; i += 1) {
    x[1 + i] = key.readUInt32LE(4 * i);
    x[11 + i] = key.readUInt32LE(16 + 4 * i);
    x[6 + i] = middle.readUInt32LE(4 * i);
  }
  return x;
}

function hsalsa20(key, input) {
  const x = state(key, input);
  rounds(x);
  const out = Buffer.alloc(32);
  [0, 5, 10, 15, 6, 7, 8, 9].forEach((word, i) => out.writeUInt32LE(x[word], 4 * i));
  return out;
}

function xsalsa20(key, nonce, length) {
  const subkey = hsalsa20(key, nonce.subarray(0, 16));
  const out = Buffer.alloc(Math.ceil(length / 64) * 64);
  const middle = Buffer.alloc(16);
  nonce.copy(middle, 0, 16, 24);
  for (let block = 0; block * 64 < length; block += 1) {
    middle.writeUInt32LE(block >>> 0, 8);
    middle.writeUInt32LE(Math.floor(block / 2 ** 32), 12);
    const start = state(subkey, middle);
    const x = Uint32Array.from(start);
    rounds(x);
    for (let i = 0; i < 16; i += 1) out.writeUInt32LE((x[i] + start[i]) >>> 0, block * 64 + 4 * i);
  }
  return out.subarray(0, length);
}

const little = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString("hex") || "0"}`);

function poly1305(message, key) {
  const r = little(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const p = (1n << 130n) - 5n;
  let sum = 0n;
  for (let at = 0; at < message.length; at += 16) {
    const block = message.subarray(at, at + 16);
    sum = ((sum + little(block) + (1n << BigInt(8 * block.length))) * r) % p;
  }
  const tag = (sum + little(key.subarray(16, 32))) & ((1n << 128n) - 1n);
  return Buffer.from(tag.toString(16).padStart(32, "0"), "hex").reverse();
}

const IV = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
const ORDER = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const MASK = (1n << 64n) - 1n;
const rotr = (value, count) => ((value >> count) | (value << (64n - count))) & MASK;

// BLAKE2b without a key.
export function blake2b(input, length) {
  const h = [...IV];
  h[0] ^= 0x01010000n ^ BigInt(length);
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  for (let index = 0; index < blocks; index += 1) {
    const block = Buffer.alloc(128);
    input.copy(block, 0, index * 128, Math.min(input.length, (index + 1) * 128));
    const last = index === blocks - 1;
    const m = Array.from({ length: 16 }, (_, i) => block.readBigUInt64LE(8 * i));
    const v = [...h, ...IV];
    v[12] ^= BigInt(last ? input.length : (index + 1) * 128);
    if (last) v[14] ^= MASK;
    const mix = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + x) & MASK; v[d] = rotr(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & MASK; v[b] = rotr(v[b] ^ v[c], 24n);
      v[a] = (v[a] + v[b] + y) & MASK; v[d] = rotr(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & MASK; v[b] = rotr(v[b] ^ v[c], 63n);
    };
    for (let round = 0; round < 12; round += 1) {
      const s = ORDER[round % 10];
      mix(0, 4, 8, 12, m[s[0]], m[s[1]]); mix(1, 5, 9, 13, m[s[2]], m[s[3]]);
      mix(2, 6, 10, 14, m[s[4]], m[s[5]]); mix(3, 7, 11, 15, m[s[6]], m[s[7]]);
      mix(0, 5, 10, 15, m[s[8]], m[s[9]]); mix(1, 6, 11, 12, m[s[10]], m[s[11]]);
      mix(2, 7, 8, 13, m[s[12]], m[s[13]]); mix(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i += 1) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = Buffer.alloc(64);
  h.forEach((word, i) => out.writeBigUInt64LE(word, 8 * i));
  return out.subarray(0, length);
}

function keys(shared, ephemeralPublic, recipientPublic, length) {
  const stream = xsalsa20(hsalsa20(shared, Buffer.alloc(16)), blake2b(Buffer.concat([ephemeralPublic, recipientPublic]), 24), 32 + length);
  return { mac: stream.subarray(0, 32), pad: stream.subarray(32) };
}

const xor = (a, b) => Buffer.from(a.map((byte, i) => byte ^ b[i]));

function key32(value, what) {
  const key = Buffer.from(value);
  if (key.length !== 32) throw new Error(`${what} must be 32 bytes`);
  return key;
}

export function seal(message, recipientPublic) {
  const recipient = key32(recipientPublic, "recipient public key");
  const plain = Buffer.from(message);
  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralPublic = rawPublic(ephemeral.publicKey);
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: publicKeyOf(recipient) });
  const { mac, pad } = keys(shared, ephemeralPublic, recipient, plain.length);
  const cipher = xor(plain, pad);
  return Buffer.concat([ephemeralPublic, poly1305(cipher, mac), cipher]);
}

export function open(sealed, recipientPublic, recipientPrivate) {
  const recipient = key32(recipientPublic, "recipient public key");
  const box = Buffer.from(sealed);
  if (box.length < 48) throw new Error("sealed value is too short");
  const ephemeralPublic = box.subarray(0, 32);
  const cipher = box.subarray(48);
  const shared = diffieHellman({ privateKey: privateKeyOf(key32(recipientPrivate, "recipient private key")), publicKey: publicKeyOf(ephemeralPublic) });
  const { mac, pad } = keys(shared, ephemeralPublic, recipient, cipher.length);
  if (!timingSafeEqual(poly1305(cipher, mac), box.subarray(32, 48))) throw new Error("sealed value does not verify");
  return xor(cipher, pad);
}
