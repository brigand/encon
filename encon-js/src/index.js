// TODO: express that this fails on node <11.2.0
// Reference: https://www.derpturkey.com/chacha20poly1305-aead-with-node-js/
const crypto = require('crypto');
const { promisify } = require('util');

const randomBytes = promisify(crypto.randomBytes);
const scrypt = promisify(crypto.scrypt);

// Source: encon/src/lib.rs
const CHUNKSIZE = 4096;
const SIGNATURE = Buffer.from([0xC1, 0x0A, 0x4B, 0xED]);
// Source: https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/crypto/aead/chacha20poly1305/constant.KEYBYTES.html
const KEYBYTES = 32;
const SALT_BYTES = 32;
const NONCE_BYTES = 12;
const AUTH_TAG_LENGTH = 16;

async function genSalt() {
  return randomBytes(SALT_BYTES);
}

async function genNonce() {
  return randomBytes(NONCE_BYTES);
}

function slices(buffer, ...sizes) {
  let offset = 0;
  let outputs = [];

  for (const size of sizes) {
    outputs.push(buffer.slice(offset, offset + size));
    offset += size;
  }

  outputs.push(buffer.slice(offset));

  return outputs;
}

function split(buffer, index) {
  let wrapped = index < 0 ? buffer.length + index : index;
  return [buffer.slice(0, wrapped), buffer.slice(wrapped)];
}

async function deriveKey(pass, salt) {
  return scrypt(pass, salt, KEYBYTES, {});
}

class Password {
  constructor(value) {
    this.value = value;
  }

  async encrypt(payload) {
    let outputs = [];

    outputs.push(SIGNATURE);

    let salt = await genSalt();
    let nonce = await genNonce();
    let key = await deriveKey(this.value, salt);

    let cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: AUTH_TAG_LENGTH });

    cipher.setAAD(Buffer.from([]));

    outputs.push(salt);
    outputs.push(nonce);
    outputs.push(cipher.update(payload));

    cipher.final();

    let authTag = cipher.getAuthTag();
    outputs.push(authTag);
    console.error('Auth tag', authTag.toString('hex'));

    return Buffer.concat(outputs);
  }

  async decrypt(buffer) {
    const [signature, salt, nonce, rest] = slices(buffer, SIGNATURE.length, SALT_BYTES, NONCE_BYTES);
    const [cipherData, authTag] = split(rest, -AUTH_TAG_LENGTH);

    let key = await deriveKey(this.value, salt);

    let decipher = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: AUTH_TAG_LENGTH});

    decipher.setAAD(Buffer.from([]));

    const output = decipher.update(cipherData);

    decipher.setAuthTag(authTag);
    decipher.final();

    return output;
  }
}

module.exports = {
  Password,
};