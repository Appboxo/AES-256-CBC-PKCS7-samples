'use strict';

const crypto = require('crypto');

const secret_key = 'u9Qd9wV0Z6Ho9_TzCYyVW_WwBJwL7KvSl4k8fmfaLyE=';
const phrase = '{"name":"Bob","email":"user@example.com","address":"Singapore"}';

const ALGORITHM = 'aes-256-cbc';
const BLOCK_SIZE = 16;

function encrypt(val){
  let key = Buffer.from(secret_key, 'base64');
  const iv = crypto.randomBytes(BLOCK_SIZE);
  let cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = Buffer.concat([iv, cipher.update(val), cipher.final()]);

  return encrypted.toString('base64');
}

function decrypt(val) {
  let key = Buffer.from(secret_key, 'base64');
  const contents = Buffer.from(val, 'base64');
  const iv = contents.slice(0, BLOCK_SIZE);
  const textBytes = contents.slice(BLOCK_SIZE);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  let decrypted = decipher.update(textBytes);
  decrypted += decipher.final();
  return decrypted;
}


console.log('secret key: ', secret_key)
console.log('phrase:', phrase)
let encrypted = encrypt(phrase);
console.log('encrypted: ', encrypted);
console.log('decrypted: ', decrypt(encrypted));
