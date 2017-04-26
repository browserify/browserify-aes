var Module = require('./aes-build');
//var wrappedKeyExpansion = Module.cwrap('KeyExpansion', null, ['number', 'number', 'number']);
function expandKey(keyLen, key) {
  var keyBuf = Module._malloc(key.length);
  Module.HEAPU8.set(key, keyBuf);
  var outBuf = Module._malloc(60 * 4);
  Module._KeyExpansion(keyBuf, outBuf, keyLen);
  Module._free(keyBuf);
  return outBuf;
}
function getKeyLen(key) {
  switch(key.length) {
    case 16:
      return 128;
    case 24:
      return 192;
    case 32:
      return 256;
    default:
      throw new Error('invalid key length');
  }
}
exports.AES = AES;
function AES(key) {
  this.keyLen = getKeyLen(key);
  this.key = expandKey(this.keyLen, key);
  this.block = Module._malloc(16);
  this.buf = new Uint8Array(Module.HEAPU8.buffer, this.block, 16);
}
function readIn(state, block) {
  state[0 * 4 + 0] = block[0];
  state[1 * 4 + 0] = block[1];
  state[2 * 4 + 0] = block[2];
  state[3 * 4 + 0] = block[3];
  state[0 * 4 + 1] = block[4];
  state[1 * 4 + 1] = block[5];
  state[2 * 4 + 1] = block[6];
  state[3 * 4 + 1] = block[7];
  state[0 * 4 + 2] = block[8];
  state[1 * 4 + 2] = block[9];
  state[2 * 4 + 2] = block[10];
  state[3 * 4 + 2] = block[11];
  state[0 * 4 + 3] = block[12];
  state[1 * 4 + 3] = block[13];
  state[2 * 4 + 3] = block[14];
  state[3 * 4 + 3] = block[15];
}
function readOut(state, out) {
  out[0] = state[0 * 4 + 0];
  out[1] = state[1 * 4 + 0];
  out[2] = state[2 * 4 + 0];
  out[3] = state[3 * 4 + 0];
  out[4] = state[0 * 4 + 1];
  out[5] = state[1 * 4 + 1];
  out[6] = state[2 * 4 + 1];
  out[7] = state[3 * 4 + 1];
  out[8] = state[0 * 4 + 2];
  out[9] = state[1 * 4 + 2];
  out[10] = state[2 * 4 + 2];
  out[11] = state[3 * 4 + 2];
  out[12] = state[0 * 4 + 3];
  out[13] = state[1 * 4 + 3];
  out[14] = state[2 * 4 + 3];
  out[15] = state[3 * 4 + 3];
}
AES.prototype.encryptBlock = function (block) {
  readIn(this.buf, block);
  Module._aes_encrypt(this.block, this.key, this.keyLen);
  var out = new Buffer(16);
  readOut(this.buf, out);
  return out;
}
AES.prototype.decryptBlock = function (block) {
  readIn(this.buf, block);
  Module._aes_decrypt(this.block, this.key, this.keyLen);
  var out = new Buffer(16);
  readOut(this.buf, out);
  return out;
}
AES.prototype.scrub = function () {
  Module._free(this.key);
  Module._free(this.block);
}
