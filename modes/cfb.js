var xor = require('../xor');
exports.encrypt = function (self, block) {
  var pad = self._cipher.encryptBlock(self._prev);
  self._prev = xor(block, pad);
  return self._prev;
};
exports.decrypt = function (self, block) {
  // yes encrypt
  var pad = self._cipher.encryptBlock(self._prev);
  self._prev = block;
  return xor(pad, block);
};