var xor = require('../xor');
exports.encrypt = exports.decrypt = function (self, block) {
  self._prev = self._cipher.encryptBlock(self._prev);
  return xor(block, self._prev);
};