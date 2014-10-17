var xor = require('../xor');
exports.encrypt = exports.decrypt = function (self, block) {
  var out = xor(block, self._cipher.encryptBlock(self._prev));
  incr32(self._prev);
  return out;
};
function incr32(iv) {
  var len = iv.length;
  var item;
  while (len--) {
    item = iv.readUInt8(len);
    if (item === 255) {
      iv.writeUInt8(0, len);
    } else {
      item++;
      iv.writeUInt8(item, len);
      break;
    }
  }
}