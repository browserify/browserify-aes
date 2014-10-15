module.exports = xor;
function xor(a, b) {
  if (a.length !== b.length) {
    throw new TypeError('must be same length');
  }
  var len = a.length;
  var out = new Buffer(len);
  var i = -1;
  while (++i < len) {
    out.writeUInt8(a[i] ^ b[i], i);
  }
  return out;
}