var createCipher = require('./index').createCipher;
var encStream = createCipher('aes192', new Buffer('password'));
var crypto = require('crypto');
var decStream = crypto.createDecipher('aes192', new Buffer('password'));
encStream.pipe(decStream).on('data', function (d) {
  console.log(d.toString());
});

var data = [
  "foo",
  "abcdefghijklmnopqrstuvwxyz",
  "You can disable automatic padding of the input data to block size. If auto_padding is false, the length of the entire input data must be a multiple of the cipher's block size or final will fail. Useful for non-standard padding, e.g. using 0x0 instead of PKCS padding. You must call this before cipher.final."
];
data.forEach(function (item) {
  console.log(item);
  encStream.write(item);
});