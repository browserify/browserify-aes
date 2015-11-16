var cAES = require('../emcc/aes').AES;
var jsAES = require('../aes').AES;
var key = new Buffer(16);
key.fill(0);
var input = new Buffer(16);
var jsTime = 0;
var cTime = 0;
function js(name) {
  var j = 0;
  input.fill(0);
  var t = process.hrtime();;
  var aes = new jsAES(key);
  while (j++ < 10000) {
    input = aes.encryptBlock(input);
  }
  var diff = process.hrtime(t);
  jsTime += (diff[0] * 1e9 + diff[1]);
}
function c(name) {
  input.fill(0);
  var i = 0;
  var t = process.hrtime();;
  var aes = new cAES(key);
  while (i++ < 10000) {
    input = aes.encryptBlock(input);
  }
  var diff = process.hrtime(t);
   cTime += (diff[0] * 1e9 + diff[1]);
}
var i = 0;
while (++i < 1000) {
  js('js' + i);
  c('c' + i);
}
console.log('c', cTime);
console.log('j', jsTime);
