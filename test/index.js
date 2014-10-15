var test = require('tape');
var fixtures = require('./fixtures.json');
var _crypto = require('crypto');
var crypto = require('../');
var modes = require('../modes');
var types = Object.keys(modes);
var ebtk = require('../EVP_BytesToKey');
function decriptNoPadding(cipher, password, thing, code) {
  var suite = _crypto.createDecipher(cipher, password);
  var buf = new Buffer('');
  suite.on('data', function (d) {
    buf = Buffer.concat([buf, d]);
  });
  suite.on('error', function (e) {
    console.log(e);
  });
  suite.on("finish", function () {
    console.log(code, buf.toString('hex'));
  });
  suite.setAutoPadding(false);
  suite.write(thing, 'hex');
  suite.end();
}
fixtures.forEach(function (fixture) {
  //var ciphers = fixture.results.ciphers = {};
  types.forEach(function (cipher) {
    test(cipher, function (t) {
      t.plan(1);
      var suite = crypto.createCipher(cipher, new Buffer(fixture.password));
      var buf = new Buffer('');
      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d]);
      });
      suite.on('error', function (e) {
        console.log(e);
      });
      suite.on("end", function () {
        // console.log(fixture.text);
        // decriptNoPadding(cipher, new Buffer(fixture.password), buf.toString('hex'), 'a');
        // decriptNoPadding(cipher, new Buffer(fixture.password), fixture.results.ciphers[cipher], 'b');
        t.equals(buf.toString('hex'), fixture.results.ciphers[cipher]);
      });
      suite.write(new Buffer(fixture.text));
      suite.end();
    });
    test(cipher + '-derypt', function (t) {
      t.plan(1);
      var suite = crypto.createDecipher(cipher, new Buffer(fixture.password));
      var buf = new Buffer('');
      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d]);
      });
      suite.on('error', function (e) {
        console.log(e);
      });
      suite.on("end", function () {
        // console.log(fixture.text);
        // decriptNoPadding(cipher, new Buffer(fixture.password), buf.toString('hex'), 'a');
        // decriptNoPadding(cipher, new Buffer(fixture.password), fixture.results.ciphers[cipher], 'b');
        t.equals(buf.toString('utf8'), fixture.text);
      });
      suite.write(new Buffer(fixture.results.ciphers[cipher], 'hex'));
      suite.end();
    });
    //var cipherivs = fixture.results.cipherivs = {};
    types.forEach(function (cipher) {
      if (modes[cipher].mode === 'ECB') {
        return;
      }
      test(cipher + '-iv', function (t) {
        t.plan(1);
        var suite = crypto.createCipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key, new Buffer(fixture.iv, 'hex'));
        var buf = new Buffer('');
        suite.on('data', function (d) {
          buf = Buffer.concat([buf, d]);
        });
        suite.on('error', function (e) {
          console.log(e);
        });
        suite.on("end", function () {
          t.equals(buf.toString('hex'), fixture.results.cipherivs[cipher]);
        });
        suite.write(new Buffer(fixture.text));
        suite.end();
      });
      test(cipher + '-iv-decrypt', function (t) {
        t.plan(1);
        var suite = crypto.createDecipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key, new Buffer(fixture.iv, 'hex'));
        var buf = new Buffer('');
        suite.on('data', function (d) {
          buf = Buffer.concat([buf, d]);
        });
        suite.on('error', function (e) {
          console.log(e);
        });
        suite.on("end", function () {
            t.equals(buf.toString('utf8'), fixture.text);
        });
        suite.write(new Buffer(fixture.results.cipherivs[cipher], 'hex'));
        suite.end();
      });
    });
  });
});
