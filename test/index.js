var test = require('tape');
var fixtures = require('./fixtures.json');
var _crypto = require('crypto');
var crypto = require('../');
var modes = require('../modes');
var types = Object.keys(modes);
var ebtk = require('../EVP_BytesToKey');
function isGCM(cipher) {
  return modes[cipher].mode === 'GCM';
}
function isNode10() {
  return process.version && process.version.split('.').length === 3 && parseInt(process.version.split('.')[1], 10) <= 10;
}
fixtures.forEach(function (fixture, i) {
  //var ciphers = fixture.results.ciphers = {};
  types.forEach(function (cipher) {
    if (isGCM(cipher)) {
      return;
    }
    test('fixture ' + i + ' ' + cipher, function (t) {
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
    test('fixture ' + i + ' ' + cipher + '-legacy', function (t) {
      t.plan(3);
      var suite = crypto.createCipher(cipher, new Buffer(fixture.password));
      var buf = new Buffer('');
      var suite2 = _crypto.createCipher(cipher, new Buffer(fixture.password));
      var buf2 = new Buffer('');
      var inbuf = new Buffer(fixture.text);
      var mid = ~~(inbuf.length/2);
      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))]);
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))]);
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate');
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))]);
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))]);
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate 2');
      buf = Buffer.concat([buf, suite.final()]);
      buf2 = Buffer.concat([buf2, suite2.final()]);
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'final');
    });
    test('fixture ' + i + ' ' + cipher + '-decrypt', function (t) {
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
    test('fixture ' + i + ' ' + cipher + '-decrypt-legacy', function (t) {
      t.plan(4);
      var suite = crypto.createDecipher(cipher, new Buffer(fixture.password));
      var buf = new Buffer('');
      var suite2 = _crypto.createDecipher(cipher, new Buffer(fixture.password));
      var buf2 = new Buffer('');
      var inbuf = new Buffer(fixture.results.ciphers[cipher], 'hex');
      var mid = ~~(inbuf.length/2);
      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))]);
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))]);
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate');
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))]);
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))]);
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate 2');
      buf = Buffer.concat([buf, suite.final()]);
      buf2 = Buffer.concat([buf2, suite2.final()]);
      t.equals(buf.toString('utf8'), fixture.text);
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'final');
    });
    //var cipherivs = fixture.results.cipherivs = {};

    types.forEach(function (cipher) {
      if (modes[cipher].mode === 'ECB') {
        return;
      }
      if (isGCM(cipher) && isNode10()) {
        return;
      }
      test('fixture ' + i + ' ' + cipher + '-iv', function (t) {
        if (isGCM(cipher)) {
          t.plan(4);
        } else {
          t.plan(2);
        }
        var suite = crypto.createCipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key, isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var suite2 = _crypto.createCipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key, isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var buf = new Buffer('');
        var buf2 = new Buffer('');
        suite.on('data', function (d) {
          buf = Buffer.concat([buf, d]);
        });
        suite.on('error', function (e) {
          console.log(e);
        });
        suite2.on('data', function (d) {
          buf2 = Buffer.concat([buf2, d]);
        });
        suite2.on('error', function (e) {
          console.log(e);
        });
        suite.on("end", function () {
          t.equals(buf.toString('hex'), fixture.results.cipherivs[cipher], 'vs fixture');
          t.equals(buf.toString('hex'), buf2.toString('hex'), 'vs node');
          if (isGCM(cipher)) {
            t.equals(suite.getAuthTag().toString('hex'), fixture.authtag[cipher], 'authtag vs fixture');
            t.equals(suite.getAuthTag().toString('hex'), suite2.getAuthTag().toString('hex'), 'authtag vs node');
          }
        });
        if (isGCM(cipher)) {
          suite.setAAD(new Buffer(fixture.aad, 'hex'));
          suite2.setAAD(new Buffer(fixture.aad, 'hex'));
        }
        suite2.write(new Buffer(fixture.text));
        suite2.end();
        suite.write(new Buffer(fixture.text));
        suite.end();
      });
      
      test('fixture ' + i + ' ' + cipher + '-legacy-iv', function (t) {
        if (isGCM(cipher)) {
          t.plan(6);
        } else {
          t.plan(4);
        }
        var suite = crypto.createCipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key, isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var suite2 = _crypto.createCipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key, isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var buf = new Buffer('');
        var buf2 = new Buffer('');
        var inbuf = new Buffer(fixture.text);
        var mid = ~~(inbuf.length/2);
        if (isGCM(cipher)) {
          suite.setAAD(new Buffer(fixture.aad, 'hex'));
          suite2.setAAD(new Buffer(fixture.aad, 'hex'));
        }
        buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))]);
        buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))]);
        t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate');
        buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))]);
        buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))]);
        t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate 2');
        buf = Buffer.concat([buf, suite.final()]);
        buf2 = Buffer.concat([buf2, suite2.final()]);
        t.equals(buf.toString('hex'), fixture.results.cipherivs[cipher]);
        t.equals(buf.toString('hex'), buf2.toString('hex'), 'final');
        if (isGCM(cipher)) {
          t.equals(suite.getAuthTag().toString('hex'), fixture.authtag[cipher], 'authtag vs fixture');
          t.equals(suite.getAuthTag().toString('hex'), suite2.getAuthTag().toString('hex'), 'authtag vs node');
        }
      });
      test('fixture ' + i + ' ' + cipher + '-iv-decrypt', function (t) {
        t.plan(2);
        var suite = crypto.createDecipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key,  isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var buf = new Buffer('');
        var suite2 = _crypto.createDecipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key,  isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var buf2 = new Buffer('');
        suite.on('data', function (d) {
          buf = Buffer.concat([buf, d]);
        });
        suite.on('error', function (e) {
          t.notOk(e);
        });
        suite2.on('data', function (d) {
          buf2 = Buffer.concat([buf2, d]);
        });
        suite2.on('error', function (e) {
          t.notOk(e);
        });
        suite.on("end", function () {
            t.equals(buf.toString('utf8'), fixture.text, 'correct text vs fixture');
            t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'correct text vs node');
        });
        if (isGCM(cipher)) {
          suite.setAuthTag(new Buffer(fixture.authtag[cipher], 'hex'));
          suite2.setAuthTag(new Buffer(fixture.authtag[cipher], 'hex'));
          suite.setAAD(new Buffer(fixture.aad, 'hex'));
          suite2.setAAD(new Buffer(fixture.aad, 'hex'));
        }
        
        suite2.write(new Buffer(fixture.results.cipherivs[cipher], 'hex'));
        suite.write(new Buffer(fixture.results.cipherivs[cipher], 'hex'));
        suite2.end();
        suite.end();
      });
      test('fixture ' + i + ' ' + cipher + '-decrypt-legacy', function (t) {
        t.plan(4);
        var suite = crypto.createDecipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key,  isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var buf = new Buffer('');
        var suite2 = _crypto.createDecipheriv(cipher, ebtk(_crypto, fixture.password, modes[cipher].key).key,  isGCM(cipher) ? (new Buffer(fixture.iv, 'hex').slice(0, 12)) : (new Buffer(fixture.iv, 'hex')));
        var buf2 = new Buffer('');
        var inbuf = new Buffer(fixture.results.cipherivs[cipher], 'hex');
        var mid = ~~(inbuf.length/2);
        if (isGCM(cipher)) {
          suite.setAAD(new Buffer(fixture.aad, 'hex'));
          suite2.setAAD(new Buffer(fixture.aad, 'hex'));
          suite.setAuthTag(new Buffer(fixture.authtag[cipher], 'hex'));
          suite2.setAuthTag(new Buffer(fixture.authtag[cipher], 'hex'));
        }
        buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))]);
        buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))]);

        t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate');
        buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))]);
        buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))]);
        t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate 2');
        buf = Buffer.concat([buf, suite.final()]);
        buf2 = Buffer.concat([buf2, suite2.final()]);
        t.equals(buf.toString('utf8'), fixture.text);
        t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'final');
      });
    });
  });
});
