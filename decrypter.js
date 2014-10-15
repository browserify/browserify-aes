var aes = require('./aes');
var Transform = require('stream').Transform;
var inherits = require('inherits');
var duplexer = require('duplexer2');
var modes = require('./modes');
var ebtk = require('./EVP_BytesToKey');
var xor = require('./xor');
inherits(Splitter, Transform);
function Splitter() {
  if (!(this instanceof Splitter)) {
    return new Splitter();
  }
  Transform.call(this);
  this.cache = new Buffer('');
}

Splitter.prototype._transform = function (data, _, next) {
  this.cache = Buffer.concat([this.cache, data]);
  var i = 0;
  var len = this.cache.length;
  while (i + 15 < len) {
    this.push(this.cache.slice(i, i + 16));
    i += 16;
  }
  if (i) {
    this.cache = this.cache.slice(i);
  }
  next();
};

inherits(ECB, Transform);
function ECB(key) {
  if (!(this instanceof ECB)) {
    return new ECB(key);
  }
  Transform.call(this);
  this._cipher = new aes.AES(key);
  this._last = void 0;
}

ECB.prototype._transform = function (data, _, next) {
  var last = this._last;
  if (last) {
    this.push(last);
  }
  this._last = this._cipher.decryptBlock(data);
  next(null);
};


ECB.prototype._flush = function (next) {
  this._cipher.scrub();
  var last = this._last;
  var padded = last[15];
  if (padded === 16) {
    return next();
  }
  var out = last.slice(0, 16 - padded);
  this.push(out);
  next();
};
inherits(CBC, Transform);
function CBC(key, iv) {
  if (!(this instanceof CBC)) {
    return new CBC(key, iv);
  }
  Transform.call(this);
  this._cipher = new aes.AES(key);
  this._prev = iv;
  this._last = void 0;
}

CBC.prototype._transform = function (data, _, next) {
  var indata = data;
  var out = this._cipher.decryptBlock(data);
  if (this._last) {
    this.push(this._last);
  }
  this._last = xor(out, this._prev);
  this._prev = indata;
  next();
};
CBC.prototype._flush = function (next) {
  this._cipher.scrub();
  var last = this._last;
  var padded = last[15];
  if (padded === 16) {
    return next();
  }
  var out = last.slice(0, 16 - padded);
  this.push(out);
  next();
};
var modeStreams = {
  ECB: ECB,
  CBC: CBC
};

module.exports = function (crypto) {
  function createDecipheriv(suite, password, iv) {
    var config = modes[suite];
    if (!config) {
      throw new TypeError('invalid suite type');
    }
    if (typeof iv === 'string') {
      iv = new Buffer(iv);
    }
    if (typeof password === 'string') {
      password = new Buffer(password);
    }
    if (password.length !== config.key/8) {
      throw new TypeError('invalid key length ' + password.length);
    }
    if (iv.length !== config.iv) {
      throw new TypeError('invalid iv length ' + iv.length);
    }
    var splitter = new Splitter();
    var stream = new modeStreams[config.mode](password, iv);
    splitter.pipe(stream);
    return duplexer(splitter, stream);
  }
  function createDecipher (suite, password) {
    var config = modes[suite];
    if (!config) {
      throw new TypeError('invalid suite type');
    }
    var keys = ebtk(crypto, password, config.key, config.iv);
    return createDecipheriv(suite, keys.key, keys.iv);
  }
  return {
    createDecipher: createDecipher,
    createDecipheriv: createDecipheriv
  };
};
