var aes = require('./aes');
var Transform = require('stream').Transform;
var inherits = require('inherits');
var duplexer = require('duplexer2');
var modes = require('./modes');
var ebtk = require('./EVP_BytesToKey');
var xor = require('./xor');
inherits(Splitter, Transform);
function unpad(last) {
  var padded = last[15];
  if (padded === 16) {
    return;
  }
  return last.slice(0, 16 - padded);
}
function Splitter(padding) {
  if (!(this instanceof Splitter)) {
    return new Splitter(padding);
  }
  if (padding === false) {
    this._padding = false;
  } else {
    this._padding = true;
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
Splitter.prototype._flush = function (next) {
  if (this._padding === false) {
    this.push(this.cache);
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
  this._pad = true;
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
  if (this._pad === false) {
    if (this._last) {
      this.push(this._last);
    }
    return next();
  }
  var depadded = unpad(this._last);
  if (depadded) {
    this.push(depadded);
  }
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
  this._pad = true;
  next();
};
CBC.prototype._flush = function (next) {
  this._cipher.scrub();
  if (this._pad === false) {
    if (this._last) {
      this.push(this._last);
    }
    return next();
  }
  var depadded = unpad(this._last);
  if (depadded) {
    this.push(depadded);
  }
  next();
};
inherits(CFB, Transform);
function CFB(key, iv) {
  if (!(this instanceof CFB)) {
    return new CFB(key, iv);
  }
  Transform.call(this);
  this._cipher = new aes.AES(key);
  this._prev = iv;
}

CFB.prototype._transform = function (data, _, next) {
  // yes encrypt
  var pad = this._cipher.encryptBlock(this._prev);
  this._prev = data;
  next(null, xor(pad, data));
};
CFB.prototype._flush = function (next) {
  this._cipher.scrub();
  next();
};

//the same as encryption
inherits(OFB, Transform);
function OFB(key, iv) {
  if (!(this instanceof OFB)) {
    return new OFB(key, iv);
  }
  Transform.call(this);
  this._cipher = new aes.AES(key);
  this._prev = iv;
}

OFB.prototype._transform = function (data, _, next) {
  this._prev = this._cipher.encryptBlock(this._prev);
  next(null, xor(data, this._prev));
};
OFB.prototype._flush = function (next) {
  this._cipher.scrub();
  next();
};

var modeStreams = {
  ECB: ECB,
  CBC: CBC,
  CFB: CFB,
  OFB: OFB
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
    var splitter = new Splitter(config.padding);
    var stream = new modeStreams[config.mode](password, iv);
    splitter.on('data', function (d) {
      stream.write(d);
    });
    splitter.on('finish', function () {
      stream.end();
    });
    var out = duplexer(splitter, stream);
    out.setAutoPadding = function (padding) {
      stream._padding = padding;
    };
    out._legacy = false;
    var outData = new Buffer('');
    out.update = function (data, inputEnd, outputEnc) {
      if (out._legacy === false) {
        out._legacy = true;
        stream.on('data', function (chunk) {
          outData = Buffer.concat([outData, chunk]);
        });
        stream.pause = function (){
          // else it will stall out
        };
      }
      splitter.write(data, inputEnd);
      var ourData = outData;
      outData = new Buffer('');
      if (outputEnc) {
        ourData = ourData.toString(outputEnc);
      }
      return ourData;
    };
    out.final = function (outputEnc) {
      splitter.end();
      var ourData = outData;
      outData = null;
      if (outputEnc) {
        ourData = ourData.toString(outputEnc);
      }
      return ourData;
    };
    return out;
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
