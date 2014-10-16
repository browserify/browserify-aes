var aes = require('./aes');
var Transform = require('stream').Transform;
var inherits = require('inherits');
var duplexer = require('duplexer2');
var modes = require('./modes');
var ebtk = require('./EVP_BytesToKey');
var xor = require('./xor');
inherits(Splitter, Transform);
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
  if (!this._padding) {
    this.push(this.cache);
    return next();
  }
  var len = 16 - this.cache.length;
  var padBuff = new Buffer(len);

  var i = -1;
  while (++i < len) {
    padBuff.writeUInt8(len, i);
  }
  var out = Buffer.concat([this.cache, padBuff]);
  this.push(out);
  next();
};

inherits(ECB, Transform);
function ECB(key) {
  if (!(this instanceof ECB)) {
    return new ECB(key);
  }
  Transform.call(this);
  this._cipher = new aes.AES(key);
}

ECB.prototype._transform = function (data, _, next) {
  var out = this._cipher.encryptBlock(data);
  next(null, out);
};
ECB.prototype._flush = function (next) {
  this._cipher.scrub();
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
}

CBC.prototype._transform = function (data, _, next) {
  data = xor(data, this._prev);
  this._prev = this._cipher.encryptBlock(data);
  next(null, this._prev);
};
CBC.prototype._flush = function (next) {
  this._cipher.scrub();
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
  var pad = this._cipher.encryptBlock(this._prev);
  this._prev = xor(data, pad);
  next(null, this._prev);
};
CFB.prototype._flush = function (next) {
  this._cipher.scrub();
  next();
};
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
inherits(CTR, Transform);
function CTR(key, iv) {
  if (!(this instanceof CTR)) {
    return new CTR(key, iv);
  }
  Transform.call(this);
  this._cipher = new aes.AES(key);
  this._iv = new Buffer(iv.length);
  iv.copy(this._iv);
}

CTR.prototype._transform = function (data, _, next) {
  this.push(xor(data, this._cipher.encryptBlock(this._iv)));
  this._incr32();
  next();
};
CTR.prototype._flush = function (next) {
  this._cipher.scrub();
  this._iv.fill(0);
  next();
};
CTR.prototype._incr32 = function () {
  var len = this._iv.length;
  var item;
  while (len--) {
    item = this._iv.readUInt8(len);
    if (item === 255) {
      this._iv.writeUInt8(0, len);
    } else {
      item++;
      this._iv.writeUInt8(item, len);
      break;
    }
  }
};
var modeStreams = {
  ECB: ECB,
  CBC: CBC,
  CFB: CFB,
  OFB: OFB,
  CTR: CTR
};
module.exports = function (crypto) {
  function createCipheriv(suite, password, iv) {
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
      splitter._padding = padding;
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
  function createCipher (suite, password) {
    var config = modes[suite];
    if (!config) {
      throw new TypeError('invalid suite type');
    }
    var keys = ebtk(crypto, password, config.key, config.iv);
    return createCipheriv(suite, keys.key, keys.iv);
  }
  return {
    createCipher: createCipher,
    createCipheriv: createCipheriv
  };
};
