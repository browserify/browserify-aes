var aes = require('./aes')
var Buffer = require('safe-buffer').Buffer
var Transform = require('cipher-base')
var inherits = require('inherits')
var xorInplace = require('buffer-xor/inplace')
var xorTest = require('timing-safe-equal')
function writeUIntBE (buff, value, start, length) {
  if (length > 6) {
    start += length - 6
    length = 6
  }
  buff.writeUIntBE(value, start, length)
}

function cbc (prev, data, self) {
  var rump = 16 - (data.length % 16)
  if (rump !== 16) {
    data = Buffer.concat([data, Buffer.alloc(rump)])
  }
  var place = 0
  while (place < data.length) {
    xorInplace(prev, data.slice(place, place + 16))
    place += 16
    prev = self._cipher.encryptBlock(prev)
  }
  return prev
}
function StreamCipher (mode, key, iv, decrypt, options) {
  Transform.call(this)

  if (!options || !options.authTagLength) throw new Error('options authTagLength is required')

  if (options.authTagLength < 4 || options.authTagLength > 16 || options.authTagLength % 2 === 1) throw new Error('authTagLength must be one of 4, 6, 8, 10, 12, 14 or 16')

  if (iv.length < 7 || iv.length > 13) throw new Error('iv must be between 7 and 13 bytes')

  this._n = iv.length
  this._l = 15 - this._n
  this._cipher = new aes.AES(key)
  this.authTagLength = options.authTagLength
  this._mode = mode
  this._add = null
  this._decrypt = decrypt
  this._authTag = null
  this._called = false
  this._plainLength = null
  this._prev = null
  this._iv = iv
  this._cache = Buffer.allocUnsafe(0)
  this._failed = false
  this._firstBlock = null
}
function validSize (ivLen, chunkLen) {
  if (ivLen === 13 && chunkLen >= 65536) {
    return false
  }
  if (ivLen === 12 && chunkLen >= 16777216) {
    return false
  }
  return true
}
inherits(StreamCipher, Transform)
function createTag (self, data) {
  var firstBlock = self._firstBlock
  if (!firstBlock) {
    firstBlock = Buffer.alloc(16)
    firstBlock[0] = ((self.authTagLength - 2) / 2) * 8 + self._l - 1
    self._iv.copy(firstBlock, 1)
    writeUIntBE(firstBlock, data.length, self._n + 1, self._l)
    firstBlock = self._cipher.encryptBlock(firstBlock)
  }
  return cbc(firstBlock, data, self)
}
StreamCipher.prototype._update = function (chunk) {
  if (this._called) throw new Error('Trying to add data in unsupported state')

  if (!validSize(this._iv.length, chunk.length)) throw new Error('Message exceeds maximum size')

  if (this._plainLength !== null && this._plainLength !== chunk.length) throw new Error('Trying to add data in unsupported state')

  this._called = true
  this._prev = Buffer.alloc(16)
  this._prev[0] = this._l - 1
  this._iv.copy(this._prev, 1)
  var toXor
  if (this._decrypt) {
    toXor = this._mode.encrypt(this, Buffer.alloc(16)).slice(0, this.authTagLength)
  } else {
    this._authTag = this._mode.encrypt(this, createTag(this, chunk)).slice(0, this.authTagLength)
  }
  var out = this._mode.encrypt(this, chunk)
  if (this._decrypt) {
    var rawAuth = createTag(this, out).slice(0, this.authTagLength)
    xorInplace(rawAuth, toXor)
    this._failed = !xorTest(rawAuth, this._authTag)
  }
  this._cipher.scrub()
  return out
}

StreamCipher.prototype._final = function () {
  if (this._decrypt && !this._authTag) throw new Error('Unsupported state or unable to authenticate data')

  if (this._failed) throw new Error('Unsupported state or unable to authenticate data')
}

StreamCipher.prototype.getAuthTag = function getAuthTag () {
  if (this._decrypt || !Buffer.isBuffer(this._authTag)) throw new Error('Attempting to get auth tag in unsupported state')

  return this._authTag
}

StreamCipher.prototype.setAuthTag = function setAuthTag (tag) {
  if (!this._decrypt) throw new Error('Attempting to set auth tag in unsupported state')

  this._authTag = tag
}

StreamCipher.prototype.setAAD = function setAAD (buf, options) {
  if (this._called) throw new Error('Attempting to set AAD in unsupported state')

  if (!options || !options.plaintextLength) throw new Error('options plaintextLength is required')

  if (!validSize(this._iv.length, options.plaintextLength)) throw new Error('Message exceeds maximum size')

  this._plainLength = options.plaintextLength

  if (!buf.length) return

  var firstBlock = Buffer.alloc(16)
  firstBlock[0] = 64 + ((this.authTagLength - 2) / 2) * 8 + this._l - 1
  this._iv.copy(firstBlock, 1)
  writeUIntBE(firstBlock, options.plaintextLength, this._n + 1, this._l)
  firstBlock = this._cipher.encryptBlock(firstBlock)

  var la = buf.length
  var ltag
  if (la < 65280) {
    ltag = Buffer.allocUnsafe(2)
    ltag.writeUInt16BE(la, 0)
  } else if (la < 4294967296) {
    ltag = Buffer.allocUnsafe(6)
    ltag[0] = 0xff
    ltag[1] = 0xfe
    ltag.writeUInt32BE(la, 2)
  } else {
    ltag = Buffer.alloc(10)
    ltag[0] = 0xff
    ltag[1] = 0xff
    ltag.writeUIntBE(la, 4, 6)
  }
  var aToAuth = Buffer.concat([ltag, buf])
  this._firstBlock = cbc(firstBlock, aToAuth, this)
}

module.exports = StreamCipher
