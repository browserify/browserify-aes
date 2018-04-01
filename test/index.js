var Buffer = require('safe-buffer').Buffer
var test = require('tape')
var fixtures = require('./fixtures.json')
var fixtures2 = require('./extra.json')
var _crypto = require('crypto')
var crypto = require('../browser.js')
var modes = require('../modes')
var CIPHERS = Object.keys(modes)
var ebtk = require('evp_bytestokey')

function isGCM (cipher) {
  return modes[cipher].mode === 'GCM'
}

function isNode10 () {
  return process.version && process.version.split('.').length === 3 && parseInt(process.version.split('.')[1], 10) <= 10
}

fixtures.forEach(function (f, i) {
  CIPHERS.forEach(function (cipher) {
    if (isGCM(cipher)) return

    test('fixture ' + i + ' ' + cipher, function (t) {
      t.plan(1)
      var suite = crypto.createCipher(cipher, Buffer.from(f.password))
      var buf = Buffer.alloc(0)
      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d])
      })
      suite.on('error', function (e) {
        console.log(e)
      })
      suite.on('end', function () {
        // console.log(f.text)
        // decriptNoPadding(cipher, Buffer.from(f.password), buf.toString('hex'), 'a')
        // decriptNoPadding(cipher, Buffer.from(f.password), f.results.ciphers[cipher], 'b')
        t.equals(buf.toString('hex'), f.results.ciphers[cipher])
      })
      suite.write(Buffer.from(f.text))
      suite.end()
    })

    test('fixture ' + i + ' ' + cipher + '-legacy', function (t) {
      t.plan(3)
      var suite = crypto.createCipher(cipher, Buffer.from(f.password))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createCipher(cipher, Buffer.from(f.password))
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(f.text)
      var mid = ~~(inbuf.length / 2)
      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate')
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate 2')
      buf = Buffer.concat([buf, suite.final()])
      buf2 = Buffer.concat([buf2, suite2.final()])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'final')
    })

    test('fixture ' + i + ' ' + cipher + '-decrypt', function (t) {
      t.plan(1)
      var suite = crypto.createDecipher(cipher, Buffer.from(f.password))
      var buf = Buffer.alloc(0)
      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d])
      })
      suite.on('error', function (e) {
        console.log(e)
      })
      suite.on('end', function () {
        // console.log(f.text)
        // decriptNoPadding(cipher, Buffer.from(f.password), buf.toString('hex'), 'a')
        // decriptNoPadding(cipher, Buffer.from(f.password), f.results.ciphers[cipher], 'b')
        t.equals(buf.toString('utf8'), f.text)
      })
      suite.write(Buffer.from(f.results.ciphers[cipher], 'hex'))
      suite.end()
    })

    test('fixture ' + i + ' ' + cipher + '-decrypt-legacy', function (t) {
      t.plan(4)
      var suite = crypto.createDecipher(cipher, Buffer.from(f.password))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createDecipher(cipher, Buffer.from(f.password))
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(f.results.ciphers[cipher], 'hex')
      var mid = ~~(inbuf.length / 2)
      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))])
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate')
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))])
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate 2')
      buf = Buffer.concat([buf, suite.final()])
      buf2 = Buffer.concat([buf2, suite2.final()])
      t.equals(buf.toString('utf8'), f.text)
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'final')
    })
  })

  CIPHERS.forEach(function (cipher) {
    if (modes[cipher].mode === 'ECB') return
    if (isGCM(cipher) && isNode10()) return

    test('fixture ' + i + ' ' + cipher + '-iv', function (t) {
      t.plan(isGCM(cipher) ? 4 : 2)

      var suite = crypto.createCipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var suite2 = _crypto.createCipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var buf = Buffer.alloc(0)
      var buf2 = Buffer.alloc(0)

      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d])
      })

      suite.on('error', function (e) {
        console.log(e)
      })

      suite2.on('data', function (d) {
        buf2 = Buffer.concat([buf2, d])
      })

      suite2.on('error', function (e) {
        console.log(e)
      })

      suite.on('end', function () {
        t.equals(buf.toString('hex'), f.results.cipherivs[cipher], 'vs fixture')
        t.equals(buf.toString('hex'), buf2.toString('hex'), 'vs node')
        if (isGCM(cipher)) {
          t.equals(suite.getAuthTag().toString('hex'), f.authtag[cipher], 'authtag vs fixture')
          t.equals(suite.getAuthTag().toString('hex'), suite2.getAuthTag().toString('hex'), 'authtag vs node')
        }
      })

      if (isGCM(cipher)) {
        suite.setAAD(Buffer.from(f.aad, 'hex'))
        suite2.setAAD(Buffer.from(f.aad, 'hex'))
      }

      suite2.write(Buffer.from(f.text))
      suite2.end()
      suite.write(Buffer.from(f.text))
      suite.end()
    })

    test('fixture ' + i + ' ' + cipher + '-legacy-iv', function (t) {
      t.plan(isGCM(cipher) ? 6 : 4)

      var suite = crypto.createCipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var suite2 = _crypto.createCipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var buf = Buffer.alloc(0)
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(f.text)
      var mid = ~~(inbuf.length / 2)
      if (isGCM(cipher)) {
        suite.setAAD(Buffer.from(f.aad, 'hex'))
        suite2.setAAD(Buffer.from(f.aad, 'hex'))
      }

      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate')
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate 2')
      buf = Buffer.concat([buf, suite.final()])
      buf2 = Buffer.concat([buf2, suite2.final()])
      t.equals(buf.toString('hex'), f.results.cipherivs[cipher])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'final')
      if (isGCM(cipher)) {
        t.equals(suite.getAuthTag().toString('hex'), f.authtag[cipher], 'authtag vs fixture')
        t.equals(suite.getAuthTag().toString('hex'), suite2.getAuthTag().toString('hex'), 'authtag vs node')
      }
    })

    test('fixture ' + i + ' ' + cipher + '-iv-decrypt', function (t) {
      t.plan(2)

      var suite = crypto.createDecipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createDecipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var buf2 = Buffer.alloc(0)

      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d])
      })

      suite.on('error', function (e) {
        t.notOk(e)
      })

      suite2.on('data', function (d) {
        buf2 = Buffer.concat([buf2, d])
      })

      suite2.on('error', function (e) {
        t.notOk(e)
      })

      suite.on('end', function () {
        t.equals(buf.toString('utf8'), f.text, 'correct text vs fixture')
        t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'correct text vs node')
      })

      if (isGCM(cipher)) {
        suite.setAuthTag(Buffer.from(f.authtag[cipher], 'hex'))
        suite2.setAuthTag(Buffer.from(f.authtag[cipher], 'hex'))
        suite.setAAD(Buffer.from(f.aad, 'hex'))
        suite2.setAAD(Buffer.from(f.aad, 'hex'))
      }

      suite2.write(Buffer.from(f.results.cipherivs[cipher], 'hex'))
      suite.write(Buffer.from(f.results.cipherivs[cipher], 'hex'))
      suite2.end()
      suite.end()
    })
    test('fixture ' + i + ' ' + cipher + '-decrypt-legacy', function (t) {
      t.plan(4)
      var suite = crypto.createDecipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createDecipheriv(cipher, ebtk(f.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(f.iv, 'hex').slice(0, 12)) : (Buffer.from(f.iv, 'hex')))
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(f.results.cipherivs[cipher], 'hex')
      var mid = ~~(inbuf.length / 2)
      if (isGCM(cipher)) {
        suite.setAAD(Buffer.from(f.aad, 'hex'))
        suite2.setAAD(Buffer.from(f.aad, 'hex'))
        suite.setAuthTag(Buffer.from(f.authtag[cipher], 'hex'))
        suite2.setAuthTag(Buffer.from(f.authtag[cipher], 'hex'))
      }
      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))])

      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate')
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))])
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate 2')
      buf = Buffer.concat([buf, suite.final()])
      buf2 = Buffer.concat([buf2, suite2.final()])
      t.equals(buf.toString('utf8'), f.text)
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'final')
    })
  })
})

fixtures2.forEach((f, i) => {
  test('test case ' + i, function (t) {
    if (CIPHERS.indexOf(f.algo) === -1) {
      console.log('skipping unsupported ' + f.algo + ' test')
      return
    }

    (function () {
      var encrypt = crypto.createCipheriv(f.algo,
        Buffer.from(f.key, 'hex'), Buffer.from(f.iv, 'hex'))
      if (f.aad) encrypt.setAAD(Buffer.from(f.aad, 'hex'))

      var hex = encrypt.update(f.plain, 'ascii', 'hex')
      hex += encrypt.final('hex')
      var authTag = encrypt.getAuthTag()

      // only test basic encryption run if output is marked as tampered.
      if (!f.tampered) {
        t.equal(hex.toUpperCase(), f.ct)
        t.equal(authTag.toString('hex').toUpperCase(), f.tag)
      }
    })()

    ;(function () {
      var decrypt = crypto.createDecipheriv(f.algo,
        Buffer.from(f.key, 'hex'), Buffer.from(f.iv, 'hex'))
      decrypt.setAuthTag(Buffer.from(f.tag, 'hex'))
      if (f.aad) decrypt.setAAD(Buffer.from(f.aad, 'hex'))
      var msg = decrypt.update(f.ct, 'hex', 'ascii')
      if (!f.tampered) {
        msg += decrypt.final('ascii')
        t.equal(msg, f.plain)
      } else {
        // assert that final throws if input data could not be verified!
        t.throws(function () { decrypt.final('ascii') }, / auth/)
      }
    })()

    ;(function () {
      if (!f.password) return
      var encrypt = crypto.createCipher(f.algo, f.password)
      if (f.aad) encrypt.setAAD(Buffer.from(f.aad, 'hex'))
      var hex = encrypt.update(f.plain, 'ascii', 'hex')
      hex += encrypt.final('hex')
      var authTag = encrypt.getAuthTag()
      // only test basic encryption run if output is marked as tampered.
      if (!f.tampered) {
        t.equal(hex.toUpperCase(), f.ct)
        t.equal(authTag.toString('hex').toUpperCase(), f.tag)
      }
    })()

    ;(function () {
      if (!f.password) return
      var decrypt = crypto.createDecipher(f.algo, f.password)
      decrypt.setAuthTag(Buffer.from(f.tag, 'hex'))
      if (f.aad) decrypt.setAAD(Buffer.from(f.aad, 'hex'))
      var msg = decrypt.update(f.ct, 'hex', 'ascii')
      if (!f.tampered) {
        msg += decrypt.final('ascii')
        t.equal(msg, f.plain)
      } else {
        // assert that final throws if input data could not be verified!
        t.throws(function () { decrypt.final('ascii') }, / auth/)
      }
    })()

    // after normal operation, test some incorrect ways of calling the API:
    // it's most certainly enough to run these tests with one algorithm only.
    if (i !== 0) {
      t.end()
      return
    }

    (function () {
      // non-authenticating mode:
      var encrypt = crypto.createCipheriv('aes-128-cbc',
        'ipxp9a6i1Mb4USb4', '6fKjEjR3Vl30EUYC')
      encrypt.update('blah', 'ascii')
      encrypt.final()
      t.throws(function () { encrypt.getAuthTag() })
      t.throws(function () {
        encrypt.setAAD(Buffer.from('123', 'ascii'))
      })
    })()

    ;(function () {
      // trying to get tag before inputting all data:
      var encrypt = crypto.createCipheriv(f.algo,
        Buffer.from(f.key, 'hex'), Buffer.from(f.iv, 'hex'))
      encrypt.update('blah', 'ascii')
      t.throws(function () { encrypt.getAuthTag() }, / state/)
    })()

    ;(function () {
      // trying to set tag on encryption object:
      var encrypt = crypto.createCipheriv(f.algo,
        Buffer.from(f.key, 'hex'), Buffer.from(f.iv, 'hex'))
      t.throws(function () {
        encrypt.setAuthTag(Buffer.from(f.tag, 'hex'))
      }, / state/)
    })()

    ;(function () {
      // trying to read tag from decryption object:
      var decrypt = crypto.createDecipheriv(f.algo,
        Buffer.from(f.key, 'hex'), Buffer.from(f.iv, 'hex'))
      t.throws(function () { decrypt.getAuthTag() }, / state/)
    })()
    t.end()
  })
})

test('autopadding false decipher', function (t) {
  t.plan(2)
  var mycipher = crypto.createCipher('AES-128-ECB', Buffer.from('password'))
  var nodecipher = _crypto.createCipher('AES-128-ECB', Buffer.from('password'))
  var myEnc = mycipher.final()
  var nodeEnc = nodecipher.final()
  t.equals(myEnc.toString('hex'), nodeEnc.toString('hex'), 'same encryption')
  var decipher = crypto.createDecipher('aes-128-ecb', Buffer.from('password'))
  decipher.setAutoPadding(false)
  var decipher2 = _crypto.createDecipher('aes-128-ecb', Buffer.from('password'))
  decipher2.setAutoPadding(false)
  t.equals(decipher.update(myEnc).toString('hex'), decipher2.update(nodeEnc).toString('hex'), 'same decryption')
})

test('autopadding false cipher throws', function (t) {
  t.plan(2)

  var mycipher = crypto.createCipher('aes-128-ecb', Buffer.from('password'))
  mycipher.setAutoPadding(false)
  var nodecipher = _crypto.createCipher('aes-128-ecb', Buffer.from('password'))
  nodecipher.setAutoPadding(false)
  mycipher.update('foo')
  nodecipher.update('foo')
  t.throws(function () {
    mycipher.final()
  }, /data not multiple of block length/)
  t.throws(function () {
    nodecipher.final()
  }, /./)
})

test('getCiphers works', function (t) {
  t.plan(1)
  t.ok(crypto.getCiphers().length, 'get some ciphers')
})

test('correctly handle incremental base64 output', function (t) {
  t.plan(2)

  var encoding = 'base64'
  function encrypt (data, key, algorithm) {
    algorithm = algorithm || 'aes256'
    var cipher = crypto.createCipher(algorithm, key)
    var part1 = cipher.update(data, 'utf8', encoding)
    var part2 = cipher.final(encoding)
    return part1 + part2
  }

  function encryptNode (data, key, algorithm) {
    algorithm = algorithm || 'aes256'
    var cipher = _crypto.createCipher(algorithm, key)
    var part1 = cipher.update(data, 'utf8', encoding)
    var part2 = cipher.final(encoding)
    return part1 + part2
  }

  function decrypt (data, key, algorithm) {
    algorithm = algorithm || 'aes256'
    var decipher = crypto.createDecipher(algorithm, key)
    return decipher.update(data, encoding, 'utf8') + decipher.final('utf8')
  }

  var key = 'this is a very secure key'
  var data = 'The quick brown fox jumps over the lazy dog.'
  var encrypted = encrypt(data, key)
  t.equals(encrypted, encryptNode(data, key), 'encrypt correctly')
  var decrypted = decrypt(encrypted, key)
  t.equals(data, decrypted, 'round trips')
})

var gcmTest = [
  {
    key: '68d010dad5295e1f4f485f35cff46c35d423797bf4cd536d4943d787e00f6f07',
    length: 8,
    answer: '44d0f292',
    tag: '1f21c63664fc5262827b9624dee894bd',
    ivFill: 9
  },
  {
    key: '9ba693ec61afc9b7950f9177780b3533126af40a7596c662e26e6d6bbf536030',
    length: 16,
    answer: '1c8f8783',
    tag: '2d2b33f509153a8afc973cf9fc983800',
    ivFill: 1
  },
  {
    key: 'dad2a11c52614e4402f0f126028d5e55b50b3a9d6d006cfbee79b77e4a4ee7b9',
    length: 21,
    ivFill: 2,
    answer: '1a8dd3ed',
    tag: '68ce0e40ee335388c0468813b8e5eb4b'
  },
  {
    key: '4c062c7bd7566bec4c509e3bf0c9cc2acb75a863403b04fdce025ba26b6a6ca2',
    length: 43,
    ivFill: 5,
    answer: '5f6ccc8c',
    tag: '9a0d845168a1491e17217a20a75defb0'
  }
]
function testIV (t, length, answer, tag, key, ivFill) {
  t.test('key length ' + length, function (t) {
    t.plan(3)
    var iv = Buffer.alloc(length, ivFill)
    var cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    var out = cipher.update('fooo').toString('hex')
    t.equals(out, answer)
    cipher.final()
    t.equals(tag, cipher.getAuthTag().toString('hex'))
    var decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(Buffer.from(tag, 'hex'))
    var decrypted = decipher.update(Buffer.from(answer, 'hex'))
    t.equals(decrypted.toString(), 'fooo')
  })
}
test('different IV lengths work for GCM', function (t) {
  gcmTest.forEach(function (item) {
    testIV(t, item.length, item.answer, item.tag, Buffer.from(item.key, 'hex'), item.ivFill)
  })
})
test('handle long uft8 plaintexts', function (t) {
  t.plan(1)
  var salt = Buffer.alloc(32, 0)

  function encrypt (txt) {
    var cipher = crypto.createCipher('aes-256-cbc', salt)
    return cipher.update(txt, 'utf8', 'base64') + cipher.final('base64')
  }

  function decrypt (enc) {
    var decipher = crypto.createDecipher('aes-256-cbc', salt)
    return decipher.update(enc, 'base64', 'utf8') + decipher.final('utf8')
  }

  var input = 'ふっかつ　あきる　すぶり　はやい　つける　まゆげ　たんさん　みんぞく　ねほりはほり　せまい　たいまつばな　ひはん'
  var enc = encrypt(input, 'a')

  var dec = decrypt(enc, 'a')
  t.equals(dec, input)
})

test('mix and match encoding', function (t) {
  t.plan(2)
  var cipher = crypto.createCipher('aes-256-cbc', 'a')
  cipher.update('foo', 'utf8', 'utf8')
  t.throws(function () {
    cipher.update('foo', 'utf8', 'base64')
  })
  cipher = crypto.createCipher('aes-256-cbc', 'a')
  cipher.update('foo', 'utf8', 'base64')
  t.doesNotThrow(function () {
    cipher.update('foo', 'utf8')
    cipher.final('base64')
  })
})

function corectPaddingWords (padding, result) {
  test('correct padding ' + padding.toString('hex'), function (t) {
    t.plan(1)
    var block1 = Buffer.alloc(16, 4)
    result = block1.toString('hex') + result.toString('hex')
    var cipher = _crypto.createCipher('aes128', Buffer.from('password'))
    cipher.setAutoPadding(false)
    var decipher = crypto.createDecipher('aes128', Buffer.from('password'))
    var out = Buffer.alloc(0)
    out = Buffer.concat([out, cipher.update(block1)])
    out = Buffer.concat([out, cipher.update(padding)])
    var deciphered = decipher.update(out)
    deciphered = Buffer.concat([deciphered, decipher.final()])
    t.equals(deciphered.toString('hex'), result)
  })
}

function incorectPaddingthrows (padding) {
  test('incorrect padding ' + padding.toString('hex'), function (t) {
    t.plan(2)
    var block1 = Buffer.alloc(16, 4)
    var cipher = crypto.createCipher('aes128', Buffer.from('password'))
    cipher.setAutoPadding(false)
    var decipher = crypto.createDecipher('aes128', Buffer.from('password'))
    var decipher2 = _crypto.createDecipher('aes128', Buffer.from('password'))
    var out = Buffer.alloc(0)
    out = Buffer.concat([out, cipher.update(block1)])
    out = Buffer.concat([out, cipher.update(padding)])
    decipher.update(out)
    decipher2.update(out)
    t.throws(function () {
      decipher.final()
    }, 'mine')
    t.throws(function () {
      decipher2.final()
    }, 'node')
  })
}

function incorectPaddingDoesNotThrow (padding) {
  test('stream incorrect padding ' + padding.toString('hex'), function (t) {
    t.plan(2)
    var block1 = Buffer.alloc(16, 4)
    var cipher = crypto.createCipher('aes128', Buffer.from('password'))
    cipher.setAutoPadding(false)
    var decipher = crypto.createDecipher('aes128', Buffer.from('password'))
    var decipher2 = _crypto.createDecipher('aes128', Buffer.from('password'))
    cipher.pipe(decipher)
    cipher.pipe(decipher2)
    cipher.write(block1)
    cipher.write(padding)
    decipher.on('error', function (e) {
      t.ok(e, 'mine')
    })
    decipher2.on('error', function (e) {
      t.ok(e, 'node')
    })
    cipher.end()
  })
}

var sixteens = Buffer.alloc(16, 16)
var fifteens = Buffer.alloc(16, 15)
fifteens[0] = 5
var one = _crypto.randomBytes(16)
one[15] = 1
var sixteens2 = Buffer.alloc(16, 16)
sixteens2[3] = 5
var fifteens2 = Buffer.alloc(16, 15)
fifteens2[0] = 5
fifteens2[1] = 6
var two = _crypto.randomBytes(16)
two[15] = 2
two[14] = 1
var zeroes = Buffer.alloc(16)
var seventeens = Buffer.alloc(16, 17)
var ff = Buffer.alloc(16, 0xff)

corectPaddingWords(sixteens, Buffer.alloc(0))
corectPaddingWords(fifteens, Buffer.from([5]))
corectPaddingWords(one, one.slice(0, -1))
;[sixteens2, fifteens2, two, zeroes, seventeens, ff].forEach((x) => {
  incorectPaddingthrows(x)
  incorectPaddingDoesNotThrow(x)
})
