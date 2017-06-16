var Buffer = require('safe-buffer').Buffer
var test = require('tape')
var fixtures = require('./fixtures.json')
var _crypto = require('crypto')
var crypto = require('../browser.js')
var modes = require('../modes')
var types = Object.keys(modes)
var ebtk = require('evp_bytestokey')

function isGCM (cipher) {
  return modes[cipher].mode === 'GCM'
}

function isNode10 () {
  return process.version && process.version.split('.').length === 3 && parseInt(process.version.split('.')[1], 10) <= 10
}

fixtures.forEach(function (fixture, i) {
  types.forEach(function (cipher) {
    if (isGCM(cipher)) return

    test('fixture ' + i + ' ' + cipher, function (t) {
      t.plan(1)
      var suite = crypto.createCipher(cipher, Buffer.from(fixture.password))
      var buf = Buffer.alloc(0)
      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d])
      })
      suite.on('error', function (e) {
        console.log(e)
      })
      suite.on('end', function () {
        // console.log(fixture.text)
        // decriptNoPadding(cipher, Buffer.from(fixture.password), buf.toString('hex'), 'a')
        // decriptNoPadding(cipher, Buffer.from(fixture.password), fixture.results.ciphers[cipher], 'b')
        t.equals(buf.toString('hex'), fixture.results.ciphers[cipher])
      })
      suite.write(Buffer.from(fixture.text))
      suite.end()
    })

    test('fixture ' + i + ' ' + cipher + '-legacy', function (t) {
      t.plan(3)
      var suite = crypto.createCipher(cipher, Buffer.from(fixture.password))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createCipher(cipher, Buffer.from(fixture.password))
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(fixture.text)
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
      var suite = crypto.createDecipher(cipher, Buffer.from(fixture.password))
      var buf = Buffer.alloc(0)
      suite.on('data', function (d) {
        buf = Buffer.concat([buf, d])
      })
      suite.on('error', function (e) {
        console.log(e)
      })
      suite.on('end', function () {
        // console.log(fixture.text)
        // decriptNoPadding(cipher, Buffer.from(fixture.password), buf.toString('hex'), 'a')
        // decriptNoPadding(cipher, Buffer.from(fixture.password), fixture.results.ciphers[cipher], 'b')
        t.equals(buf.toString('utf8'), fixture.text)
      })
      suite.write(Buffer.from(fixture.results.ciphers[cipher], 'hex'))
      suite.end()
    })

    test('fixture ' + i + ' ' + cipher + '-decrypt-legacy', function (t) {
      t.plan(4)
      var suite = crypto.createDecipher(cipher, Buffer.from(fixture.password))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createDecipher(cipher, Buffer.from(fixture.password))
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(fixture.results.ciphers[cipher], 'hex')
      var mid = ~~(inbuf.length / 2)
      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))])
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate')
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))])
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate 2')
      buf = Buffer.concat([buf, suite.final()])
      buf2 = Buffer.concat([buf2, suite2.final()])
      t.equals(buf.toString('utf8'), fixture.text)
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'final')
    })
  })

  types.forEach(function (cipher) {
    if (modes[cipher].mode === 'ECB') return
    if (isGCM(cipher) && isNode10()) return

    test('fixture ' + i + ' ' + cipher + '-iv', function (t) {
      t.plan(isGCM(cipher) ? 4 : 2)

      var suite = crypto.createCipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
      var suite2 = _crypto.createCipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
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
        t.equals(buf.toString('hex'), fixture.results.cipherivs[cipher], 'vs fixture')
        t.equals(buf.toString('hex'), buf2.toString('hex'), 'vs node')
        if (isGCM(cipher)) {
          t.equals(suite.getAuthTag().toString('hex'), fixture.authtag[cipher], 'authtag vs fixture')
          t.equals(suite.getAuthTag().toString('hex'), suite2.getAuthTag().toString('hex'), 'authtag vs node')
        }
      })

      if (isGCM(cipher)) {
        suite.setAAD(Buffer.from(fixture.aad, 'hex'))
        suite2.setAAD(Buffer.from(fixture.aad, 'hex'))
      }

      suite2.write(Buffer.from(fixture.text))
      suite2.end()
      suite.write(Buffer.from(fixture.text))
      suite.end()
    })

    test('fixture ' + i + ' ' + cipher + '-legacy-iv', function (t) {
      t.plan(isGCM(cipher) ? 6 : 4)

      var suite = crypto.createCipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
      var suite2 = _crypto.createCipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
      var buf = Buffer.alloc(0)
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(fixture.text)
      var mid = ~~(inbuf.length / 2)
      if (isGCM(cipher)) {
        suite.setAAD(Buffer.from(fixture.aad, 'hex'))
        suite2.setAAD(Buffer.from(fixture.aad, 'hex'))
      }

      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate')
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'intermediate 2')
      buf = Buffer.concat([buf, suite.final()])
      buf2 = Buffer.concat([buf2, suite2.final()])
      t.equals(buf.toString('hex'), fixture.results.cipherivs[cipher])
      t.equals(buf.toString('hex'), buf2.toString('hex'), 'final')
      if (isGCM(cipher)) {
        t.equals(suite.getAuthTag().toString('hex'), fixture.authtag[cipher], 'authtag vs fixture')
        t.equals(suite.getAuthTag().toString('hex'), suite2.getAuthTag().toString('hex'), 'authtag vs node')
      }
    })

    test('fixture ' + i + ' ' + cipher + '-iv-decrypt', function (t) {
      t.plan(2)

      var suite = crypto.createDecipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createDecipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
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
        t.equals(buf.toString('utf8'), fixture.text, 'correct text vs fixture')
        t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'correct text vs node')
      })

      if (isGCM(cipher)) {
        suite.setAuthTag(Buffer.from(fixture.authtag[cipher], 'hex'))
        suite2.setAuthTag(Buffer.from(fixture.authtag[cipher], 'hex'))
        suite.setAAD(Buffer.from(fixture.aad, 'hex'))
        suite2.setAAD(Buffer.from(fixture.aad, 'hex'))
      }

      suite2.write(Buffer.from(fixture.results.cipherivs[cipher], 'hex'))
      suite.write(Buffer.from(fixture.results.cipherivs[cipher], 'hex'))
      suite2.end()
      suite.end()
    })
    test('fixture ' + i + ' ' + cipher + '-decrypt-legacy', function (t) {
      t.plan(4)
      var suite = crypto.createDecipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
      var buf = Buffer.alloc(0)
      var suite2 = _crypto.createDecipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, isGCM(cipher) ? (Buffer.from(fixture.iv, 'hex').slice(0, 12)) : (Buffer.from(fixture.iv, 'hex')))
      var buf2 = Buffer.alloc(0)
      var inbuf = Buffer.from(fixture.results.cipherivs[cipher], 'hex')
      var mid = ~~(inbuf.length / 2)
      if (isGCM(cipher)) {
        suite.setAAD(Buffer.from(fixture.aad, 'hex'))
        suite2.setAAD(Buffer.from(fixture.aad, 'hex'))
        suite.setAuthTag(Buffer.from(fixture.authtag[cipher], 'hex'))
        suite2.setAuthTag(Buffer.from(fixture.authtag[cipher], 'hex'))
      }
      buf = Buffer.concat([buf, suite.update(inbuf.slice(0, mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(0, mid))])

      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate')
      buf = Buffer.concat([buf, suite.update(inbuf.slice(mid))])
      buf2 = Buffer.concat([buf2, suite2.update(inbuf.slice(mid))])
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'intermediate 2')
      buf = Buffer.concat([buf, suite.final()])
      buf2 = Buffer.concat([buf2, suite2.final()])
      t.equals(buf.toString('utf8'), fixture.text)
      t.equals(buf.toString('utf8'), buf2.toString('utf8'), 'final')
    })
  })
})

if (!isNode10()) {
  test('node tests', function (t) {
    var TEST_CASES = [
      { algo: 'aes-128-gcm',
        key: '6970787039613669314d623455536234',
        iv: '583673497131313748307652',
        plain: 'Hello World!',
        ct: '4BE13896F64DFA2C2D0F2C76',
        tag: '272B422F62EB545EAA15B5FF84092447',
        tampered: false },
      { algo: 'aes-128-gcm',
        key: '6970787039613669314d623455536234',
        iv: '583673497131313748307652',
        plain: 'Hello World!',
        ct: '4BE13896F64DFA2C2D0F2C76',
        aad: '000000FF',
        tag: 'BA2479F66275665A88CB7B15F43EB005',
        tampered: false },
      { algo: 'aes-128-gcm',
        key: '6970787039613669314d623455536234',
        iv: '583673497131313748307652',
        plain: 'Hello World!',
        ct: '4BE13596F64DFA2C2D0FAC76',
        tag: '272B422F62EB545EAA15B5FF84092447',
        tampered: true },
      { algo: 'aes-256-gcm',
        key: '337a54767a7233703637564336316a6d56353472495975313534357834546c59',
        iv: '36306950306836764a6f4561',
        plain: 'Hello node.js world!',
        ct: '58E62CFE7B1D274111A82267EBB93866E72B6C2A',
        tag: '9BB44F663BADABACAE9720881FB1EC7A',
        tampered: false },
      { algo: 'aes-256-gcm',
        key: '337a54767a7233703637564336316a6d56353472495975313534357834546c59',
        iv: '36306950306836764a6f4561',
        plain: 'Hello node.js world!',
        ct: '58E62CFF7B1D274011A82267EBB93866E72B6C2B',
        tag: '9BB44F663BADABACAE9720881FB1EC7A',
        tampered: true },
      { algo: 'aes-192-gcm',
        key: '1ed2233fa2223ef5d7df08546049406c7305220bca40d4c9',
        iv: '0e1791e9db3bd21a9122c416',
        plain: 'Hello node.js world!',
        password: 'very bad password',
        aad: '63616c76696e',
        ct: 'DDA53A4059AA17B88756984995F7BBA3C636CC44',
        tag: 'D2A35E5C611E5E3D2258360241C5B045',
        tampered: false }
    ]

    var ciphers = Object.keys(modes)
    function testIt (i) {
      t.test('test case ' + i, function (t) {
        var test = TEST_CASES[i]

        if (ciphers.indexOf(test.algo) === -1) {
          console.log('skipping unsupported ' + test.algo + ' test')
          return
        }

        (function () {
          var encrypt = crypto.createCipheriv(test.algo,
            Buffer.from(test.key, 'hex'), Buffer.from(test.iv, 'hex'))
          if (test.aad) encrypt.setAAD(Buffer.from(test.aad, 'hex'))

          var hex = encrypt.update(test.plain, 'ascii', 'hex')
          hex += encrypt.final('hex')
          var authTag = encrypt.getAuthTag()

          // only test basic encryption run if output is marked as tampered.
          if (!test.tampered) {
            t.equal(hex.toUpperCase(), test.ct)
            t.equal(authTag.toString('hex').toUpperCase(), test.tag)
          }
        })()

        ;(function () {
          var decrypt = crypto.createDecipheriv(test.algo,
            Buffer.from(test.key, 'hex'), Buffer.from(test.iv, 'hex'))
          decrypt.setAuthTag(Buffer.from(test.tag, 'hex'))
          if (test.aad) decrypt.setAAD(Buffer.from(test.aad, 'hex'))
          var msg = decrypt.update(test.ct, 'hex', 'ascii')
          if (!test.tampered) {
            msg += decrypt.final('ascii')
            t.equal(msg, test.plain)
          } else {
            // assert that final throws if input data could not be verified!
            t.throws(function () { decrypt.final('ascii') }, / auth/)
          }
        })()

        ;(function () {
          if (!test.password) return
          var encrypt = crypto.createCipher(test.algo, test.password)
          if (test.aad) encrypt.setAAD(Buffer.from(test.aad, 'hex'))
          var hex = encrypt.update(test.plain, 'ascii', 'hex')
          hex += encrypt.final('hex')
          var authTag = encrypt.getAuthTag()
          // only test basic encryption run if output is marked as tampered.
          if (!test.tampered) {
            t.equal(hex.toUpperCase(), test.ct)
            t.equal(authTag.toString('hex').toUpperCase(), test.tag)
          }
        })()

        ;(function () {
          if (!test.password) return
          var decrypt = crypto.createDecipher(test.algo, test.password)
          decrypt.setAuthTag(Buffer.from(test.tag, 'hex'))
          if (test.aad) decrypt.setAAD(Buffer.from(test.aad, 'hex'))
          var msg = decrypt.update(test.ct, 'hex', 'ascii')
          if (!test.tampered) {
            msg += decrypt.final('ascii')
            t.equal(msg, test.plain)
          } else {
            // assert that final throws if input data could not be verified!
            t.throws(function () { decrypt.final('ascii') }, / auth/)
          }
        })()

        // after normal operation, test some incorrect ways of calling the API:
        // it's most certainly enough to run these tests with one algorithm only.

        if (i > 0) {
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
          var encrypt = crypto.createCipheriv(test.algo,
            Buffer.from(test.key, 'hex'), Buffer.from(test.iv, 'hex'))
          encrypt.update('blah', 'ascii')
          t.throws(function () { encrypt.getAuthTag() }, / state/)
        })()

        ;(function () {
          // trying to set tag on encryption object:
          var encrypt = crypto.createCipheriv(test.algo,
            Buffer.from(test.key, 'hex'), Buffer.from(test.iv, 'hex'))
          t.throws(function () {
            encrypt.setAuthTag(Buffer.from(test.tag, 'hex'))
          }, / state/)
        })()

        ;(function () {
          // trying to read tag from decryption object:
          var decrypt = crypto.createDecipheriv(test.algo,
            Buffer.from(test.key, 'hex'), Buffer.from(test.iv, 'hex'))
          t.throws(function () { decrypt.getAuthTag() }, / state/)
        })()
        t.end()
      })
    }

    for (var i in TEST_CASES) {
      testIt(i)
    }
  })
}

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

var sixteens = Buffer.alloc(16, 16)
corectPaddingWords(sixteens, Buffer.alloc(0))
var fifteens = Buffer.alloc(16, 15)
fifteens[0] = 5
corectPaddingWords(fifteens, Buffer.from([5]))
var one = _crypto.randomBytes(16)
one[15] = 1
corectPaddingWords(one, one.slice(0, -1))
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

var sixteens2 = Buffer.alloc(16, 16)
sixteens2[3] = 5
incorectPaddingthrows(sixteens2)
incorectPaddingDoesNotThrow(sixteens2)
var fifteens2 = Buffer.alloc(16, 15)
fifteens2[0] = 5
fifteens2[1] = 6
incorectPaddingthrows(fifteens2)
incorectPaddingDoesNotThrow(fifteens2)
var two = _crypto.randomBytes(16)
two[15] = 2
two[14] = 1
incorectPaddingthrows(two)
incorectPaddingDoesNotThrow(two)

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
