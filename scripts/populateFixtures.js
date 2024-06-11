var modes = require('../modes/list.json')
var fixtures = require('../test/fixtures.json')
var crypto = require('crypto')
var types = ['aes-128-ccm', 'aes-192-ccm', 'aes-256-ccm']
var ebtk = require('evp_bytestokey')
var fs = require('fs')

fixtures.forEach(function (fixture) {
  types.forEach(function (cipher) {
    var suite2 = crypto.createCipheriv(cipher, ebtk(fixture.password, false, modes[cipher].key).key, new Buffer(fixture.iv, 'hex').slice(0, 12), {
      authTagLength: 16
    })
    var text = Buffer.from(fixture.text)
    var aad = Buffer.from(fixture.aad, 'hex')
    console.log('aad', aad)
    suite2.setAAD(aad, {
      plaintextLength: text.length
    })
    var buf2 = suite2.update(text)
    suite2.final()
    fixture.results.cipherivs[cipher] = buf2.toString('hex')
    fixture.authtag[cipher] = suite2.getAuthTag().toString('hex')
  })
})
fs.writeFileSync('./test/fixturesNew.json', JSON.stringify(fixtures, false, 4))
