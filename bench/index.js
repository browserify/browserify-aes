let Benchmark = require('benchmark')
let _local = require('../browser')
let _npm = require('browserify-aes/browser')
let key = Buffer.alloc(16, 0xff)
let iv = Buffer.alloc(16, 0x01)

function test (mod, message) {
  let cipher = mod.createCipheriv('aes-128-ctr', key, iv)
  let b = cipher.update(message)
  return Buffer.concat([b, cipher.final()])
}

let local = (m) => test(_local, m)
let npm = (m) => test(_npm, m)

function run (message) {
  if (
    local(message).toString('hex') !==
    npm(message).toString('hex')
  ) throw new Error('not equal')

  new Benchmark.Suite()
  .add('local', () => local(message))
  .add('npm', () => npm(message))
  .on('cycle', (e) => console.log(String(e.target)))
  .run()
}

let lorem = Buffer.allocUnsafe(800)
run(lorem.slice(0, 20), key)
run(lorem.slice(0, 80), key)
run(lorem, key)
