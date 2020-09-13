import unpack from '../src'

const expected = [
  require('./data/expected0.json'),
  require('./data/expected1.json'),
  require('./data/expected2.json'),
  require('./data/expected3.json'),
]

const keys = [
  require('./data/keys0.json'),
  require('./data/keys1.json'),
  require('./data/keys2.json'),
  require('./data/keys3.json'),
]

test('output matches openssl rsa -text', function () {
  expect.assertions(keys.length * 4)

  keys.forEach(function (key, ix) {
    const priv = unpack(key.private)
    const pub = unpack(key.public)

    //console.log(unbuffer(priv), expected[ix])
    expect(unbuffer(priv)).toEqual(expected[ix])
    expect(pub.modulus).toEqual(priv.modulus)
    expect(pub.bits).toEqual(priv.bits)
    expect(pub.publicExponent).toEqual(priv.publicExponent)
  })
})

test('invalid pem data returns undefined', function () {
  expect(unpack('blah')).toEqual(undefined)
})

function unbuffer(c) {
  return Object.keys(c).reduce(function (acc, key) {
    if (c[key] instanceof ArrayBuffer) {
      acc[key] = toBase64(c[key])
    } else acc[key] = c[key]
    return acc
  }, {})
}

function toBase64(buffer: ArrayBuffer) {
  let binary = ''
  const bytes = new Uint8Array(buffer)
  const len = bytes.byteLength
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return window.btoa(binary)
}
