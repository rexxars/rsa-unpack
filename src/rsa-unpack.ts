/* eslint-disable no-bitwise */
export default function unpackRsa(pem: string): PublicKey | PrivateKey | undefined {
  const [, keyType] = /^-----BEGIN RSA (PRIVATE|PUBLIC) KEY-----/.exec(pem) || []
  if (!keyType) {
    return undefined
  }

  const type = keyType.toLowerCase()

  if (pem.split('\n').slice(-2)[0] !== `-----END RSA ${keyType} KEY-----`) {
    return undefined
  }

  const content = pem.split('\n').slice(1, -2).join('')
  const buf = fromBase64(content)
  const view = new DataView(buf)

  const first = view.getUint8(1)
  const privateOffset = first & 0x80 ? first - 0x80 + 5 : 7
  const publicOffset = first & 0x80 ? first - 0x80 + 2 : 2
  let offset = type === 'private' ? privateOffset : publicOffset

  function read(): ArrayBuffer {
    let seek = view.getUint8(offset + 1)

    if (seek & 0x80) {
      const nudge = seek - 0x80
      seek = nudge - 1 === 0 ? view.getUint8(offset + 2) : view.getUint16(offset + 2, false)
      offset += nudge
    }

    offset += 2

    const chunk = buf.slice(offset, offset + seek)
    offset += seek
    return chunk
  }

  const modulus = read()

  const publicKey: PublicKey = {
    modulus,
    bits: (modulus.byteLength - 1) * 8 + Math.ceil(Math.log(byte(modulus, 0) + 1) / Math.log(2)),
    publicExponent: parseInt(buf2hex(read()), 16),
  }

  if (type === 'public') {
    return publicKey
  }

  return {
    ...publicKey,
    privateExponent: toBase64(read()),
    prime1: toBase64(read()),
    prime2: toBase64(read()),
    exponent1: toBase64(read()),
    exponent2: toBase64(read()),
    coefficient: toBase64(read()),
  }
}

function fromBase64(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const len = binary.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
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

function byte(buf: ArrayBuffer, index: number): number {
  return new DataView(buf).getUint8(index)
}

function buf2hex(buffer: ArrayBuffer) {
  return Array.prototype.map
    .call(new Uint8Array(buffer), (x) => `00${x.toString(16)}`.slice(-2))
    .join('')
}

export interface PublicKey {
  modulus: ArrayBuffer
  bits: number
  publicExponent: number
}

export type PrivateKey = PublicKey & {
  privateExponent: string
  prime1: string
  prime2: string
  exponent1: string
  exponent2: string
  coefficient: string
}
