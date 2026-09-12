'use strict'
const crypto = require('crypto')

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' // RFC 4648
const DIGITS = 6
const STEP = 30 // seconds
const SECRET_BYTES = 20 // 160 bits, as recommended by RFC 4226

function base32Encode(buf) {
    let out = '', bits = 0, value = 0
    for (const byte of buf) {
        value = ((value << 8) | byte) & 0xfff
        bits += 8
        while (bits >= 5) {
            bits -= 5
            out += ALPHABET[(value >>> bits) & 31]
        }
    }
    if (bits > 0)
        out += ALPHABET[(value << (5 - bits)) & 31]
    return out
}

function base32Decode(str) {
    const clean = String(str).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '')
    if (!clean || !/^[A-Z2-7]+$/.test(clean))
        throw new Error('invalid base32 secret')
    const out = []
    let bits = 0, value = 0
    for (const ch of clean) {
        value = ((value << 5) | ALPHABET.indexOf(ch)) & 0xfff
        bits += 5
        if (bits >= 8) {
            bits -= 8
            out.push((value >>> bits) & 255)
        }
    }
    return Buffer.from(out)
}

function generateSecret() {
    return base32Encode(crypto.randomBytes(SECRET_BYTES))
}

function hotp(key, counter, digits = DIGITS) {
    const msg = Buffer.alloc(8)
    msg.writeBigUInt64BE(BigInt(counter))
    const mac = crypto.createHmac('sha1', key).update(msg).digest()
    const offset = mac[mac.length - 1] & 0xf
    const code = mac.readUInt32BE(offset) & 0x7fffffff
    return String(code % 10 ** digits).padStart(digits, '0')
}

function timeStep(now = Date.now()) {
    return Math.floor(now / 1000 / STEP)
}

// returns the matching time step, or null steps up to after are refused, so the caller can prevent replays
// only tokens made exclusively of DIGITS digits are accepted (spaces are tolerated, as some apps show 123 456)
function verify({ secret, token, window = 1, now = Date.now(), after = -Infinity }) {
    if (typeof token !== 'string' && typeof token !== 'number')
        return null
    token = String(token).replace(/\s+/g, '')
    if (!new RegExp(`^\\d{${DIGITS}}$`).test(token))
        return null
    const key = base32Decode(secret)
    const expected = Buffer.from(token)
    const current = timeStep(now)
    let match = null
    for (let step = current - window; step <= current + window; step++) // no early exit, same work for any token
        if (crypto.timingSafeEqual(Buffer.from(hotp(key, step)), expected) && match === null && step > after)
            match = step
    return match
}

// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
function otpauthURL({ secret, issuer, account }) {
    const enc = s => encodeURIComponent(String(s).replace(/:/g, '')) // : separates issuer and account in the label
    return `otpauth://totp/${enc(issuer)}:${enc(account)}?secret=${secret}&issuer=${enc(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP}`
}

module.exports = { generateSecret, verify, otpauthURL, hotp, timeStep, base32Encode, base32Decode, DIGITS, STEP }
