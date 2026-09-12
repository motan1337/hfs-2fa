'use strict'
const { test } = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const totp = require('../dist/totp')

test('RFC 6238 appendix B test vectors (SHA1, 8 digits)', () => {
    const key = Buffer.from('12345678901234567890')
    const vectors = { 59: '94287082', 1111111109: '07081804', 1111111111: '14050471',
        1234567890: '89005924', 2000000000: '69279037', 20000000000: '65353130' }
    for (const [time, expected] of Object.entries(vectors))
        assert.equal(totp.hotp(key, Math.floor(Number(time) / totp.STEP), 8), expected, 'time ' + time)
})

test('RFC 4226 appendix D test vectors (HOTP, 6 digits)', () => {
    const key = Buffer.from('12345678901234567890')
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
    expected.forEach((code, counter) => assert.equal(totp.hotp(key, counter), code))
})

test('base32 follows RFC 4648 and round-trips', () => {
    assert.equal(totp.base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI')
    assert.deepEqual(totp.base32Decode('MZXW6YTBOI======'), Buffer.from('foobar'))
    assert.deepEqual(totp.base32Decode('mzxw 6ytb-oi'), Buffer.from('foobar')) // authenticator apps show spaced keys
    for (let len = 1; len <= 64; len++) {
        const buf = crypto.randomBytes(len)
        assert.deepEqual(totp.base32Decode(totp.base32Encode(buf)), buf)
    }
    assert.throws(() => totp.base32Decode('MZXW6YTB0I')) // 0 is not in the alphabet refused instead of read as zero
    assert.throws(() => totp.base32Decode(''))
})

test('same codes as speakeasy for secrets stored by version 1 of the plugin', () => {
    const legacy = [
        { base32: 'IYSCM23FJFPHU23HHA2T4NDSM52WIQDB', codes: { 59: '067985', 1234567890: '546544', 1757600000: '767688', 2000000000: '793532' } },
        { base32: 'HAQVMXSPKBBSKRSTOR5DIXL2ERAEY3DY', codes: { 59: '928867', 1234567890: '058159', 1757600000: '110874', 2000000000: '501350' } },
        { base32: 'KJGVMT3MLY6CS3DZJJFCQ43LNYZT4R3F', codes: { 59: '336542', 1234567890: '571908', 1757600000: '103935', 2000000000: '250799' } },
    ]
    for (const { base32, codes } of legacy)
        for (const [time, expected] of Object.entries(codes)) {
            assert.equal(totp.hotp(totp.base32Decode(base32), totp.timeStep(Number(time) * 1000)), expected)
            assert.equal(totp.verify({ secret: base32, token: expected, now: Number(time) * 1000 }), totp.timeStep(Number(time) * 1000))
        }
})

test('generated secrets are 160 bit and random', () => {
    const secrets = new Set()
    for (let i = 0; i < 100; i++) {
        const secret = totp.generateSecret()
        assert.match(secret, /^[A-Z2-7]{32}$/)
        assert.equal(totp.base32Decode(secret).length, 20)
        secrets.add(secret)
    }
    assert.equal(secrets.size, 100)
})

test('verify accepts the drift window, refuses malformed tokens, and refuses replays', () => {
    const secret = totp.generateSecret()
    const key = totp.base32Decode(secret)
    const now = 1757600000_000
    const step = totp.timeStep(now)
    const token = totp.hotp(key, step)
    assert.equal(totp.verify({ secret, token, now }), step)
    assert.equal(totp.verify({ secret, token: totp.hotp(key, step - 1), now }), step - 1)
    assert.equal(totp.verify({ secret, token: totp.hotp(key, step + 1), now }), step + 1)
    assert.equal(totp.verify({ secret, token: totp.hotp(key, step - 2), now }), null)
    assert.equal(totp.verify({ secret, token: token.slice(0, 3) + ' ' + token.slice(3), now }), step)
    for (const bad of [token + 'a', token.slice(1) + 'a', token + '0', token.slice(1), '+' + token.slice(1), '1e5',
        '', ' ', null, undefined, true, [token], { toString: () => token }])
        assert.equal(totp.verify({ secret, token: bad, now }), null, 'accepted ' + JSON.stringify(bad))
    assert.equal(totp.verify({ secret, token, now, after: step }), null) // already used
    assert.equal(totp.verify({ secret, token, now, after: step - 1 }), step)
})

test('otpauth URL follows the Key Uri Format, and escapes what it embeds', () => {
    const url = totp.otpauthURL({ secret: 'JBSWY3DPEHPK3PXP', issuer: 'My HFS', account: 'al:ice&x=1' })
    assert.equal(url, 'otpauth://totp/My%20HFS:alice%26x%3D1?secret=JBSWY3DPEHPK3PXP&issuer=My%20HFS&algorithm=SHA1&digits=6&period=30')
    const parsed = new URL(url)
    assert.equal(parsed.searchParams.get('issuer'), 'My HFS')
    assert.deepEqual([...parsed.searchParams.keys()], ['secret', 'issuer', 'algorithm', 'digits', 'period'])
})
