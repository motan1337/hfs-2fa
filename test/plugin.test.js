'use strict'
// emulates the parts of hfs the plugin interacts with (src/auth.ts setLoggedIn, src/plugins.ts listener trap and
// middleware, src/api.auth.ts login/loginSrp2, src/middlewares.ts prepareState), and checks that 2FA is really enforced.
// 3.2 is hfs up to 3.2
const { test } = require('node:test')
const assert = require('node:assert/strict')
const totp = require('../dist/totp')
const plugin = require('../dist/plugin')

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
const code = (offset = 0, secret = SECRET) => totp.hotp(totp.base32Decode(secret), totp.timeStep() + offset)
const wrongCode = () => code(-10) // outside the accepted window
const tick = () => new Promise(resolve => setImmediate(resolve))

async function setup(hfs = '3.3') {
    const veto = hfs === '3.3'
    const listeners = new Map()
    const on = (name, cb) => {
        if (!listeners.has(name)) listeners.set(name, new Set())
        listeners.get(name).add(cb)
    }
    const emit = (name, ...args) => [...listeners.get(name) || []].map(cb => cb(...args, { event: name }))
    const emitAsync = (name, ...args) => Promise.all(emit(name, ...args))
    // plugins.ts exceptions of plugins listeners are logged and ignored, returned values pass through
    const trap = cb => (...args) => {
        try {
            const ret = cb(...args)
            return ret instanceof Promise ? ret.catch(() => {}) : ret
        }
        catch {}
    }
    const accounts = { alice: { username: 'alice' }, bob: { username: 'bob' } }
    const getAccount = u => accounts[String(u || '').toLowerCase()]
    const store = new Map(), config = { issuer: 'Test HFS' }, subs = [], logs = [], fired = []
    on('login', () => fired.push('login'))
    on('failedLogin', () => fired.push('failedLogin'))
    const api = {
        Const: { API_URI: '/~/api/', API_VERSION: veto ? 13.4 : 13.1 },
        events: { on: (name, cb) => on(name, trap(cb)) },
        getAccount,
        getCurrentUsername: ctx => ctx.state.account?.username || '',
        openDb: async () => ({
            get: async k => store.get(k),
            put: async (k, v) => { store.set(k, JSON.parse(JSON.stringify(v))) },
            del: async k => { store.delete(k) },
        }),
        log: (...args) => logs.push(args.join(' ')),
        getConfig: k => config[k],
        setConfig: (k, v) => {
            config[k] = v
            for (const s of subs) if (s.k === k) s.cb(v)
        },
        subscribeConfig: (k, cb) => {
            subs.push({ k, cb })
            cb(config[k])
        },
        getHfsConfig: () => '',
    }
    const pl = await plugin.init(api)

    // auth.ts
    async function setLoggedIn(ctx, username) {
        const s = ctx.session
        delete ctx.state.usernames
        delete s.loggingIn
        const a = ctx.state.account = getAccount(username)
        if (!a) return
        const inputs = { ...ctx.state.params, ...ctx.query }
        const result = await emitAsync('finalizingLogin', { ctx, username: veto ? a.username : username, inputs })
        const error = veto && result.find(x => x && typeof x === 'string')
        if (error) {
            ctx.state.account = getAccount(s.username)
            delete ctx.state.usernames
            throw Object.assign(new Error(error), { name: 'UnauthorizedError', status: 401, expose: true }) // like koa ctx.throw
        }
        const normalized = username.toLowerCase()
        if (s.username !== normalized)
            delete s.allowNet
        if (hfs === 'changed')
            s.identity = normalized
        else
            s.username = normalized
        s.ts = Date.now()
        await emitAsync('login', ctx)
    }

    function ctxFor({ url = '/', query = {}, params, authorization = '', autoLogin, session = {} } = {}) {
        return {
            originalUrl: url, query, session, autoLogin, state: { params }, ip: '1.2.3.4', status: 404, body: undefined,
            get: header => header.toLowerCase() === 'authorization' ? authorization : '',
        }
    }

    // one http request prepareState (credentials in the request are always right here), plugins middleware, optional api
    async function request(ctx, apiHandler) {
        const s = ctx.session
        const u = ctx.get('authorization')
        let a = u && u !== s.username && getAccount(u) || !s.username && getAccount(ctx.autoLogin)
        const loggedInNotBySession = a
        ctx.state.account = a ||= getAccount(s.username)
        if (a && loggedInNotBySession)
            try {
                await setLoggedIn(ctx, a.username)
            }
            catch (e) {
                if (!veto) throw e // older hfs let it reach koa
                emit('failedLogin')
                return Object.assign(ctx, { status: 401, body: String(e) })
            }
        const after = await pl.middleware(ctx)
        if (apiHandler)
            Object.assign(ctx, await apiHandler(ctx))
        await after?.()
        return ctx
    }

    // api.auth.ts
    const loginApi = username => async ctx => {
        try {
            await setLoggedIn(ctx, getAccount(username).username)
        }
        catch (e) {
            if (veto) emit('failedLogin')
            return { status: 401, body: String(e) }
        }
        return { status: 200, body: { username: ctx.state.account?.username } }
    }
    async function srpApi(ctx) {
        const { username } = ctx.session.loggingIn // as typed by the user in loginSrp1
        try {
            await setLoggedIn(ctx, username)
        }
        catch (e) {
            emit('failedLogin')
            return { status: 401, body: String(e) }
        }
        return { status: 200, body: { username: ctx.state.account?.username } }
    }
    const loginCtx = (otp, session = {}) => ctxFor({ url: '/~/api/login', params: otp === undefined ? {} : { otp }, session })
    const message = text => veto ? 'UnauthorizedError: ' + text : text // how hfs words the refusal

    return { api, pl, store, config, logs, fired, emit, request, loginApi, srpApi, ctxFor, loginCtx, message }
}

for (const hfs of ['3.2', '3.3']) {
    const name = s => `[hfs ${hfs}] ${s}`

    test(name('accounts without 2FA log in as usual'), async () => {
        const t = await setup(hfs)
        const ctx = await t.request(t.loginCtx(undefined), t.loginApi('bob'))
        assert.equal(ctx.status, 200)
        assert.equal(ctx.session.username, 'bob')
    })

    test(name('login is refused without a valid OTP, and nothing reaches the session'), async () => {
        const t = await setup(hfs)
        t.store.set('alice', { base32: SECRET })
        const attempts = [[undefined, 'OTP required'], ['', 'OTP required'], [[code()], 'OTP required'],
            [wrongCode(), 'Invalid OTP'], [code().slice(1) + 'x', 'Invalid OTP']]
        for (const [otp, error] of attempts) {
            const ctx = await t.request(t.loginCtx(otp), t.loginApi('alice'))
            assert.equal(ctx.status, 401)
            assert.equal(ctx.body, t.message(error))
            assert.equal(ctx.session.username, undefined)
            assert.equal(ctx.state.account, undefined)
        }
        assert.ok(!t.fired.includes('login')) // the login event was never emitted
        assert.equal(t.fired.length, hfs === '3.3' ? attempts.length : 0) // failedLogin, counted by antibrute
    })

    test(name('a valid OTP logs in, and can be used only once'), async () => {
        const t = await setup(hfs)
        t.store.set('alice', { ascii: 'x', hex: 'y', base32: SECRET, otpauth_url: 'z' }) // record made by version 1
        const otp = code()
        const ok = await t.request(t.loginCtx(otp), t.loginApi('alice'))
        assert.equal(ok.status, 200)
        assert.equal(ok.session.username, 'alice')
        assert.deepEqual(t.fired, ['login'])
        assert.deepEqual(Object.keys(t.store.get('alice')).sort(), ['base32', 'lastStep']) // redundant copies of the secret dropped
        const replay = await t.request(t.loginCtx(otp), t.loginApi('alice'))
        assert.equal(replay.status, 401)
        assert.equal(replay.body, t.message('Invalid OTP'))
        const next = await t.request(t.loginCtx(code(1)), t.loginApi('alice'))
        assert.equal(next.status, 200)
    })

    test(name('SRP login with the username in a different case still requires the OTP'), async () => {
        const t = await setup(hfs)
        t.store.set('alice', { base32: SECRET })
        const srpCtx = otp => t.ctxFor({ url: '/~/api/loginSrp2', params: { otp }, session: { loggingIn: { username: 'ALICE' } } })
        const bad = await t.request(srpCtx(''), t.srpApi)
        assert.equal(bad.status, 401)
        assert.equal(bad.body, t.message('OTP required'))
        assert.equal(bad.session.username, undefined)
        assert.deepEqual(t.fired, ['failedLogin']) // counted by hfs antibrute
        const good = await t.request(srpCtx(code()), t.srpApi)
        assert.equal(good.status, 200)
        assert.equal(good.session.username, 'alice')
    })

    test(name('basic auth without ?otp= is refused with a 401 error'), async () => {
        const t = await setup(hfs)
        t.store.set('alice', { base32: SECRET })
        const attempt = t.request(t.ctxFor({ authorization: 'alice' }))
        if (hfs === '3.3') {
            const refused = await attempt
            assert.equal(refused.status, 401)
            assert.equal(refused.body, t.message('OTP required'))
            assert.equal(refused.session.username, undefined)
        }
        else
            await assert.rejects(attempt, e => e.status === 401 && e.expose && String(e) === 'OTP required')
        const ctx = await t.request(t.ctxFor({ authorization: 'alice', query: { otp: code() } }))
        assert.equal(ctx.session.username, 'alice')
        assert.equal(ctx.state.account.username, 'alice')
    })

    test(name('sessions that did not pass the OTP check are logged out'), async () => {
        const t = await setup(hfs)
        t.store.set('alice', { base32: SECRET })
        const old = await t.request(t.ctxFor({ session: { username: 'alice' } })) // other device or version 1
        assert.equal(old.state.account, undefined)
        assert.equal(old.session.username, undefined)
        const auto = await t.request(t.ctxFor({ autoLogin: 'alice' })) // auto_login_net
        assert.equal(auto.state.account, undefined)
        assert.equal(auto.session.username, undefined)
        const verified = await t.request(t.loginCtx(code()), t.loginApi('alice'))
        const next = await t.request(t.ctxFor({ session: verified.session }))
        assert.equal(next.state.account.username, 'alice')
    })

    test(name('a refused login keeps the current identity, and its verification'), async () => {
        const t = await setup(hfs)
        t.store.set('alice', { base32: SECRET })
        const other = await t.request(t.loginCtx(wrongCode(), { username: 'bob' }), t.loginApi('alice'))
        assert.equal(other.status, 401)
        assert.equal(other.session.username, 'bob')
        assert.equal((await t.request(t.ctxFor({ session: other.session }))).state.account.username, 'bob')
        const verified = await t.request(t.loginCtx(code()), t.loginApi('alice'))
        const again = await t.request(t.loginCtx(wrongCode(), verified.session), t.loginApi('alice'))
        assert.equal(again.status, 401)
        assert.equal((await t.request(t.ctxFor({ session: again.session }))).state.account?.username, 'alice')
    })

    test(name('wrong codes are throttled'), async () => {
        const t = await setup(hfs)
        t.store.set('alice', { base32: SECRET })
        for (let i = 0; i < 5; i++)
            assert.equal((await t.request(t.loginCtx(wrongCode()), t.loginApi('alice'))).body, t.message('Invalid OTP'))
        const ctx = await t.request(t.loginCtx(code()), t.loginApi('alice'))
        assert.equal(ctx.status, 401)
        assert.match(ctx.body, /Too many wrong codes/)
    })
}

test('[hfs changed] if the refusal stops working, the login is undone anyway and a warning is logged', async () => {
    const t = await setup('changed')
    t.store.set('alice', { base32: SECRET })
    const ctx = await t.request(t.loginCtx(wrongCode()), t.loginApi('alice'))
    assert.equal(ctx.status, 401)
    assert.equal(ctx.body, 'Invalid OTP')
    assert.equal(ctx.state.account, undefined)
    assert.equal(ctx.session.username, undefined)
    assert.ok(t.logs.some(x => x.includes("didn't stop HFS")))
})

test('setup must be confirmed with a code, the secret is not disclosed afterwards, disabling requires a code', async () => {
    const t = await setup()
    const ctx = t.ctxFor({ session: { username: 'alice' } })
    ctx.state.account = { username: 'alice' }
    const rest = t.pl.customRest
    const s = await rest.hfs2fa_setup({}, ctx)
    assert.match(s.secret, /^[A-Z2-7]{32}$/)
    assert.equal(s.uri, `otpauth://totp/Test%20HFS:alice?secret=${s.secret}&issuer=Test%20HFS&algorithm=SHA1&digits=6&period=30`)
    assert.match(s.qr, /^data:image\/png;base64,/)
    assert.equal((await rest.hfs2fa_setup({}, ctx)).secret, s.secret) // same pending secret until it expires
    assert.deepEqual(await rest.hfs2fa_status({}, ctx), { enabled: false })
    await assert.rejects(rest.hfs2fa_confirm({ otp: code(-10, s.secret) }, ctx), e => e === 'Invalid OTP')
    assert.deepEqual(await rest.hfs2fa_confirm({ otp: code(0, s.secret) }, ctx), { enabled: true })
    assert.equal(ctx.session.hfs2fa, 'alice') // this session stays logged in
    assert.deepEqual(await rest.hfs2fa_status({}, ctx), { enabled: true })
    await assert.rejects(rest.hfs2fa_setup({}, ctx), e => e === '2FA is already enabled')
    assert.equal(t.store.get('alice').base32, s.secret)
    await assert.rejects(rest.hfs2fa_disable({}, ctx), e => e === 'OTP required')
    await assert.rejects(rest.hfs2fa_disable({ otp: code(0, s.secret) }, ctx), e => e === 'Invalid OTP') // already used
    assert.deepEqual(await rest.hfs2fa_disable({ otp: code(1, s.secret) }, ctx), { enabled: false })
    assert.equal(t.store.has('alice'), false)
    await assert.rejects(rest.hfs2fa_status({}, t.ctxFor()), e => e === 'Not logged in')
})

test('admins can reset 2FA from the config, renamed accounts keep it', async () => {
    const t = await setup()
    t.store.set('alice', { base32: SECRET })
    t.store.set('bob', { base32: SECRET })
    t.api.setConfig('reset', ['Alice'])
    await tick()
    assert.equal(t.store.has('alice'), false)
    assert.deepEqual(t.config.reset, [])
    await Promise.all(t.emit('accountRenamed', { from: 'bob', to: 'robert' }))
    assert.equal(t.store.has('bob'), false)
    assert.equal(t.store.get('robert').base32, SECRET)
})
