exports.version = 2
exports.description = "Two factor authentication (TOTP) for HFS logins, works with Google Authenticator, Aegis, Authy and similar apps"
exports.apiRequired = 12.3 // finalizingLogin, beforeLoginSubmit, HFS.Btn
exports.frontend_js = ['main.js']
exports.repo = "damienzonly/hfs-2fa"
exports.preview = ["https://github.com/user-attachments/assets/c7514e29-eaf2-4901-85d2-f8919d0cbc79","https://github.com/user-attachments/assets/89e0c41b-6a74-4c6a-becc-072517c72d97","https://github.com/user-attachments/assets/8edb44a7-7949-4242-8fa7-de18da0e48e4","https://github.com/user-attachments/assets/e4f4ea64-ac6a-4274-84ea-9a1078c5f99f"]
exports.changelog = [
    { "version": 2, "message": "Security fixes: 2FA was not enforced on recent HFS versions, and could be bypassed by typing the username with different letter case. Added replay protection, throttling of wrong codes, confirmation of new setups, a code to disable 2FA, admin reset. Replaced the deprecated speakeasy library." }
]

exports.config = {
    issuer: {
        type: 'string',
        label: 'Issuer',
        helperText: 'Name shown in the authenticator app. If empty, the host of base_url is used, otherwise "HFS"',
    },
    reset: {
        type: 'username',
        multiple: true,
        groups: false,
        label: 'Reset 2FA',
        helperText: 'For users who lost their authenticator selected accounts get their 2FA removed when you save, then this field empties itself',
    },
}

exports.init = async api => {
    const totp = require('./totp')
    const qr = require('./qrcode')
    const db = await api.openDb('2fa') 

    const MARK = 'hfs2fa' 
    const DENIED = Symbol('hfs2fa denied')
    const RESTORE = Symbol('hfs2fa restore')
    const OTP_REQUIRED = 'OTP required'
    const WINDOW = 1 // accepted clock drift, in 30 seconds steps
    const FREE_ATTEMPTS = 5 
    const THROTTLE_BASE = 30_000, THROTTLE_MAX = 15 * 60_000
    const SETUP_TTL = 10 * 60_000
    const LOGIN_API = (api.Const?.API_URI || '/~/api/') + 'login' 
    const failures = new Map() // username { count, until }
    const lastSteps = new Map() // username last accepted time step, stops concurrent replays before the db is updated
    const setups = new Map() // username { secret, expires }, waiting for confirmation

    // hfs ignores exceptions thrown by plugins event listeners, so throwing here would not stop the login
    api.events.on('finalizingLogin', async ({ ctx, username, inputs }) => {
        // credentials in this request? otherwise the login comes from the configuration, like auto_login_net
        const hard = ctx.originalUrl.startsWith(LOGIN_API) || 'login' in ctx.query || Boolean(ctx.get('authorization'))
        try {
            delete ctx.session[MARK]
            // the event carries the username as typed (e.g. admin with srp login), while our records use the canonical one
            const user = api.getAccount(username)?.username
            const record = user && await db.get(user)
            if (!record) return
            const error = await checkOtp(user, record, inputs?.otp)
            if (!error) {
                ctx.session[MARK] = user
                return // nothing what a listener returns may get a meaning in future HFS versions
            }
            if (hard && error !== OTP_REQUIRED)
                api.log(`login of ${user} from ${ctx.ip} refused: ${error}`)
            denyLogin(ctx, error, hard)
        }
        catch (e) {
            api.log(`2FA check failed: ${e?.message || e}`)
            denyLogin(ctx, '2FA check failed', hard)
        }
    })

    api.events.on('accountRenamed', async ({ from, to }) => {
        const record = await db.get(from)
        if (!record || await db.get(to)) return
        await db.put(to, record)
        await db.del(from)
        forget(from)
        api.log(`2FA moved from ${from} to ${to}`)
    })

    api.subscribeConfig('reset', async list => {
        list = [].concat(list || []).filter(Boolean)
        if (!list.length) return
        try {
            for (const name of list) {
                const user = api.getAccount(name)?.username || name
                forget(user)
                if (!await db.get(user)) continue
                await db.del(user)
                api.log(`2FA removed by admin for ${user}`)
            }
        }
        catch (e) {
            api.log(`2FA reset failed: ${e?.message || e}`)
        }
        api.setConfig('reset', [])
    })

    return {
        async middleware(ctx) {
            await enforce(ctx)
            return () => enforce(ctx, true)
        },
        customRest: {
            hfs2fa_status: rest(async (params, ctx) => {
                return { enabled: Boolean(await db.get(currentUser(ctx))) }
            }),
            hfs2fa_setup: rest(async (params, ctx) => {
                const user = currentUser(ctx)
                if (await db.get(user)) throw '2FA is already enabled'
                let setup = setups.get(user)
                if (!(setup?.expires > Date.now()))
                    setups.set(user, setup = { secret: totp.generateSecret(), expires: Date.now() + SETUP_TTL })
                const uri = totp.otpauthURL({ secret: setup.secret, issuer: getIssuer(), account: user })
                let image = null // the key can still be typed manually if the QR cannot be produced
                try { image = await qr.toDataURL(uri) }
                catch {}
                return { secret: setup.secret, uri, qr: image }
            }),
            hfs2fa_confirm: rest(async (params, ctx) => {
                const user = currentUser(ctx)
                const setup = setups.get(user)
                if (!(setup?.expires > Date.now())) throw 'Setup expired, please start again'
                const wait = throttled(user)
                if (wait) throw wait
                const step = totp.verify({ secret: setup.secret, token: params?.otp, window: WINDOW })
                if (step === null) throw failed(user)
                setups.delete(user)
                failures.delete(user)
                lastSteps.set(user, step)
                await db.put(user, { base32: setup.secret, lastStep: step, created: new Date().toISOString() })
                ctx.session[MARK] = user // this session stays, other sessions of the account will be logged out
                api.log(`2FA enabled for ${user}`)
                return { enabled: true }
            }),
            hfs2fa_cancel: rest(async (params, ctx) => {
                setups.delete(currentUser(ctx))
                return {}
            }),
            hfs2fa_disable: rest(async (params, ctx) => {
                const user = currentUser(ctx)
                const record = await db.get(user)
                if (!record) throw '2FA is not enabled'
                const error = await checkOtp(user, record, params?.otp)
                if (error) throw error
                await db.del(user)
                api.log(`2FA disabled for ${user}`)
                return { enabled: false }
            }),
        },
    }

    // an error escaping a customRest handler is sent to the client complete with its stack trace, so only strings get out
    function rest(handler) {
        return async (params, ctx) => {
            try {
                return await handler(params, ctx)
            }
            catch (e) {
                if (typeof e === 'string') throw e
                api.log(`2FA request failed: ${e?.message || e}`)
                throw 'Unexpected error'
            }
        }
    }

    function currentUser(ctx) {
        const user = api.getCurrentUsername(ctx)
        if (!user) throw 'Not logged in'
        return user
    }

    // returns an error message, or nothing if the code is valid, in which case it is consumed and cant be used again
    async function checkOtp(user, record, otp) {
        const wait = throttled(user)
        if (wait) return wait
        if (typeof otp !== 'string' && typeof otp !== 'number' || !String(otp).trim())
            return OTP_REQUIRED
        const after = Math.max(record.lastStep ?? -Infinity, lastSteps.get(user) ?? -Infinity)
        const step = totp.verify({ secret: record.base32, token: otp, window: WINDOW, after })
        if (step === null)
            return failed(user)
        lastSteps.set(user, step)
        failures.delete(user)
        await db.put(user, { base32: record.base32, lastStep: step, created: record.created }) // also drops the redundant copies stored by version 1
    }

    function throttled(user) {
        const wait = (failures.get(user)?.until || 0) - Date.now()
        if (wait > 0)
            return `Too many wrong codes, try again in ${Math.ceil(wait / 1000)} seconds`
    }

    function failed(user) {
        const count = (failures.get(user)?.count || 0) + 1
        const delay = count < FREE_ATTEMPTS ? 0 : Math.min(THROTTLE_BASE * 2 ** (count - FREE_ATTEMPTS), THROTTLE_MAX)
        failures.set(user, { count, until: Date.now() + delay })
        return 'Invalid OTP'
    }

    function forget(user) {
        for (const map of [failures, lastSteps, setups])
            map.delete(user)
    }

    function denyLogin(ctx, message, hard) {
        ctx.state[DENIED] = message
        const s = ctx.session
        if (!hard || !s) return // without credentials in the request we let the login finish, and our middleware undoes it
        // setLoggedIn() proceeds assigning session.username we make that assignment throw, so the login stops before the
        // session is saved and before the login event, and hfs answers 401 with our message
        const prev = Object.getOwnPropertyDescriptor(s, 'username')
        const restore = ctx.state[RESTORE] = () => {
            delete ctx.state[RESTORE]
            delete s.username
            if (prev)
                Object.defineProperty(s, 'username', prev)
        }
        Object.defineProperty(s, 'username', {
            configurable: true,
            enumerable: true,
            get: () => prev?.value,
            set() {
                restore()
                delete ctx.state.account
                throw Object.assign(new Error(message), { name: '', status: 401, expose: true }) // name='' makes String(error) just the message
            },
        })
    }

    // defense in depth, on every request an account with 2FA must have passed our check in this session, whatever
    // the way it logged in this also logs out sessions opened before 2FA was enabled, or with version 1 of this plugin.
    async function enforce(ctx, upstream) {
        try {
            if (ctx.state[RESTORE]) { // still there = hfs never assigned session.username, so our refusal didnt stop it
                ctx.state[RESTORE]()
                api.log("warning: refusing a login didn't stop HFS, the login is being undone here instead. Please report this with your HFS version")
            }
            const user = api.getCurrentUsername(ctx)
            if (!user || ctx.session?.[MARK] === user) return
            if (!await has2fa(user)) return
        }
        catch (e) {
            api.log(`2FA enforcement failed: ${e?.message || e}`)
        }
        delete ctx.state.account
        delete ctx.state.usernames
        const s = ctx.session
        if (s) {
            delete s.username
            delete s[MARK]
            delete s.allowNet
        }
        if (upstream && ctx.status < 400) {
            ctx.status = 401
            ctx.body = ctx.state[DENIED] || OTP_REQUIRED
        }
    }

    async function has2fa(user) {
        try {
            return Boolean(await db.get(user))
        }
        catch {
            return true // fail closed
        }
    }

    // never derived from the Host header of the request, as that is chosen by the client
    function getIssuer() {
        let issuer = api.getConfig('issuer')
        const base = !issuer && api.getHfsConfig('base_url')
        if (base)
            try { issuer = new URL(/^\w+:\/\//.test(base) ? base : 'http://' + base).hostname }
            catch {}
        return String(issuer || '').replace(/:/g, '').trim().slice(0, 64) || 'HFS'
    }
}
