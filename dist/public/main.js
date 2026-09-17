(() => { // own scope nothing leaks into the page globals
    'use strict'
    const { h, Btn } = HFS
    const { useState, useEffect, useRef } = HFS.React
    const CODE_INPUT = { inputMode: 'numeric', autoComplete: 'one-time-code', pattern: '[0-9 ]*', maxLength: 7, placeholder: '123456' }

    HFS.onEvent('beforeLoginSubmit', () => h(LoginField))
    HFS.onEvent('userPanelAfterInfo', () => h(Panel))

    // the login form sends all its named fields, so the server finds this as otp
    function LoginField() {
        return h('div', { className: 'field' },
            h('label', { htmlFor: 'otp' }, 'OTP'),
            h('input', { id: 'otp', name: 'otp', type: 'text', ...CODE_INPUT }),
            h('p', { style: { fontSize: '0.8em' } }, 'Code from your authenticator app. Leave empty if you did not enable 2FA.'))
    }

    function Panel() {
        const [status, setStatus] = useState(null)
        const [setup, setSetup] = useState(null)
        const [busy, setBusy] = useState(false)
        const mounted = useRef(true)
        const working = useRef(false)
        useEffect(() => {
            refresh()
            return () => { mounted.current = false }
        }, [])

        if (!status)
            return h('div', { style: styles.box }, '2FA: loading…')
        if (status.error)
            return h('div', { style: styles.box }, '2FA: ', status.error)
        if (setup)
            return h('div', { style: styles.box },
                h('b', null, 'Set up 2FA'),
                h('div', null, 'Scan the QR code with your authenticator app, then enter the code it shows to confirm.'),
                setup.qr && h('img', { src: setup.qr, alt: 'QR code to scan with the authenticator app', style: styles.qr }),
                h('div', { style: styles.secret }, 'Or enter this key manually: ', h('code', null, setup.secret)),
                h(CodeForm, { busy, onSubmit: confirm, onCancel: cancel }))
        return h('div', { style: styles.box },
            h('div', { style: styles.row },
                h('b', null, status.enabled ? '2FA is enabled' : '2FA is disabled'),
                h(Btn, { label: status.enabled ? 'Disable' : 'Enable', style: styles.button, onClick: status.enabled ? disable : enable })))

        function refresh() {
            return call('status').then(res => mounted.current && setStatus(res),
                err => mounted.current && setStatus({ error: message(err) }))
        }

        // one operation at a time and errors are shown instead of being eatten
        async function exclusive(job) {
            if (working.current) return
            working.current = true
            setBusy(true)
            try { await job() }
            catch (err) { toast(message(err), 'error') }
            finally {
                working.current = false
                if (mounted.current) setBusy(false)
            }
        }

        function enable() {
            return exclusive(async () => {
                const res = await call('setup')
                if (mounted.current) setSetup(res)
            })
        }

        function confirm(otp) {
            return exclusive(async () => {
                await call('confirm', { otp })
                toast('2FA enabled', 'success')
                if (!mounted.current) return
                setSetup(null)
                await refresh()
            })
        }

        function cancel() {
            return exclusive(async () => {
                await call('cancel')
                if (mounted.current) setSetup(null)
            })
        }

        function disable() {
            return exclusive(async () => {
                const otp = await ask('Enter a code from your authenticator app to disable 2FA')
                if (!otp) return
                await call('disable', { otp })
                toast('2FA disabled', 'success')
                if (mounted.current) await refresh()
            })
        }
    }

    function CodeForm({ busy, onSubmit, onCancel }) {
        const [otp, setOtp] = useState('')
        const submit = () => otp.trim() && onSubmit(otp)
        return h('div', { style: styles.row },
            h('input', {
                ...CODE_INPUT,
                value: otp,
                autoFocus: true,
                'aria-label': 'Code',
                style: styles.input,
                onChange: ev => setOtp(ev.target.value),
                onKeyDown(ev) {
                    if (ev.key !== 'Enter') return
                    ev.preventDefault()
                    ev.stopPropagation()
                    submit()
                },
            }),
            h('button', { type: 'button', disabled: busy || !otp.trim(), onClick: submit }, 'Confirm'),
            h('button', { type: 'button', disabled: busy, onClick: onCancel }, 'Cancel'))
    }

    function call(name, params) {
        return HFS.customRestCall('hfs2fa_' + name, params)
    }

    function message(err) {
        return err?.message || String(err)
    }

    function toast(msg, type) {
        if (HFS.toast) HFS.toast(msg, type)
        else alert(msg)
    }

    function ask(msg) {
        const prompt = HFS.dialogLib?.promptDialog
        return prompt ? prompt(msg, { inputProps: CODE_INPUT }) : Promise.resolve(window.prompt(msg))
    }

    const styles = {
        box: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '.5em', textAlign: 'center' },
        row: { display: 'flex', alignItems: 'center', justifyContent: 'center', flexWrap: 'wrap', gap: '.5em' },
        button: { marginLeft: '1em' },
        qr: { maxWidth: '100%' },
        secret: { wordBreak: 'break-all' },
        input: { width: '7em', textAlign: 'center' },
    }
})()
