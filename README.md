# HFS 2FA Authentication

This plugin adds TOTP two factor authentication to HFS logins, with any authenticator app
(Google Authenticator, Aegis, Authy, 1Password, etc)

Requires HFS with plugin API 12.3 or newer.

## Enabling it

Click the user icon in the top left corner, then Enable, scan the QR code with your app,
and type the code it shows to confirm. 2FA is active only after that confirmation, so you cannot
lock yourself out by closing the page halfway.

From then on, the login form asks for a code beside username and password.

To turn it off, open the same panel and click Disable a valid code is required.

![](https://github.com/user-attachments/assets/89e0c41b-6a74-4c6a-becc-072517c72d97)

![](https://github.com/user-attachments/assets/8edb44a7-7949-4242-8fa7-de18da0e48e4)

![](https://github.com/user-attachments/assets/e4f4ea64-ac6a-4274-84ea-9a1078c5f99f)

![](https://github.com/user-attachments/assets/c7514e29-eaf2-4901-85d2-f8919d0cbc79)

## Configuration

- Issuer: the name shown in the authenticator app. If empty, the host of base_url is used,
  otherwise "HFS".
- Reset 2FA: for users who lost their authenticator. Select the accounts and save their 2FA is
  removed and the field empties itself. This is the recovery procedure, so keep at least one admin
  account able to reach the admin panel.

## What it protects, and what it does not

A code is required by every login that goes through HFS login APIs, including the SRP login used by
the web UI. Sessions that never passed the check are logged out on their next request, so enabling 2FA
also kicks out sessions of that account opened elsewhere, including sessions opened before 2FA existed.

Some HFS features cannot carry a code, and for an account with 2FA they behave as follows:

- HTTP basic auth, WebDAV clients, and ?login=user:pass urls are refused with 401, unless the
  request also carries the current code as ?otp=123456. A code can be used only once, so this is not
  practical for WebDAV, prefer an account without 2FA for those clients, or turn off HFS
  authorization_header setting.
- The admin panel login form has no field for the code (plugins do not extend it). Log in from the
  main page first, then open the admin panel, the session is shared.
- auto_login_net accounts are not logged in at all once they enable 2FA, they have to use the
  login form.
- localhost_admin (on by default) gives full admin access from the machine running HFS with no
  login at all, and therefore no 2FA. Turn it off if you don't want that.

Secrets are stored in plain text in plugins/hfs-2fa/storage/2fa, as HFS storage has no encryption
protect that file and your backups the way you protect the accounts file.

## Upgrading from version 1

Existing enrollments keep working, the codes are unchanged. All sessions of accounts with 2FA are
logged out once, because version 1 did not actually verify anything (see below) and its sessions
cannot be trusted.

Version 1 did not protect accounts at all on current HFS, exceptions thrown by a plugin inside the
finalizingLogin event are swallowed by HFS, so the login always completed, with a wrong code or
none. It could also be bypassed by typing the username with a different letter case. Version 2
enforces the check on every login path, refuses reused codes, throttles wrong ones, and requires a
code to disable 2FA.

## Development

```
npm ci          # dependencies of the build
npm test        # RFC 6238 test vectors, and the login flows against an emulated HFS
npm run build   # rebuilds dist/qrcode.js
```

dist/ is the plugin itself plugin.js (backend), public/main.js (frontend), totp.js
(RFC 6238, only uses node:crypto) and the bundled qrcode.js
