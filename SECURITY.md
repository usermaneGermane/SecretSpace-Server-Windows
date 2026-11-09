# Security policy

SecretSpace keeps passwords, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
the repository's **Security** tab -> **Report a vulnerability**.

Include what you found, the version (`server\version.py`), and the steps to
reproduce it. You will get an answer within a week. Please give a reasonable
time for a fix before you publish anything.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Pre-releases (alpha) | Best effort; they are test versions |
| Older releases | No; please update first |

## Scope

The sync server in this repository: the token check, request handling, the
stored vault blobs, the setup (firewall rules, token and certificate files)
and the service. Client issues go to the client repositories, the same way.
