# Security Notes

This project was built as a learning tool and CV portfolio piece. It is intended for scanning networks you own or have explicit permission to test — not for unauthorised network reconnaissance.

## Implemented controls
- Parameterised SQL queries throughout (no string-built queries), preventing SQL injection
- Input validation on all API endpoints (network range restricted to private IPv4 /24 or smaller, timeout bounded 1-10s, device fields length-limited and whitelisted)
- CSV export sanitised against spreadsheet formula injection
- Security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Rate limiting on the scan endpoint to prevent abuse
- Secrets (SECRET_KEY) loaded from environment variables, never committed to source control
- Debug mode disabled by default; must be explicitly enabled via environment variable
- Audit logging of scans, settings changes, and failures to `ipam.log`

## Known limitations / future work
- No authentication layer — intended for single-user local use, not multi-user or internet-facing deployment
- No CSRF protection on forms — low risk currently since there's no session/login state, but would be required if authentication is added
- No HTTPS — should be placed behind a reverse proxy (e.g. nginx) with TLS if ever deployed beyond localhost