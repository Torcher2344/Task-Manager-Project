# Recon Skill

## Objective
Build a reproducible recon pipeline with graceful fallback when external tools are missing.

## Windows-first pipeline
1. **Subdomain enumeration**
   - Tool path: `subfinder.exe`
   - Command:
     ```powershell
     subfinder -silent -d example.com | Out-File -Encoding utf8 recon\subdomains.txt
     ```
   - Fallback:
     ```python
     seeds = ["www", "api", "admin", "dev", "staging"]
     ```

2. **Live host probing**
   - Tool: `httpx`
   - Command:
     ```powershell
     httpx -silent -l recon\subdomains.txt | Out-File -Encoding utf8 recon\live_hosts.txt
     ```
   - Fallback: async `aiohttp` GET probes for `https://` then `http://`.

3. **Crawling**
   - Tool: `katana`
   - Command:
     ```powershell
     katana -list recon\live_hosts.txt -silent | Out-File -Encoding utf8 recon\katana_urls.txt
     ```
   - Fallback: parse landing pages and script/link tags with BeautifulSoup.

4. **Historical URLs**
   - waybackurls:
     ```powershell
     Get-Content recon\live_hosts.txt | waybackurls | Out-File -Encoding utf8 recon\wayback_urls.txt
     ```
   - gau:
     ```powershell
     gau --subs example.com | Out-File -Encoding utf8 recon\gau_urls.txt
     ```
   - Fallback: rely on in-app crawled endpoints only.

5. **Consolidation**
   ```powershell
   Get-Content recon\*.txt | Sort-Object -Unique | Out-File -Encoding utf8 recon\all_urls.txt
   ```

## Linux/macOS equivalents
- Replace PowerShell pipes with shell redirects (`>`), paths with `/`, and commands remain the same where tools exist.

## Safety constraints
- Respect max `10 req/s` per host.
- Enforce scope before every request.
- Recon is read-only.
