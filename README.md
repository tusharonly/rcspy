# RC Spy - Firebase & Supabase Security Scanner

<p>
  <a href="https://github.com/tusharonly/rcspy/releases/latest">
    <img alt="release" src="https://img.shields.io/github/v/release/tusharonly/rcspy" />
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0">
    <img alt="license" src="https://img.shields.io/badge/License-GPLv3-blue.svg" />
  </a>
  <img alt="downloads" src="https://img.shields.io/github/downloads/tusharonly/rcspy/total" />
  <img alt="stars" src="https://img.shields.io/github/stars/tusharonly/rcspy" />
</p>

RC Spy is a security tool that scans installed Android apps to detect backend misconfigurations. It identifies exposed Firebase Remote Config endpoints and Supabase instances with insecure storage buckets or tables. The tool extracts credentials from APKs (including Flutter apps) and tests for vulnerable endpoints. Built using the [Flutter](https://flutter.dev/) framework.

<p align="center">
<a href="https://github.com/tusharonly/rcspy/releases/latest" target="_blank">
    <img alt="Get it on GitHub" height="70" src="public/get-it-on-github.png" /></a>
</p>

## Features

### Firebase Detection
- **APK Analysis** — Extracts Firebase credentials (App IDs & API Keys) from installed apps
- **Vulnerability Detection** — Checks if Remote Config endpoints are publicly accessible
- **Multiple Views** — View exposed configs in List, Table, or raw JSON format

### Supabase Detection
- **Credential Extraction** — Finds Supabase project URLs and API keys
- **Smart JWT Validation** — Validates JWT tokens to ensure they're actually Supabase keys (not Auth0, Firebase Auth, etc.)
- **Key Format Support** — Detects both old JWT format (`eyJ...`) and new format (`sb_publishable_...`)
- **Security Analysis** — Tests for exposed storage buckets and database tables
- **Schema Discovery** — Automatically discovers tables via PostgREST OpenAPI schema
- **Multiple Views** — View exposed data in List, Table, or raw JSON format (unified with Firebase UI)

### General
- **Flutter App Support** — Scans native libraries (`.so` files) where Flutter stores compiled strings
- **Smart Filtering** — Filter by All, Vulnerable, Firebase, Supabase, Secure, or No Backend
- **Search** — Quick search to find apps by name
- **Manual Scan Mode** — Start scanning when you're ready with the "Start Scan" button
- **Local Caching** — Results persist across app launches
- **Fast Scanning** — Parallel analysis using isolates for smooth performance
- **Share Results** — Export and share analysis findings

## How it looks

<div>
  <kbd><img src="screenshots/home_page.jpg" width="200"></kbd>
  <kbd><img src="screenshots/list_view.jpg" width="200"></kbd>
  <kbd><img src="screenshots/json_view.jpg" width="200"></kbd>
</div>

<br />

<details>
  <summary>See full screenshots</summary>
  <div align="center">
  <kbd><img src="screenshots/home_page.jpg" width="200"></kbd>
  <kbd><img src="screenshots/list_view.jpg" width="200"></kbd>
  <kbd><img src="screenshots/table_view.jpg" width="200"></kbd>
  </div>

  <br/>

  <div align="center">
    <kbd><img src="screenshots/json_view.jpg" width="200"></kbd>
    <kbd><img src="screenshots/settings.jpg" width="200"></kbd>
  </div>
</details>

## Use Cases

- Security researchers auditing app configurations
- Penetration testers identifying misconfigurations
- Developers checking their own apps for vulnerabilities
- Bug bounty hunters looking for exposed backends

## Built With

- Flutter & Dart
- Provider for state management
- Isolates for background processing

## Disclaimer

This tool is intended for **security research and educational purposes only**. Only scan apps you have permission to analyze. The developer is not responsible for any misuse of this tool.

## License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">Made with love for security researchers</p>

<p align="center">
  <a href="https://x.com/tusharghige">Follow me on X</a>
</p>
