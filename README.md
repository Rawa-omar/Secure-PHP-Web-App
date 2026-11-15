
# SecurePortal: Secure PHP Web App

IT 670, Selected Topics in Information Security.

A PHP and MySQL web application with registration, login, and a profile page that shows live security and tech feeds from REST APIs. The focus of the project is defending against common web attacks.

**Authors:** Ghada Altuwayjiri, Lujain Al-Dawsari, Rawa Almotawa

## Features

- Front page with navigation, hero section, and the authors' names
- Register, login, logout, and profile pages sharing one template (`includes/header.php` and `includes/footer.php`)
- Profile page showing name, mobile, email, and registration date
- REST API widgets on the profile page:
  - Hacker News: top stories
  - NIST NVD: newest critical vulnerabilities (CVEs)
  - Cloudflare Radar: mobile vs desktop traffic (optional, needs a free API token)
- Responsive design (CSS grid and flexbox)

## Security measures

| Threat | Defense |
|---|---|
| SQL injection | PDO prepared statements with bound parameters on every query |
| XSS | All output escaped with `htmlspecialchars` through the `e()` helper; API links restricted to http/https |
| Password theft | `password_hash()` (bcrypt) and `password_verify()` |
| Session hijacking | `session_regenerate_id(true)` on login, HttpOnly and SameSite=Lax cookie flags |
| Session abuse | Automatic logout after 15 minutes of inactivity |
| CSRF | Random token in the register and login forms, verified on every POST |
| Brute force | 5 failed logins per email and IP locks login for 10 minutes (`login_attempts` table) |
| User enumeration | One generic login error message for wrong email or wrong password |
| Server-side validation | Email format, password length, and duplicate email checks in PHP |

## Requirements

- XAMPP (Apache, MySQL, PHP 8+) or similar
- Internet access for the API widgets
- cURL is used when available. If the extension is missing, the app falls back to `file_get_contents`.

## Setup

1. Copy the project folder to `C:\xampp\htdocs\` (for example `C:\xampp\htdocs\Secure-PHP-Web-App`).
2. Start **Apache** and **MySQL** in the XAMPP control panel.
3. Open `http://localhost/phpmyadmin`, create a database named `secure_app`, then import `secure_app.sql`.
4. Copy `config.example.php` to `config.php` and set your values:
   - `APP_NAME` and `AUTHORS`
   - Database settings (XAMPP defaults: user `root`, empty password)
   - `CF_RADAR_TOKEN` (optional, leave empty to skip the Cloudflare widget)
5. Open `http://localhost/Secure-PHP-Web-App/`.

`config.php` is listed in `.gitignore` so credentials and tokens are never committed.

## Project structure

```
├── index.php            Front page
├── register.php         Registration
├── login.php            Login
├── profile.php          Profile and API widgets
├── logout.php           Logout
├── config.example.php   Config template (copy to config.php)
├── secure_app.sql       Database schema
├── css/style.css        Styles
└── includes/
    ├── header.php       Shared navbar
    ├── footer.php       Shared footer
    ├── security.php     CSRF, brute-force limiting, session timeout
    └── api.php          REST API helpers
```

## Database

- `users`: id, name, mobile, email (unique), password (hash), register_day_time
- `login_attempts`: id, email, ip, attempted_at

## Security testing

- **SQL injection:** `' OR '1'='1` in the login form is rejected with a generic error.
- **XSS:** registering with the name `<script>alert(1)</script>` displays it as plain text.
- **CSRF:** removing the hidden `csrf` field makes the form return "Invalid request".
- **Brute force:** the 6th failed attempt returns "Too many failed attempts".
- **Cookies:** `document.cookie` in the browser console does not reveal `PHPSESSID`.