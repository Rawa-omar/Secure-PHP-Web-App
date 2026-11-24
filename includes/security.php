<?php
// ---------- CSRF ----------
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

function csrf_check(): bool {
    return isset($_POST['csrf'], $_SESSION['csrf'])
        && is_string($_POST['csrf'])
        && hash_equals($_SESSION['csrf'], $_POST['csrf']);
}

// ---------- Brute force ----------
const MAX_ATTEMPTS = 5;     // عدد المحاولات الفاشلة المسموحة
const LOCK_MINUTES = 10;    // مدة القفل بالدقائق

function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function is_locked_out(string $email): bool {
    $since = date('Y-m-d H:i:s', time() - LOCK_MINUTES * 60);
    $stmt = db()->prepare(
        'SELECT COUNT(*) FROM login_attempts WHERE email = ? AND ip = ? AND attempted_at > ?'
    );
    $stmt->execute([$email, client_ip(), $since]);
    return (int) $stmt->fetchColumn() >= MAX_ATTEMPTS;
}

function record_failed_attempt(string $email): void {
    $stmt = db()->prepare('INSERT INTO login_attempts (email, ip, attempted_at) VALUES (?, ?, ?)');
    $stmt->execute([$email, client_ip(), date('Y-m-d H:i:s')]);
}

function clear_attempts(string $email): void {
    $stmt = db()->prepare('DELETE FROM login_attempts WHERE email = ? AND ip = ?');
    $stmt->execute([$email, client_ip()]);
}

// ---------- Session idle timeout ----------
const IDLE_TIMEOUT = 15 * 60;   // 15 دقيقة بدون نشاط

function enforce_session_timeout(): void {
    if (!isset($_SESSION['user_id'])) {
        return;
    }
    $now = time();
    if (isset($_SESSION['last_activity']) && $now - $_SESSION['last_activity'] > IDLE_TIMEOUT) {
        log_event('session_timeout', (int) $_SESSION['user_id']);
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 3600, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
        header('Location: login.php?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = $now;
}

// ---------- Security event log ----------
// Events: login_success, login_failed, login_blocked, csrf_failed, logout, session_timeout
function log_event(string $event, ?int $userId = null, ?string $email = null): void {
    $ua = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
    $email = ($email === null || $email === '') ? null : mb_substr($email, 0, 150);
    try {
        $stmt = db()->prepare(
            'INSERT INTO security_log (user_id, email, event, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([$userId, $email, $event, client_ip(), $ua, date('Y-m-d H:i:s')]);
    } catch (PDOException $ex) {
        // Logging must never break login or logout (for example if the security_log table is missing)
        error_log('security_log insert failed: ' . $ex->getMessage());
    }
}

// Turns a raw User-Agent string into something readable, e.g. "Chrome on Windows"
function device_label(?string $ua): string {
    $ua = (string) $ua;
    if ($ua === '') {
        return 'Unknown device';
    }
    $browsers = ['Edg/' => 'Edge', 'OPR/' => 'Opera', 'Firefox/' => 'Firefox', 'Chrome/' => 'Chrome', 'Safari/' => 'Safari'];
    $systems  = ['Windows' => 'Windows', 'Android' => 'Android', 'iPhone' => 'iPhone', 'iPad' => 'iPad',
                 'Mac OS X' => 'macOS', 'Linux' => 'Linux'];
    $browser = 'Unknown browser';
    foreach ($browsers as $needle => $name) {
        if (stripos($ua, $needle) !== false) { $browser = $name; break; }
    }
    $system = 'unknown system';
    foreach ($systems as $needle => $name) {
        if (stripos($ua, $needle) !== false) { $system = $name; break; }
    }
    return $browser . ' on ' . $system;
}

// Called at login, BEFORE logging the new login_success:
// returns the previous successful login and how many failed attempts happened since then.
function login_summary(int $userId, string $email): array {
    $summary = ['previous' => null, 'failed' => 0];
    try {
        $stmt = db()->prepare(
            "SELECT id, ip, user_agent, created_at FROM security_log
             WHERE user_id = ? AND event = 'login_success' ORDER BY id DESC LIMIT 1"
        );
        $stmt->execute([$userId]);
        $prev = $stmt->fetch() ?: null;

        $stmt = db()->prepare(
            "SELECT COUNT(*) FROM security_log
             WHERE event = 'login_failed' AND (user_id = ? OR email = ?) AND id > ?"
        );
        $stmt->execute([$userId, $email, $prev ? (int) $prev['id'] : 0]);

        $summary['previous'] = $prev;
        $summary['failed']   = (int) $stmt->fetchColumn();
    } catch (PDOException $ex) {
        error_log('login_summary failed: ' . $ex->getMessage());
    }
    return $summary;
}

// Latest security events for one account (by user id, or by email for attempts on it)
function user_activity(int $userId, string $email, int $limit = 10): array {
    try {
        $stmt = db()->prepare(
            'SELECT event, ip, user_agent, created_at FROM security_log
             WHERE user_id = ? OR email = ? ORDER BY id DESC LIMIT ' . max(1, $limit)
        );
        $stmt->execute([$userId, $email]);
        return $stmt->fetchAll();
    } catch (PDOException $ex) {
        error_log('user_activity failed: ' . $ex->getMessage());
        return [];
    }
}

function event_label(string $event): string {
    return [
        'login_success'   => 'Successful login',
        'login_failed'    => 'Failed login',
        'login_blocked'   => 'Login blocked (too many attempts)',
        'csrf_failed'     => 'Rejected request (invalid CSRF token)',
        'logout'          => 'Logged out',
        'session_timeout' => 'Logged out after inactivity',
    ][$event] ?? $event;
}

// ---------- HTTP security headers ----------
function send_security_headers(): void {
    // Content-Security-Policy: scripts only from our own files, no plugins, no framing
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
         . "img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
    header('X-Frame-Options: DENY');                 // clickjacking (older browsers)
    header('X-Content-Type-Options: nosniff');       // no MIME-type guessing
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
}