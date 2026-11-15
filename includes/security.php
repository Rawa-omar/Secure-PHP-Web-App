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