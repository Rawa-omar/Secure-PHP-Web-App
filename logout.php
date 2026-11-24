<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/security.php';

if (isset($_SESSION['user_id'])) {
    log_event('logout', (int) $_SESSION['user_id']);
}

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 3600, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();

header('Location: login.php?loggedout=1');
exit;
