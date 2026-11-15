<?php
// Copy this file to config.php and fill in your own values.

// ===== App info =====
const APP_NAME = 'SecurePortal';
const AUTHORS  = 'Your Name &amp; Partner Name';

// ===== Database connection (XAMPP defaults) =====
const DB_HOST = 'localhost';
const DB_NAME = 'secure_app';
const DB_USER = 'root';
const DB_PASS = '';          // XAMPP's root password is empty by default

// ===== Cloudflare Radar API token (free) =====
// Paste your token between the quotes. Never commit the real token.
const CF_RADAR_TOKEN = '';

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO(
            'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,   // real prepared statements
            ]
        );
    }
    return $pdo;
}

// Use this every time you print user data on a page (stops XSS)
function e(?string $text): string {
    return htmlspecialchars($text ?? '', ENT_QUOTES, 'UTF-8');
}