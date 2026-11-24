<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/security.php';

if (isset($_SESSION['user_id'])) {
    header('Location: profile.php');
    exit;
}

$error = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!csrf_check()) {
        log_event('csrf_failed', null, $email);
        $error = 'Invalid request. Please reload the page and try again.';
    } elseif ($email === '' || $password === '') {
        $error = 'Enter your email and password.';
    } elseif (is_locked_out($email)) {
        log_event('login_blocked', null, $email);
        $error = 'Too many failed attempts. Please try again in ' . LOCK_MINUTES . ' minutes.';
    } else {
        try {
            // Prepared statement (stops SQL injection)
            $stmt = db()->prepare('SELECT id, name, email, password FROM users WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            // Compare the typed password with the stored hash
            if ($user && password_verify($password, $user['password'])) {
                $userId = (int) $user['id'];
                clear_attempts($email);
                session_regenerate_id(true);          // new session ID after login
                $_SESSION['user_id'] = $userId;
                $_SESSION['last_activity'] = time();

                // Previous login and failed attempts since then, read before logging this login
                $_SESSION['login_summary'] = login_summary($userId, $user['email']);
                log_event('login_success', $userId, $user['email']);

                header('Location: profile.php');
                exit;
            }
            record_failed_attempt($email);
            log_event('login_failed', $user ? (int) $user['id'] : null, $email);
            // Same message for "no such email" and "wrong password" so attackers learn nothing
            $error = 'Incorrect email or password.';
        } catch (PDOException $ex) {
            $error = 'Something went wrong on our side. Please try again.';
        }
    }
}

$pageTitle = 'Log in';
require __DIR__ . '/includes/header.php';
?>
<div class="card form-card">
  <h1>Log in</h1>

  <?php if (isset($_GET['registered'])): ?>
    <div class="msg ok">Your account is ready. Log in to continue.</div>
  <?php endif; ?>
  <?php if (isset($_GET['loggedout'])): ?>
    <div class="msg ok">You have been logged out.</div>
  <?php endif; ?>
    <?php if (isset($_GET['timeout'])): ?>
    <div class="msg error">Your session expired due to inactivity. Please log in again.</div>
  <?php endif; ?>
  <?php if ($error): ?>
    <div class="msg error"><?= e($error) ?></div>
  <?php endif; ?>

  <form method="post" action="login.php" novalidate>
    <?= csrf_field() ?>
    <label for="email">Email</label>
    <input type="email" id="email" name="email" value="<?= e($email) ?>" required autocomplete="email">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autocomplete="current-password">

    <button type="submit" class="btn">Log in</button>
  </form>

  <p class="hint">No account yet? <a href="register.php">Create one</a></p>
</div>
<?php require __DIR__ . '/includes/footer.php'; ?>
