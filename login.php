<?php
require_once __DIR__ . '/config.php';

if (isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$error = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        $error = 'Enter your email and password.';
    } else {
        try {
            // Prepared statement (stops SQL injection)
            $stmt = db()->prepare('SELECT id, name, password FROM users WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            // Compare the typed password with the stored hash
            if ($user && password_verify($password, $user['password'])) {
                session_regenerate_id(true);          // new session ID after login
                $_SESSION['user_id'] = (int) $user['id'];
                header('Location: profile.php');
                exit;
            }
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
  <?php if ($error): ?>
    <div class="msg error"><?= e($error) ?></div>
  <?php endif; ?>

  <form method="post" action="login.php" novalidate>
    <label for="email">Email</label>
    <input type="email" id="email" name="email" value="<?= e($email) ?>" required autocomplete="email">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autocomplete="current-password">

    <button type="submit" class="btn">Log in</button>
  </form>

  <p class="hint">No account yet? <a href="register.php">Create one</a></p>
</div>
<?php require __DIR__ . '/includes/footer.php'; ?>
