<?php
require_once __DIR__ . '/config.php';

// Already logged in? Go to profile.
if (isset($_SESSION['user_id'])) {
    header('Location: profile.php');
    exit;
}

$errors = [];
$name = $mobile = $email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name     = trim($_POST['name'] ?? '');
    $mobile   = trim($_POST['mobile'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm'] ?? '';

    // ---- Validation (server side) ----
    if ($name === '' || mb_strlen($name) > 100) {
        $errors[] = 'Enter your name (up to 100 characters).';
    }
    if (!preg_match('/^\+?[0-9]{9,15}$/', $mobile)) {
        $errors[] = 'Enter a valid mobile number, digits only (for example 0501234567).';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 150) {
        $errors[] = 'Enter a valid email address.';
    }
    if (strlen($password) < 8) {
        $errors[] = 'Your password must be at least 8 characters.';
    }
    if ($password !== $confirm) {
        $errors[] = 'The two passwords do not match.';
    }

    // ---- Save the user ----
    if (!$errors) {
        try {
            // Prepared statement: the ? marks keep user input separate from the SQL (stops SQL injection)
            $check = db()->prepare('SELECT id FROM users WHERE email = ?');
            $check->execute([$email]);

            if ($check->fetch()) {
                $errors[] = 'An account with this email already exists.';
            } else {
                $insert = db()->prepare(
                    'INSERT INTO users (name, mobile, email, password) VALUES (?, ?, ?, ?)'
                );
                // Store a hash, never the real password
                $insert->execute([$name, $mobile, $email, password_hash($password, PASSWORD_DEFAULT)]);

                header('Location: login.php?registered=1');
                exit;
            }
        } catch (PDOException $ex) {
            $errors[] = 'Something went wrong on our side. Please try again.';
        }
    }
}

$pageTitle = 'Create account';
require __DIR__ . '/includes/header.php';
?>
<div class="card form-card">
  <h1>Create your account</h1>

  <?php foreach ($errors as $err): ?>
    <div class="msg error"><?= e($err) ?></div>
  <?php endforeach; ?>

  <form method="post" action="register.php" novalidate>
    <label for="name">Full name</label>
    <input type="text" id="name" name="name" value="<?= e($name) ?>" required maxlength="100" autocomplete="name">

    <label for="mobile">Mobile number</label>
    <input type="tel" id="mobile" name="mobile" value="<?= e($mobile) ?>" required autocomplete="tel">

    <label for="email">Email</label>
    <input type="email" id="email" name="email" value="<?= e($email) ?>" required autocomplete="email">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required minlength="8" autocomplete="new-password">
    <p class="hint">At least 8 characters.</p>

    <label for="confirm">Confirm password</label>
    <input type="password" id="confirm" name="confirm" required autocomplete="new-password">

    <button type="submit" class="btn">Create account</button>
  </form>

  <p class="hint">Already registered? <a href="login.php">Log in</a></p>
</div>
<?php require __DIR__ . '/includes/footer.php'; ?>
