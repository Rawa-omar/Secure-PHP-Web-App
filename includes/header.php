<?php require_once __DIR__ . '/../config.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= e($pageTitle ?? APP_NAME) ?> | <?= APP_NAME ?></title>
  <link rel="stylesheet" href="css/style.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site-header">
  <div class="wrap bar">
    <a class="brand" href="index.php"><?= APP_NAME ?></a>
    <nav aria-label="Main">
      <?php if (isset($_SESSION['user_id'])): ?>
        <a href="profile.php">Profile</a>
        <a href="logout.php" class="btn btn-small">Log out</a>
      <?php else: ?>
        <a href="login.php">Log in</a>
        <a href="register.php" class="btn btn-small">Create account</a>
      <?php endif; ?>
    </nav>
  </div>
</header>
<main id="main">
