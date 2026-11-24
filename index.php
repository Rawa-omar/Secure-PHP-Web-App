<?php
$pageTitle = 'Home';
require __DIR__ . '/includes/header.php';
?>
<section class="hero">
  <div class="wrap hero-grid">
    <div>
      <h1>Your account, kept private and kept yours.</h1>
      <p class="lead">Create an account, sign in, and see your profile alongside live security news and the latest critical vulnerabilities.</p>
      <div class="actions">
        <?php if (isset($_SESSION['user_id'])): ?>
          <a class="btn" href="profile.php">Go to your profile</a>
        <?php else: ?>
          <a class="btn" href="register.php">Create account</a>
          <a class="btn btn-ghost" href="login.php">Log in</a>
        <?php endif; ?>
      </div>
      <p class="byline">By <?= AUTHORS ?></p>
    </div>

    <aside class="panel" aria-label="How your data is protected">
      <h2>How we protect your data</h2>
      <dl>
        <dt>Passwords are hashed</dt>
        <dd>We never store your real password, only a one-way hash of it.</dd>
        <dt>Queries are parameterized</dt>
        <dd>Form input can't change what the database is asked to do, which blocks SQL injection.</dd>
        <dt>Output is escaped</dt>
        <dd>Anything you type is displayed as plain text, which blocks cross-site scripting (XSS).</dd>
      </dl>
    </aside>
  </div>
</section>
<?php require __DIR__ . '/includes/footer.php'; ?>
