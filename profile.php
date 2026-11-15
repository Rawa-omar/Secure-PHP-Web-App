<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/api.php';
require_once __DIR__ . '/includes/security.php'; 

enforce_session_timeout(); 

// Only logged-in users may see this page
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$stmt = db()->prepare('SELECT name, mobile, email, register_day_time FROM users WHERE id = ?');
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {               // stale session (account no longer exists): clear it here, then go to login
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

// ---- REST APIs (results are cached for a few minutes) ----
$news   = cached('hn',    600, fn() => get_hn_top(5));
$cves   = cached('nvd',   900, fn() => get_nvd_latest(5));
$radar  = CF_RADAR_TOKEN !== '' ? cached('radar', 1800, fn() => get_radar_devices(CF_RADAR_TOKEN)) : null;

$pageTitle = 'Profile';
require __DIR__ . '/includes/header.php';
?>
<div class="wrap" style="padding: 48px 0;">
  <div class="card">
    <h1>Welcome, <?= e($user['name']) ?></h1>
    <dl class="info">
      <dt>Name</dt><dd><?= e($user['name']) ?></dd>
      <dt>Mobile</dt><dd><?= e($user['mobile']) ?></dd>
      <dt>Email</dt><dd><?= e($user['email']) ?></dd>
      <dt>Registered on</dt><dd><?= e($user['register_day_time']) ?></dd>
    </dl>
  </div>

  <div class="card" style="margin-top: 24px;">
    <h2>Security and tech briefing</h2>
    <div class="widgets">

      <section class="widget">
        <h3>Top stories on Hacker News</h3>
        <?php if ($news): ?>
          <ul class="feed">
            <?php foreach ($news as $s): $link = safe_url($s['url']); ?>
              <li>
                <?php if ($link): ?>
                  <a href="<?= e($link) ?>" target="_blank" rel="noopener noreferrer"><?= e($s['title']) ?></a>
                <?php else: ?>
                  <?= e($s['title']) ?>
                <?php endif; ?>
                <span class="hint"><?= e((string) $s['score']) ?> points, <?= e((string) $s['comments']) ?> comments</span>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php else: ?>
          <p class="hint">Stories are unavailable right now. Please try again later.</p>
        <?php endif; ?>
      </section>

      <section class="widget">
        <h3>Newest critical vulnerabilities (NIST NVD)</h3>
        <?php if ($cves === null): ?>
          <p class="hint">The vulnerability database is unavailable right now. Please try again in a minute.</p>
        <?php elseif (!$cves): ?>
          <p class="hint">No critical vulnerabilities were published in the last 7 days.</p>
        <?php else: ?>
          <ul class="feed">
            <?php foreach ($cves as $c): ?>
              <li>
                <a href="https://nvd.nist.gov/vuln/detail/<?= e(rawurlencode($c['id'])) ?>" target="_blank" rel="noopener noreferrer"><?= e($c['id']) ?></a>
                <span class="badge">CVSS <?= e((string) ($c['score'] ?? 'n/a')) ?></span>
                <span class="hint"><?= e($c['desc']) ?></span>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php endif; ?>
      </section>

      <section class="widget">
        <h3>Global web traffic by device (Cloudflare Radar)</h3>
        <?php if (CF_RADAR_TOKEN === ''): ?>
          <p class="hint">Add your Cloudflare Radar API token in config.php to show this section.</p>
        <?php elseif ($radar): ?>
          <p class="big"><?= e(number_format((float) ($radar['mobile'] ?? 0), 1)) ?>%</p>
          <p>of requests come from mobile devices</p>
          <p class="hint">Desktop <?= e(number_format((float) ($radar['desktop'] ?? 0), 1)) ?>%, other <?= e(number_format((float) ($radar['other'] ?? 0), 1)) ?>%. Last 7 days, worldwide.</p>
        <?php else: ?>
          <p class="hint">Traffic data is unavailable right now. Check the token and try again later.</p>
        <?php endif; ?>
      </section>

    </div>
  </div>
</div>
<?php require __DIR__ . '/includes/footer.php'; ?>
