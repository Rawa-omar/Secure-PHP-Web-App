<?php
// Calls a REST API from the server and returns the decoded JSON (or null on failure).
// Calls a REST API from the server and returns the decoded JSON (or null on failure).
// Uses cURL when available, otherwise falls back to file_get_contents.
function fetch_json(string $url, array $headers = [], int $timeout = 8): ?array {
    $allHeaders = array_merge(['Accept: application/json', 'User-Agent: IT670-student-project'], $headers);
    $body = false;
    $code = 0;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_HTTPHEADER     => $allHeaders,
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
    } else {
        $context = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'header'        => implode("\r\n", $allHeaders),
                'timeout'       => $timeout,
                'ignore_errors' => true,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $body = @file_get_contents($url, false, $context);
        if ($body !== false && isset($http_response_header[0])
            && preg_match('#\s(\d{3})\s#', $http_response_header[0], $m)) {
            $code = (int) $m[1];
        }
    }

    if ($body === false || $code !== 200) {
        return null;
    }
    $data = json_decode($body, true);
    return is_array($data) ? $data : null;
}

// Keeps a result in the session for a while, so we don't call the APIs on every page load.
function cached(string $key, int $ttl, callable $fn): ?array {
    if (isset($_SESSION['cache'][$key]) && time() - $_SESSION['cache'][$key]['t'] < $ttl) {
        return $_SESSION['cache'][$key]['v'];
    }
    $value = $fn();
    if ($value !== null) {
        $_SESSION['cache'][$key] = ['t' => time(), 'v' => $value];
    }
    return $value;
}

// Only allow normal web links (blocks javascript: links, a classic XSS trick).
function safe_url(?string $url): ?string {
    if ($url && filter_var($url, FILTER_VALIDATE_URL) && preg_match('#^https?://#i', $url)) {
        return $url;
    }
    return null;
}

// ---------- API 1: Hacker News ----------
function get_hn_top(int $count = 5): ?array {
    $ids = fetch_json('https://hacker-news.firebaseio.com/v0/topstories.json');
    if (!$ids) {
        return null;
    }
    $stories = [];
    foreach (array_slice($ids, 0, $count) as $id) {
        $id = (int) $id;
        $item = fetch_json('https://hacker-news.firebaseio.com/v0/item/' . $id . '.json');
        if ($item && !empty($item['title'])) {
            $stories[] = [
                'id'       => $id,
                'title'    => (string) $item['title'],
                'url'      => $item['url'] ?? ('https://news.ycombinator.com/item?id=' . $id),
                'score'    => (int) ($item['score'] ?? 0),
                'comments' => (int) ($item['descendants'] ?? 0),
            ];
        }
    }
    return $stories ?: null;
}

// ---------- API 2: NIST National Vulnerability Database ----------
// Latest CRITICAL CVEs published in the last 7 days.
function get_nvd_latest(int $count = 5): ?array {
    $start = gmdate('Y-m-d\TH:i:s', time() - 7 * 86400) . '.000';
    $end   = gmdate('Y-m-d\TH:i:s') . '.000';
    $url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&resultsPerPage=100'
         . '&pubStartDate=' . $start . '&pubEndDate=' . $end;
    $data = fetch_json($url, [], 25);
    if (!$data || !isset($data['vulnerabilities'])) {
        return null;
    }
    $list = [];
    foreach ($data['vulnerabilities'] as $v) {
        $cve = $v['cve'] ?? [];
        $desc = '';
        foreach ($cve['descriptions'] ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en') { $desc = (string) $d['value']; break; }
        }
        $metric = $cve['metrics']['cvssMetricV31'][0] ?? ($cve['metrics']['cvssMetricV30'][0] ?? null);
        $list[] = [
            'id'        => (string) ($cve['id'] ?? ''),
            'published' => (string) ($cve['published'] ?? ''),
            'score'     => $metric['cvssData']['baseScore'] ?? null,
            'desc'      => mb_strimwidth($desc, 0, 160, '...'),
        ];
    }
    usort($list, fn($a, $b) => strcmp($b['published'], $a['published']));   // newest first
    return array_slice($list, 0, $count);   // may be an empty list if nothing was published
}

// ---------- API 3: Cloudflare Radar (needs a free API token) ----------
// Share of mobile vs desktop web traffic worldwide, last 7 days.
function get_radar_devices(string $token): ?array {
    $url = 'https://api.cloudflare.com/client/v4/radar/http/summary/device_type?dateRange=7d&format=json';
    $data = fetch_json($url, ['Authorization: Bearer ' . $token]);
    return $data['result']['summary_0'] ?? null;
}
