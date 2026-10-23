<?php
// Serve ONLY on a loopback-only location in the real FPM pool / Apache vhost.
// Do not run with `php probe.php` or PHP's development server.
$expectedToken = 'REPLACE_WITH_A_RANDOM_TOKEN_OF_AT_LEAST_32_CHARACTERS';
$remote = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
$auth = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
if ($expectedToken === 'REPLACE_WITH_A_RANDOM_TOKEN_OF_AT_LEAST_32_CHARACTERS' || strlen($expectedToken) < 32) {
    http_response_code(503);
    exit;
}
if (!in_array($remote, array('127.0.0.1', '::1'), true) ||
    !function_exists('hash_equals') || !hash_equals('Bearer ' . $expectedToken, $auth)) {
    http_response_code(403);
    exit;
}
if (PHP_SAPI !== 'fpm-fcgi' && PHP_SAPI !== 'apache2handler') {
    http_response_code(503);
    exit;
}
$ticks = '';
if (PHP_OS !== 'Darwin') {
    $stat = @file_get_contents('/proc/self/stat');
    $end = $stat === false ? false : strrpos($stat, ')');
    $fields = $end === false ? array() : preg_split('/\s+/', trim(substr($stat, $end + 1)));
    if (!isset($fields[19]) || !ctype_digit($fields[19])) {
        http_response_code(503);
        exit;
    }
    $ticks = $fields[19];
}
$ini = ini_get_all(null, true);
$progress = isset($ini['session.upload_progress.enabled']) ? $ini['session.upload_progress.enabled'] : null;
$memory = isset($ini['memory_limit']) ? $ini['memory_limit'] : null;
header('Content-Type: application/json');
header('Cache-Control: no-store');
echo json_encode(array(
    'pid' => getmypid(),
    'start_ticks' => $ticks,
    'sapi' => PHP_SAPI,
    'version' => PHP_VERSION,
    'progress' => $progress === null ? null : (string)$progress['local_value'],
    'progress_master' => $progress === null ? null : (string)$progress['global_value'],
    'memory_limit' => $memory === null ? null : (string)$memory['local_value']
));
