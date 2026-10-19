<?php
/**
 * Tiny File Manager — choose one storage backend.
 * Switch $storage_type between 'mega' and 'local', then reload the page.
 */
$storage_type = 'mega'; // 'mega' or 'local'

// Full public application URL for sharing; include the application folder.
// Keep this above mega_require_login(), which handles public downloads.
$mega_share_base_url = 'https://ktlun.me/mega/';

// Successful and failed login audit files are created in this application folder.
$user_logging_enabled = false; // true to enable; false creates no records
$user_logging_timezone = 'UTC'; // e.g. 'Asia/Hong_Kong' or 'America/Los_Angeles'
$user_logging_retention_days = 30; // UTC calendar days, including today; 0 keeps all

// Enforce a five-minute wait after this many consecutive failed MEGA logins.
$mega_login_cooldown_enabled = true; // false allows immediate manual retry
$mega_login_max_failures = 3; // integer 1-100; reset after success or cooldown expiry


// Set to an existing, dedicated directory OUTSIDE the public web root.
$local_root = '/srv/tinyfilemanager/files';
// Generate a password hash with: php -r 'echo password_hash("YOUR_PASSWORD", PASSWORD_DEFAULT), PHP_EOL;'
$local_username = 'admin';
$local_password_hash = ''; // REQUIRED for local mode; do not use demo passwords

if ($storage_type === 'mega') {
    require_once __DIR__ . '/mega_wrapper.php';
    $use_auth = false;
    $root_path = 'mega://root';
    mega_require_login();
} elseif ($storage_type === 'local') {
    if (!is_dir($local_root) || !is_readable($local_root)) {
        http_response_code(503);
        exit('Local storage root does not exist or is not readable. Check config.php.');
    }
    $resolved = realpath($local_root);
    if ($resolved === false || $resolved === '/' || $resolved === realpath(__DIR__)) {
        http_response_code(503);
        exit('Unsafe local storage root. Choose a dedicated directory.');
    }
    if ($local_password_hash === '' || !preg_match('/^\$2[aby]\$|^\$argon2/i', $local_password_hash)) {
        http_response_code(503);
        exit('Set a secure local_password_hash in config.php before enabling local storage.');
    }
    $root_path = $resolved;
    $root_url = ''; // Local preview/download is served by the application when needed.
    $use_auth = true;
    $auth_users = array($local_username => $local_password_hash);
    $readonly_users = array();
} else {
    http_response_code(503);
    exit('Invalid storage_type in config.php.');
}
