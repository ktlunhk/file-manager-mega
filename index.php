<?php
/** Optional sign-in audit. Only this fixed schema is written; no secrets. */
function fm_log_user_login($username, $success, $category = '') {
    if (($GLOBALS['user_logging_enabled'] ?? false) !== true) return;
    try {
        $zone = new DateTimeZone($GLOBALS['user_logging_timezone'] ?? 'UTC');
        $now = new DateTimeImmutable('now', $zone);
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) $ip = '';
        $clean = function($value, $limit) {
            if (!is_string($value)) return '';
            $value = substr($value, 0, $limit);
            // Drop malformed UTF-8 rather than allowing it to break the record.
            if (!preg_match('//u', $value)) $value = function_exists('iconv') ? @iconv('UTF-8', 'UTF-8//IGNORE', $value) : preg_replace('/[\x80-\xff]/', '', $value);
            return is_string($value) ? $value : '';
        };
        $categories = ['invalid_credentials', 'invalid_security_token', 'login_cooldown', 'two_factor_required', 'invalid_two_factor', 'service_error', 'invalid_request'];
        if (!isset($GLOBALS['fm_login_request_id'])) $GLOBALS['fm_login_request_id'] = bin2hex(random_bytes(16));
        $id = $GLOBALS['fm_login_request_id'];
        $entry = json_encode([
            'datetime' => $now->format('Y-m-d\TH:i:sP'),
            'timezone' => $zone->getName(),
            'username' => $clean($username, 512),
            'ip' => $ip,
            'status' => $success ? 'success' : 'failure',
            'failure_category' => $success ? null : (in_array($category, $categories, true) ? $category : 'service_error'),
            'storage' => ($GLOBALS['storage_type'] ?? 'local') === 'mega' ? 'mega' : 'local',
            'browser' => $clean($_SERVER['HTTP_USER_AGENT'] ?? '', 1024),
            'request_id' => $id
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        if ($entry === false) throw new RuntimeException('Invalid audit entry');
        // UTC filenames keep retention unambiguous if the display timezone changes.
        $path = __DIR__ . '/user_login_' . gmdate('Y-m-d') . '.php';
        if (is_link($path)) throw new RuntimeException('Unsafe audit file');
        $fh = @fopen($path, 'c+b');
        if (!$fh) throw new RuntimeException('Audit file unavailable');
        @chmod($path, 0600);
        try {
            if (!flock($fh, LOCK_EX)) throw new RuntimeException('Audit lock unavailable');
            $prefix = "<?php http_response_code(404); exit; ?>\n";
            rewind($fh); $current = fread($fh, strlen($prefix));
            if ($current !== '' && $current !== $prefix) throw new RuntimeException('Invalid audit file');
            fseek($fh, 0, SEEK_END);
            $bytes = ($current === '' ? $prefix : '') . $entry . "\n";
            while ($bytes !== '') {
                $written = fwrite($fh, $bytes);
                if (!$written) throw new RuntimeException('Audit write failed');
                $bytes = substr($bytes, $written);
            }
            if (!fflush($fh)) throw new RuntimeException('Audit flush failed');
        } finally { flock($fh, LOCK_UN); fclose($fh); }
        if (!headers_sent()) header('X-Request-ID: ' . $id);
        $days = $GLOBALS['user_logging_retention_days'] ?? 30;
        if (!is_int($days) || $days < 0 || $days > 3650) $days = 30;
        if ($days > 0) {
            $cutoff = (new DateTimeImmutable('today', new DateTimeZone('UTC')))->modify('-' . ($days - 1) . ' days')->format('Y-m-d');
            foreach (glob(__DIR__ . '/user_login_????-??-??.php') ?: [] as $old) {
                if (is_link($old) || !is_file($old) || !preg_match('/\Auser_login_(\d{4}-\d{2}-\d{2})\.php\z/', basename($old), $m) || $m[1] >= $cutoff) continue;
                $parts = explode('-', $m[1]);
                if (!checkdate((int)$parts[1], (int)$parts[2], (int)$parts[0])) continue;
                $candidate = @fopen($old, 'rb');
                if (!$candidate) continue;
                $protected = fread($candidate, strlen($prefix)) === $prefix;
                fclose($candidate);
                if ($protected) @unlink($old);
            }
        }
    } catch (Throwable $e) {
        // A logging failure never prevents login and never discloses credentials.
        error_log('[filemanager] Unable to write login audit. Check folder permissions and logging configuration.');
    }
}

function fm_login_failure_category($error) {
    if ($error->getMessage() === 'Invalid two-factor code') return 'invalid_two_factor';
    if ($error instanceof InvalidArgumentException) return 'invalid_request';
    if ($error->getMessage() === 'Wrong email or password') return 'invalid_credentials';
    if ($error->getMessage() === 'Two-factor code required') return 'two_factor_required';
    return 'service_error';
}

// Integrated public download handler (v115).
/** Public, account-independent MEGA file downloads through this website. */
// The public share-link base URL is configured in config.php.
defined('MEGA_SHARE_KEY_FILE') || define('MEGA_SHARE_KEY_FILE', __DIR__ . '/mega_share_secret.php');

// Before normal application initialization, config.php's selected backend is
// available globally. After initialization use the validated application mode.
function fm_mega_sharing_enabled() {
    return defined('FM_STORAGE_TYPE') ? FM_STORAGE_TYPE === 'mega' : ($GLOBALS['storage_type'] ?? 'local') === 'mega';
}
function fm_share_require_mega() {
    if (!fm_mega_sharing_enabled()) fm_share_fail(404, 'Not found');
}

/** A site signature prevents this endpoint becoming a proxy for arbitrary links. */
function fm_share_signing_key($create = false)
{
    $file = MEGA_SHARE_KEY_FILE;
    if (!is_file($file) && $create) {
        $fh = @fopen($file, 'x+b');
        if ($fh) {
            @chmod($file, 0600);
            flock($fh, LOCK_EX);
            $contents = "<?php return '" . bin2hex(random_bytes(32)) . "';\n";
            $ok = fwrite($fh, $contents) === strlen($contents) && fflush($fh);
            flock($fh, LOCK_UN); fclose($fh);
            if (!$ok) throw new RuntimeException('Unable to save sharing key');
        }
    }
    $fh = @fopen($file, 'rb');
    if (!$fh) throw new RuntimeException('Sharing key unavailable. Allow PHP to create mega_share_secret.php in the application folder.');
    flock($fh, LOCK_SH); $contents = stream_get_contents($fh); flock($fh, LOCK_UN); fclose($fh);
    if (!preg_match("/\\A<\\?php return '([a-f0-9]{64})';\\s*\\z/", $contents, $m)) throw new RuntimeException('Invalid sharing key file');
    return hex2bin($m[1]);
}

function fm_share_verify($token)
{
    if (!is_string($token) || !preg_match('/\A([A-Za-z0-9_-]{8}\.[A-Za-z0-9_-]{43})\.([a-f0-9]{64})\z/', $token, $m)) {
        throw new InvalidArgumentException('Invalid download link');
    }
    $parts = fm_share_parts($m[1]);
    if (!hash_equals(hash_hmac('sha256', $m[1], fm_share_signing_key()), $m[2])) throw new InvalidArgumentException('Invalid download link');
    return $parts;
}

function fm_share_parts($token)
{
    if (!is_string($token) || !preg_match('/\A([A-Za-z0-9_-]{8})\.([A-Za-z0-9_-]{43})\z/', $token, $m)) {
        throw new InvalidArgumentException('Invalid download link');
    }
    $key = base64_decode(strtr($m[2], '-_', '+/') . '=', true);
    if ($key === false || strlen($key) !== 32 || rtrim(strtr(base64_encode($key), '+/', '-_'), '=') !== $m[2]) {
        throw new InvalidArgumentException('Invalid download link');
    }
    return [$m[1], $key];
}

function fm_share_url($megaLink)
{
    fm_share_require_mega();
    $base = $GLOBALS['mega_share_base_url'] ?? '';
    $parts = is_string($base) ? parse_url($base) : false;
    if (!is_string($base) || preg_match('/[\x00-\x20\x7f]/', $base) || !$parts ||
        !in_array(strtolower($parts['scheme'] ?? ''), ['https', 'http'], true) || empty($parts['host']) ||
        isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
        throw new RuntimeException('Set a valid mega_share_base_url in config.php (for example, https://your-domain/mega/).');
    }
    if (!preg_match('~\Ahttps://mega\.nz/file/([A-Za-z0-9_-]{8})#([A-Za-z0-9_-]{43})\z~', $megaLink, $m)) {
        throw new RuntimeException('Invalid MEGA public link');
    }
    $token = $m[1] . '.' . $m[2];
    fm_share_parts($token);
    return rtrim($base, '/') . '/?share=' . $token . '.' . hash_hmac('sha256', $token, fm_share_signing_key(true));
}

/** Single HTTP range, with overflow-safe numeric parsing. */
function fm_share_range($range, $size)
{
    if ($range === '') return [0, max(0, $size - 1), false];
    if ($size === 0 || !preg_match('/\Abytes=(\d*)-(\d*)\z/', $range, $m) || ($m[1] === '' && $m[2] === '')) {
        throw new OutOfRangeException('Invalid range');
    }
    foreach ([$m[1], $m[2]] as $n) {
        $n = ltrim($n, '0');
        if (strlen($n) > strlen((string)PHP_INT_MAX) || (strlen($n) === strlen((string)PHP_INT_MAX) && strcmp($n, (string)PHP_INT_MAX) > 0)) {
            throw new OutOfRangeException('Invalid range');
        }
    }
    if ($m[1] === '') {
        $suffix = (int)$m[2];
        if ($suffix < 1) throw new OutOfRangeException('Invalid range');
        return [max(0, $size - $suffix), $size - 1, true];
    }
    $start = (int)$m[1];
    $end = $m[2] === '' ? $size - 1 : min((int)$m[2], $size - 1);
    if ($start >= $size || $start > $end) throw new OutOfRangeException('Invalid range');
    return [$start, $end, true];
}

function fm_share_upstream_url($url)
{
    if (!is_string($url)) throw new RuntimeException('Invalid download response');
    $p = parse_url($url);
    $host = strtolower($p['host'] ?? '');
    if (!$p || ($p['scheme'] ?? '') !== 'https' || isset($p['user']) || isset($p['pass']) || isset($p['query']) || isset($p['fragment']) ||
        (isset($p['port']) && $p['port'] !== 443) || !preg_match('/\A(?:[a-z0-9-]+\.)*(?:userstorage\.mega\.co\.nz|userstorage\.mega\.nz)\z/', $host)) {
        throw new RuntimeException('Invalid download host');
    }
    return rtrim($url, '/');
}

/** Bounded AES-CTR decryption, including unaligned resume offsets. */
class FmShareDecryptor
{
    private $aes, $nonce, $offset, $skip, $remaining, $buffer = '', $emit;
    public $received = 0;
    public function __construct($key, $start, $length, $emit)
    {
        $this->aes = substr($key, 0, 16) ^ substr($key, 16, 16);
        $this->nonce = substr($key, 16, 8);
        $this->offset = intdiv($start, 16) * 16;
        $this->skip = $start - $this->offset;
        $this->remaining = $length;
        $this->emit = $emit;
    }
    public function push($bytes, $final = false)
    {
        $this->received += strlen($bytes);
        $this->buffer .= $bytes;
        $length = $final ? strlen($this->buffer) : (strlen($this->buffer) & ~15);
        if (!$length) return;
        $plain = MegaApi::ctr(substr($this->buffer, 0, $length), $this->aes, $this->nonce, $this->offset);
        if ($plain === false) throw new RuntimeException('Unable to decrypt file');
        $this->offset += $length;
        $this->buffer = substr($this->buffer, $length);
        if ($this->skip) {
            $skip = min($this->skip, strlen($plain));
            $plain = substr($plain, $skip);
            $this->skip -= $skip;
        }
        $plain = substr($plain, 0, $this->remaining);
        $this->remaining -= strlen($plain);
        if ($plain !== '') call_user_func($this->emit, $plain);
    }
}

function fm_share_fail($code, $message)
{
    http_response_code($code);
    header_remove('Content-Disposition');
    header_remove('Content-Range');
    header_remove('Content-Length');
    header('Content-Type: text/plain; charset=utf-8');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') echo $message;
    exit;
}

function fm_serve_public_share($token)
{
    fm_share_require_mega();
    header('Cache-Control: private, no-store');
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['GET', 'HEAD'], true)) {
        header('Allow: GET, HEAD');
        fm_share_fail(405, 'Method not allowed');
    }
    try { list($handle, $key) = fm_share_verify($token); }
    catch (InvalidArgumentException $e) { fm_share_fail(404, 'Download link not found'); }
    catch (RuntimeException $e) { fm_share_fail(503, 'Sharing is temporarily unavailable'); }
    if (PHP_INT_SIZE < 8 || !extension_loaded('curl') || !extension_loaded('openssl')) {
        fm_share_fail(503, 'Downloads require 64-bit PHP with curl and openssl');
    }
    require_once __DIR__ . '/mega_wrapper.php';
    try {
        // No session, account credentials, or private file handles are accepted.
        $info = MegaApi::api(['a' => 'g', 'g' => 1, 'p' => $handle, 'ssl' => 2]);
        if (!is_array($info) || !isset($info['s'], $info['at'], $info['g'])) {
            fm_share_fail($info === -17 ? 503 : 404, 'File unavailable or sharing has been disabled');
        }
        if (!is_int($info['s']) || $info['s'] < 0) throw new RuntimeException('Invalid file size');
        $size = $info['s'];
        $url = fm_share_upstream_url($info['g']);
        $attrs = MegaApi::cbcD(MegaApi::b64d($info['at']), substr($key, 0, 16) ^ substr($key, 16, 16));
        if (!is_string($attrs) || substr($attrs, 0, 4) !== 'MEGA') fm_share_fail(404, 'Download link not found');
        $attrs = json_decode(rtrim(substr($attrs, 4), "\0"), true);
        if (!is_array($attrs) || !isset($attrs['n']) || !is_string($attrs['n'])) fm_share_fail(404, 'Download link not found');
        $name = preg_replace('/[\x00-\x1f\x7f\/\\\\]/', '_', $attrs['n']);
        $name = $name === '' ? 'download' : $name;
        $etag = '"' . hash('sha256', $token . ':' . $size) . '"';
        $range = $method === 'GET' ? (string)($_SERVER['HTTP_RANGE'] ?? '') : '';
        if (isset($_SERVER['HTTP_IF_RANGE']) && $_SERVER['HTTP_IF_RANGE'] !== $etag) $range = '';
        try { list($start, $end, $partial) = fm_share_range($range, $size); }
        catch (OutOfRangeException $e) {
            header('Content-Range: bytes */' . $size);
            http_response_code(416);
            header('Content-Length: 0');
            exit;
        }
        $length = $size ? $end - $start + 1 : 0;
        @ini_set('zlib.output_compression', '0');
        @set_time_limit(0);
        while (ob_get_level()) ob_end_clean();
        http_response_code($partial ? 206 : 200);
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . str_replace(['"', '\\'], '_', preg_replace('/[^\x20-\x7e]/', '_', $name)) . '"; filename*=UTF-8\'\'' . rawurlencode($name));
        header('Content-Length: ' . $length);
        header('Accept-Ranges: bytes');
        header('ETag: ' . $etag);
        header('X-Accel-Buffering: no');
        if ($partial) header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
        if ($method === 'HEAD' || !$length) exit;
        $aligned = intdiv($start, 16) * 16;
        $expected = $end - $aligned + 1;
        $sent = 0;
        $decoder = new FmShareDecryptor($key, $start, $length, function($plain) use (&$sent) {
            echo $plain; $sent += strlen($plain); flush();
        });
        $ch = curl_init($url . '/' . $aligned . '-' . $end);
        curl_setopt_array($ch, [CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 0, CURLOPT_LOW_SPEED_LIMIT => 1, CURLOPT_LOW_SPEED_TIME => 60,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_WRITEFUNCTION => function($c, $bytes) use ($decoder, $expected) {
                $status = curl_getinfo($c, CURLINFO_HTTP_CODE);
                if (connection_aborted() || !in_array($status, [200, 206], true) || $decoder->received + strlen($bytes) > $expected) return 0;
                $decoder->push($bytes);
                return strlen($bytes);
            }]);
        $ok = curl_exec($ch) !== false && $decoder->received === $expected;
        curl_close($ch);
        if ($ok) $decoder->push('', true);
        if (!$ok && !$sent && !headers_sent()) fm_share_fail(502, 'Download temporarily unavailable. Please retry.');
        // On a mid-stream failure, preserve the advertised length so download
        // clients detect an incomplete response and can resume it.
        exit;
    } catch (Throwable $e) {
        if (!headers_sent()) fm_share_fail(502, 'Download temporarily unavailable. Please retry.');
        exit;
    }
}

// Public downloads are dispatched by mega_require_login only after config.php
// selects MEGA, and before prompting visitors for account credentials.
//Default Configuration
$CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":true,"theme":"light"}';

/**
 * H3K ~ Tiny File Manager V2.6
 * @author CCP Programmers
 * @github https://github.com/prasathmani/tinyfilemanager
 * @link https://tinyfilemanager.github.io
 */

//TFM version
define('VERSION', '2.6');

//Application Title
define('APP_TITLE', 'Tiny File Manager');

// --- EDIT BELOW CONFIGURATION CAREFULLY ---

// Auth with login/password
// set true/false to enable/disable it
// Is independent from IP white- and blacklisting
$use_auth = true;

// Login user name and password
// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
// Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html
$auth_users = array(
    'admin' => '$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW', //admin@123
    'user' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO' //12345
);

// Readonly users
// e.g. array('users', 'guest', ...)
$readonly_users = array(
    'user'
);

// Global readonly, including when auth is not being used
$global_readonly = false;

// user specific directories
// array('Username' => 'Directory path', 'Username2' => 'Directory path', ...)
$directories_users = array();

// Enable highlight.js (https://highlightjs.org/) on view's page
$use_highlightjs = true;

// highlight.js style
// for dark theme use 'ir-black'
$highlightjs_style = 'vs';

// Enable ace.js (https://ace.c9.io/) on view's page
$edit_files = true;

// Default timezone for date() and time()
// Doc - http://php.net/manual/en/timezones.php
$default_timezone = 'Etc/UTC'; // UTC

// Root path for file manager
// use absolute path of directory i.e: '/var/www/folder' or $_SERVER['DOCUMENT_ROOT'].'/folder'
//make sure update $root_url in next section
$root_path = $_SERVER['DOCUMENT_ROOT'];

// Root url for links in file manager.Relative to $http_host. Variants: '', 'path/to/subfolder'
// Will not working if $root_path will be outside of server document root
$root_url = '';

// Server hostname. Can set manually if wrong
// $_SERVER['HTTP_HOST'].'/folder'
$http_host = $_SERVER['HTTP_HOST'];

// input encoding for iconv
$iconv_input_encoding = 'UTF-8';

// date() format for file modification date
// Doc - https://www.php.net/manual/en/function.date.php
$datetime_format = 'm/d/Y g:i A';

// Path display mode when viewing file information
// 'full' => show full path
// 'relative' => show path relative to root_path
// 'host' => show path on the host
$path_display_mode = 'full';

// Allowed file extensions for create and rename files
// e.g. 'txt,html,css,js'
$allowed_file_extensions = '';

// Allowed file extensions for upload files
// e.g. 'gif,png,jpg,html,txt'
$allowed_upload_extensions = '';

// Favicon path. This can be either a full url to an .PNG image, or a path based on the document root.
// full path, e.g http://example.com/favicon.png
// local path, e.g images/icons/favicon.png
$favicon_path = '';

// Files and folders to excluded from listing
// e.g. array('myfile.html', 'personal-folder', '*.php', '/path/to/folder', ...)
$exclude_items = array();

// Online office Docs Viewer
// Available rules are 'google', 'microsoft' or false
// Google => View documents using Google Docs Viewer
// Microsoft => View documents using Microsoft Web Apps Viewer
// false => disable online doc viewer
$online_viewer = 'google';

// Sticky Nav bar
// true => enable sticky header
// false => disable sticky header
$sticky_navbar = true;

// Maximum file upload size
// Increase the following values in php.ini to work properly
// memory_limit, upload_max_filesize, post_max_size
$max_upload_size_bytes = 5000000000; // size 5,000,000,000 bytes (~5GB)

// chunk size used for upload
// eg. decrease to 1MB if nginx reports problem 413 entity too large
$upload_chunk_size_bytes = 2000000; // chunk size 2,000,000 bytes (~2MB)

// Possible rules are 'OFF', 'AND' or 'OR'
// OFF => Don't check connection IP, defaults to OFF
// AND => Connection must be on the whitelist, and not on the blacklist
// OR => Connection must be on the whitelist, or not on the blacklist
$ip_ruleset = 'OFF';

// Should users be notified of their block?
$ip_silent = true;

// IP-addresses, both ipv4 and ipv6
$ip_whitelist = array(
    '127.0.0.1',    // local ipv4
    '::1'           // local ipv6
);

// IP-addresses, both ipv4 and ipv6
$ip_blacklist = array(
    '0.0.0.0',      // non-routable meta ipv4
    '::'            // non-routable meta ipv6
);

// extension => language for advanced editor
$ext_language = array(
    'js' => 'javascript',
    'ts' => 'typescript',
    'py' => 'python',
    'c' => 'c_cpp',
    'h' => 'c_cpp',
    'cpp' => 'c_cpp',
    'hpp' => 'c_cpp',
    'rs' => 'rust',
    'yml' => 'yaml',
    'bat' => 'batchfile',
    'go' => 'golang',
    'md' => 'markdown',
    'hbs' => 'handlebars',
    'cs' => 'csharp',
    'ps1' => 'powershell',
    'htm' => 'html',
    'htaccess' => 'apache_conf',
);

// if User has the external config file, try to use it to override the default config above [config.php]
// sample config - https://tinyfilemanager.github.io/config-sample.txt
$config_file = __DIR__ . '/config.php';
if (is_readable($config_file)) {
    @include($config_file);
}

define('FM_STORAGE_TYPE', isset($storage_type) ? $storage_type : 'local');
if (isset($_GET['share']) || isset($_GET['mega_link']) || isset($_GET['mega_shared_links'])) {
    fm_share_require_mega();
}

define('ACE_FONTSIZE', isset($ace_fontsize) ? $ace_fontsize : 12);
define('ACE_THEME', isset($ace_theme) ? $ace_theme : 'textmate');

// External CDN resources that can be used in the HTML (replace for GDPR compliance)
$external = array(
    'css-bootstrap' => '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">',
    'css-dropzone' => '<link href="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.css" rel="stylesheet">',
    'css-font-awesome' => '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css" crossorigin="anonymous">',
    'css-highlightjs' => '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/' . $highlightjs_style . '.min.css">',
    'js-ace' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.2/ace.js"></script>',
    'js-bootstrap' => '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>',
    'js-dropzone' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.js"></script>',
    'js-jquery' => '<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>',
    'js-jquery-datatables' => '<script src="https://cdn.datatables.net/1.13.1/js/jquery.dataTables.min.js" crossorigin="anonymous" defer></script>',
    'js-highlightjs' => '<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>',
    'pre-jsdelivr' => '<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin/><link rel="dns-prefetch" href="https://cdn.jsdelivr.net"/>',
    'pre-cloudflare' => '<link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin/><link rel="dns-prefetch" href="https://cdnjs.cloudflare.com"/>'
);

// --- EDIT BELOW CAREFULLY OR DO NOT EDIT AT ALL ---

// max upload file size
define('MAX_UPLOAD_SIZE', $max_upload_size_bytes);

// upload chunk size
define('UPLOAD_CHUNK_SIZE', $upload_chunk_size_bytes);

// private key and session name to store to the session
if (!defined('FM_SESSION_ID')) {
    define('FM_SESSION_ID', 'filemanager');
}

// Configuration
$cfg = new FM_Config();

// Default language
$lang = isset($cfg->data['lang']) ? $cfg->data['lang'] : 'en';

// Show or hide files and folders that starts with a dot
$show_hidden_files = isset($cfg->data['show_hidden']) ? $cfg->data['show_hidden'] : true;

// PHP error reporting - false = Turns off Errors, true = Turns on Errors
$report_errors = isset($cfg->data['error_reporting']) ? $cfg->data['error_reporting'] : true;

// Hide Permissions and Owner cols in file-listing
$hide_Cols = true; // MEGA has no meaningful POSIX owner/permissions columns

// Theme
$theme = isset($cfg->data['theme']) ? $cfg->data['theme'] : 'light';


//available languages
$lang_list = array(
    'en' => 'English'
);

// Load available language codes before validating saved browser preferences.
// Previously the list contained only 'en' at that point, so saved languages
// such as 'zh-TW' were discarded on every page load.
$mega_language_file = __DIR__ . '/translation.json';
if (is_readable($mega_language_file)) {
    $mega_language_data = json_decode(@file_get_contents($mega_language_file), true);
    if (is_array($mega_language_data) && isset($mega_language_data['language']) && is_array($mega_language_data['language'])) {
        foreach ($mega_language_data['language'] as $mega_language_entry) {
            if (is_array($mega_language_entry) &&
                isset($mega_language_entry['code'], $mega_language_entry['name']) &&
                is_string($mega_language_entry['code']) &&
                is_string($mega_language_entry['name'])) {
                $lang_list[$mega_language_entry['code']] = $mega_language_entry['name'];
            }
        }
    }
}
unset($mega_language_file, $mega_language_data, $mega_language_entry);

if ($report_errors == true) {
    @ini_set('error_reporting', E_ALL);
    @ini_set('display_errors', 1);
} else {
    @ini_set('error_reporting', E_ALL);
    @ini_set('display_errors', 0);
}

// if fm included
if (defined('FM_EMBED')) {
    $use_auth = false;
    $sticky_navbar = false;
} else {
    @set_time_limit(600);

    date_default_timezone_set($default_timezone);

    ini_set('default_charset', 'UTF-8');
    if (version_compare(PHP_VERSION, '5.6.0', '<') && function_exists('mb_internal_encoding')) {
        mb_internal_encoding('UTF-8');
    }
    if (function_exists('mb_regex_encoding')) {
        mb_regex_encoding('UTF-8');
    }

    session_cache_limiter('nocache'); // Prevent logout issue after page was cached
    session_name(FM_SESSION_ID);
    function session_error_handling_function($code, $msg, $file, $line)
    {
        // Permission denied for default session, try to create a new one
        if ($code == 2) {
            session_abort();
            session_id(session_create_id());
            @session_start();
        }
    }
    set_error_handler('session_error_handling_function');
    session_start();
    restore_error_handler();
}

//Generating CSRF Token
if (empty($_SESSION['token'])) {
    if (function_exists('random_bytes')) {
        $_SESSION['token'] = bin2hex(random_bytes(32));
    } else {
        $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
}

if (empty($auth_users)) {
    $use_auth = false;
}

$is_https = isset($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) == 'on' || $_SERVER['HTTPS'] == 1)
    || isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https';

// update $root_url based on user specific directories
if (isset($_SESSION[FM_SESSION_ID]['logged']) && !empty($directories_users[$_SESSION[FM_SESSION_ID]['logged']])) {
    $wd = fm_clean_path(dirname($_SERVER['PHP_SELF']));
    $root_url =  $root_url . $wd . DIRECTORY_SEPARATOR . $directories_users[$_SESSION[FM_SESSION_ID]['logged']];
}
// clean $root_url
$root_url = fm_clean_path($root_url);

// abs path for site
defined('FM_ROOT_URL') || define('FM_ROOT_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . (!empty($root_url) ? '/' . $root_url : ''));
defined('FM_SELF_URL') || define('FM_SELF_URL', ($is_https ? 'https' : 'http') . '://' . $http_host . $_SERVER['PHP_SELF']);

// logout
if (isset($_GET['logout'])) {
    unset($_SESSION[FM_SESSION_ID]['logged']);
    unset($_SESSION['token']);
    fm_redirect(FM_SELF_URL);
}

// Validate connection IP
if ($ip_ruleset != 'OFF') {
    function getClientIP()
    {
        if (array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER)) {
            return  $_SERVER["HTTP_CF_CONNECTING_IP"];
        } else if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
            return  $_SERVER["HTTP_X_FORWARDED_FOR"];
        } else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
            return $_SERVER['REMOTE_ADDR'];
        } else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
            return $_SERVER['HTTP_CLIENT_IP'];
        }
        return '';
    }

    $clientIp = getClientIP();
    $proceed = false;
    $whitelisted = in_array($clientIp, $ip_whitelist);
    $blacklisted = in_array($clientIp, $ip_blacklist);

    if ($ip_ruleset == 'AND') {
        if ($whitelisted == true && $blacklisted == false) {
            $proceed = true;
        }
    } else
    if ($ip_ruleset == 'OR') {
        if ($whitelisted == true || $blacklisted == false) {
            $proceed = true;
        }
    }

    if ($proceed == false) {
        trigger_error('User connection denied from: ' . $clientIp, E_USER_WARNING);

        if ($ip_silent == false) {
            fm_set_msg(lng('Access denied. IP restriction applicable'), 'error');
            fm_show_header_login();
            fm_show_message();
        }
        exit();
    }
}

// Checking if the user is logged in or not. If not, it will show the login form.
if ($use_auth) {
    if (isset($_SESSION[FM_SESSION_ID]['logged'], $auth_users[$_SESSION[FM_SESSION_ID]['logged']])) {
        // Logged
    } elseif (isset($_POST['fm_usr'], $_POST['fm_pwd'])) {
        // Logging In
        sleep(1);
        if (function_exists('password_verify')) {
            $auditUser = is_string($_POST['fm_usr']) ? $_POST['fm_usr'] : '';
            $validToken = isset($_POST['token']) && is_string($_POST['token']) && verifyToken($_POST['token']);
            $validCredentials = is_string($_POST['fm_usr']) && is_string($_POST['fm_pwd']) && isset($auth_users[$auditUser]) && password_verify($_POST['fm_pwd'], $auth_users[$auditUser]);
            if ($validCredentials && $validToken) {
                $_SESSION[FM_SESSION_ID]['logged'] = $_POST['fm_usr'];
                fm_log_user_login($auditUser, true);
                fm_set_msg(lng('You are logged in'));
                fm_redirect(FM_SELF_URL);
            } else {
                fm_log_user_login($auditUser, false, !$validToken ? 'invalid_security_token' : 'invalid_credentials');
                unset($_SESSION[FM_SESSION_ID]['logged']);
                fm_set_msg(lng('Login failed. Invalid username or password'), 'error');
                fm_redirect(FM_SELF_URL);
            }
        } else {
            fm_set_msg(lng('password_hash not supported, Upgrade PHP version'), 'error');;
        }
    } else {
        // Form
        unset($_SESSION[FM_SESSION_ID]['logged']);
        fm_show_header_login();
?>
        <section class="h-100">
            <div class="container h-100">
                <div class="row justify-content-md-center align-content-center h-100vh">
                    <div class="card-wrapper">
                        <div class="card fat" data-bs-theme="<?php echo FM_THEME; ?>">
                            <div class="card-body">
                                <form class="form-signin" action="" method="post" autocomplete="off">
                                    <div class="mb-3">
                                        <div class="brand">
                                            <svg version="1.0" xmlns="http://www.w3.org/2000/svg" M1008 width="100%" height="80px" viewBox="0 0 238.000000 140.000000" aria-label="H3K Tiny File Manager">
                                                <g transform="translate(0.000000,140.000000) scale(0.100000,-0.100000)" fill="#000000" stroke="none">
                                                    <path d="M160 700 l0 -600 110 0 110 0 0 260 0 260 70 0 70 0 0 -260 0 -260 110 0 110 0 0 600 0 600 -110 0 -110 0 0 -260 0 -260 -70 0 -70 0 0 260 0 260 -110 0 -110 0 0 -600z" />
                                                    <path fill="#003500" d="M1008 1227 l-108 -72 0 -117 0 -118 110 0 110 0 0 110 0 110 70 0 70 0 0 -180 0 -180 -125 0 c-69 0 -125 -3 -125 -6 0 -3 23 -39 52 -80 l52 -74 73 0 73 0 0 -185 0 -185 -70 0 -70 0 0 115 0 115 -110 0 -110 0 0 -190 0 -190 181 0 181 0 109 73 108 72 1 181 0 181 -69 48 -68 49 68 50 69 49 0 249 0 248 -182 -1 -183 0 -107 -72z" />
                                                    <path d="M1640 700 l0 -600 110 0 110 0 0 208 0 208 35 34 35 34 35 -34 35 -34 0 -208 0 -208 110 0 110 0 0 212 0 213 -87 87 -88 88 88 88 87 87 0 213 0 212 -110 0 -110 0 0 -208 0 -208 -70 -69 -70 -69 0 277 0 277 -110 0 -110 0 0 -600z" />
                                                </g>
                                            </svg>
                                        </div>
                                        <div class="text-center">
                                            <h1 class="card-title"><?php echo APP_TITLE; ?></h1>
                                        </div>
                                    </div>
                                    <hr />
                                    <div class="mb-3">
                                        <p class="text-secondary"><?php echo lng('Sign in to your account'); ?></p>
                                        <label for="fm_usr" class="pb-2"><?php echo lng('Username'); ?></label>
                                        <input type="text" class="form-control" id="fm_usr" name="fm_usr" required autofocus>
                                    </div>

                                    <div class="mb-3">
                                        <label for="fm_pwd" class="pb-2"><?php echo lng('Password'); ?></label>
                                        <div class="fm-login-password-wrap">
                                            <input type="password" class="form-control" id="fm_pwd" name="fm_pwd" required autocomplete="current-password">
                                            <button type="button" class="fm-password-toggle" id="fm_password_toggle" aria-label="<?php echo lng('Show password') ?>" aria-pressed="false" title="Show password">
                                                <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path class="fm-eye-slash" d="M3 3l18 18" style="display:none"/></svg>
                                            </button>
                                        </div>
                                    </div>

                                    <div class="mb-3">
                                        <?php fm_show_message(); ?>
                                    </div>
                                    <input type="hidden" name="token" value="<?php echo htmlentities($_SESSION['token']); ?>" />
                                    <div class="mb-3">
                                        <button type="submit" class="btn btn-success fm-login-submit w-100">
                                            <?php echo lng('Login'); ?>
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        <div class="footer text-center">
                            &mdash;&mdash; &copy;
                            <a href="https://tinyfilemanager.github.io/" target="_blank" class="text-decoration-none text-muted" data-version="<?php echo VERSION; ?>">CCP Programmers</a> &mdash;&mdash;
                        </div>
                    </div>
                </div>
            </div>
        </section>

    <?php
        ?>
        <script>
        (function () {
            var toggle = document.getElementById('fm_password_toggle');
            var password = document.getElementById('fm_pwd');
            if (!toggle || !password) return;
            toggle.addEventListener('click', function () {
                var visible = password.type === 'password';
                password.type = visible ? 'text' : 'password';
                toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
                toggle.setAttribute('title', visible ? 'Hide password' : 'Show password');
                toggle.setAttribute('aria-pressed', visible ? 'true' : 'false');
                var slash = toggle.querySelector('.fm-eye-slash');
                if (slash) slash.style.display = visible ? '' : 'none';
            });
        }());
        </script>
        <?php
        fm_show_footer_login();
        exit;
    }
}

// update root path
if ($use_auth && isset($_SESSION[FM_SESSION_ID]['logged'])) {
    $root_path = isset($directories_users[$_SESSION[FM_SESSION_ID]['logged']]) ? $directories_users[$_SESSION[FM_SESSION_ID]['logged']] : $root_path;
}

// Browser-only personal preferences. The cookie allows PHP to apply the
// preferences while rendering; localStorage is the durable browser copy.
// The cookie name is scoped to the authenticated MEGA account (never the password).
$mega_pref_identity = !empty($GLOBALS['mega_authenticated_pref_id']) ? $GLOBALS['mega_authenticated_pref_id'] : 'guest';
$mega_pref_cookie = 'mega_fm_prefs_' . substr($mega_pref_identity, 0, 24);
$mega_pref_storage = 'mega_fm_prefs_v1_' . $mega_pref_identity;
$mega_pref_values = array();
if (isset($_COOKIE[$mega_pref_cookie]) && strlen($_COOKIE[$mega_pref_cookie]) <= 2048) {
    $decoded = json_decode($_COOKIE[$mega_pref_cookie], true);
    if (is_array($decoded)) $mega_pref_values = $decoded;
}
if (isset($mega_pref_values['theme']) && in_array($mega_pref_values['theme'], array('light','dark'), true)) $theme = $mega_pref_values['theme'];
if (isset($mega_pref_values['lang']) && in_array($mega_pref_values['lang'], array_keys($lang_list), true)) $lang = $mega_pref_values['lang'];
if (isset($mega_pref_values['show_hidden']) && is_bool($mega_pref_values['show_hidden'])) $show_hidden_files = $mega_pref_values['show_hidden'];
// Layout follows an explicit browser preference; old preferences default to Auto.
$mega_view_mode = isset($mega_pref_values['view_mode']) && in_array($mega_pref_values['view_mode'], array('auto', 'mobile', 'desktop'), true) ? $mega_pref_values['view_mode'] : 'auto';
define('FM_VIEW_MODE', $mega_view_mode);
// MEGA deletion is a per-browser account preference; default to recoverable deletion.
define('FM_DELETE_MODE', isset($mega_pref_values['delete_mode']) && $mega_pref_values['delete_mode']==='permanent' ? 'permanent' : 'rubbish');
// Browser identity is a layout hint only; explicit user choices take priority.
function fm_browser_prefers_desktop($server) {
    $mobile = trim((string)($server['HTTP_SEC_CH_UA_MOBILE'] ?? ''));
    if ($mobile === '?1') return false;
    if ($mobile === '?0') return true;
    $ua = (string)($server['HTTP_USER_AGENT'] ?? '');
    if (preg_match('/Android|Mobile|iPhone|iPad|iPod/i', $ua)) return false;
    return (bool)preg_match('/Windows NT|Macintosh|X11|CrOS/i', $ua);
}
function fm_layout_media_query() {
    $mode = defined('FM_VIEW_MODE') ? FM_VIEW_MODE : 'auto';
    if ($mode === 'mobile') return '(min-width:0px)';
    if ($mode === 'desktop' || ($mode === 'auto' && defined('FM_AUTO_DESKTOP') && FM_AUTO_DESKTOP)) return '(max-width:0px)';
    return '(max-width:991px)';
}
function fm_desktop_media_query() {
    $mobile = fm_layout_media_query();
    if ($mobile === '(min-width:0px)') return '(max-width:0px)';
    if ($mobile === '(max-width:0px)') return '(min-width:0px)';
    return '(min-width:992px)';
}
define('FM_AUTO_DESKTOP', fm_browser_prefers_desktop($_SERVER));

// Define the effective theme only after account-specific browser preferences.
define('FM_THEME', $theme);
// Owner/permissions columns are not applicable to MEGA; keep hidden.
if (isset($mega_pref_values['hide_Cols']) && is_bool($mega_pref_values['hide_Cols'])) $hide_Cols = true;
// Error reporting remains a server administrator setting.
// clean and check $root_path
$root_path = rtrim($root_path, '\\/');
$root_path = str_replace('\\', '/', $root_path);
if (!@is_dir($root_path)) {
    echo "<h1>" . lng('Root path') . " \"{$root_path}\" " . lng('not found!') . " </h1>";
    exit;
}

defined('FM_SHOW_HIDDEN') || define('FM_SHOW_HIDDEN', $show_hidden_files);
defined('FM_ROOT_PATH') || define('FM_ROOT_PATH', $root_path);
defined('FM_LANG') || define('FM_LANG', $lang);
defined('FM_FILE_EXTENSION') || define('FM_FILE_EXTENSION', $allowed_file_extensions);
defined('FM_UPLOAD_EXTENSION') || define('FM_UPLOAD_EXTENSION', $allowed_upload_extensions);
defined('FM_EXCLUDE_ITEMS') || define('FM_EXCLUDE_ITEMS', (version_compare(PHP_VERSION, '7.0.0', '<') ? serialize($exclude_items) : $exclude_items));
defined('FM_DOC_VIEWER') || define('FM_DOC_VIEWER', $online_viewer);
define('FM_READONLY', $global_readonly || ($use_auth && !empty($readonly_users) && isset($_SESSION[FM_SESSION_ID]['logged']) && in_array($_SESSION[FM_SESSION_ID]['logged'], $readonly_users)));
define('FM_IS_WIN', DIRECTORY_SEPARATOR == '\\');

// always use ?p=
if (!isset($_GET['p']) && empty($_FILES)) {
    fm_redirect(FM_SELF_URL . '?p=');
}

// get path
$p = isset($_GET['p']) ? $_GET['p'] : (isset($_POST['p']) ? $_POST['p'] : '');

// clean path
$p = fm_clean_path($p);

// for ajax request - save
$input = file_get_contents('php://input');
$_POST = (strpos($input, 'ajax') != FALSE && strpos($input, 'save') != FALSE) ? json_decode($input, true) : $_POST;

// instead globals vars
define('FM_PATH', $p);
// Reject symlink-based escapes and paths outside the local storage root.
if (FM_STORAGE_TYPE === 'local') {
    $candidate = FM_ROOT_PATH;
    foreach (explode('/', trim($p, '/')) as $part) {
        if ($part === '') continue;
        if ($part === '.' || $part === '..' || strpos($part, "\\") !== false) {
            http_response_code(403); exit('Invalid local path');
        }
        $candidate .= '/' . $part;
        if (is_link($candidate)) { http_response_code(403); exit('Symlink navigation is disabled'); }
    }
    if (file_exists($candidate)) {
        $resolvedCandidate = realpath($candidate);
        if ($resolvedCandidate === false || ($resolvedCandidate !== FM_ROOT_PATH &&
            strpos($resolvedCandidate, FM_ROOT_PATH . '/') !== 0)) {
            http_response_code(403); exit('Local path is outside storage root');
        }
    }
}

define('FM_USE_AUTH', $use_auth);
define('FM_EDIT_FILE', $edit_files);
defined('FM_ICONV_INPUT_ENC') || define('FM_ICONV_INPUT_ENC', $iconv_input_encoding);
defined('FM_USE_HIGHLIGHTJS') || define('FM_USE_HIGHLIGHTJS', $use_highlightjs);
defined('FM_HIGHLIGHTJS_STYLE') || define('FM_HIGHLIGHTJS_STYLE', $highlightjs_style);
defined('FM_DATETIME_FORMAT') || define('FM_DATETIME_FORMAT', $datetime_format);

unset($p, $use_auth, $iconv_input_encoding, $use_highlightjs, $highlightjs_style);

// Integrated MEGA search: shared header, breadcrumb and navigation with every other page.
if (isset($_GET['local_tools']) && FM_STORAGE_TYPE === 'local') {
    fm_local_search_page();
    exit;
}
if (FM_STORAGE_TYPE === 'mega' && isset($_GET['mega_rubbish'])) {
    fm_mega_rubbish_page();
    exit;
}
if (FM_STORAGE_TYPE === 'mega' && isset($_GET['mega_shared_links'])) {
    fm_mega_shared_links_page();
    exit;
}
if (FM_STORAGE_TYPE === 'mega' && isset($_GET['mega_link'])) {
    fm_mega_link_page();
    exit;
}
if (isset($_GET['mega_tools']) && FM_STORAGE_TYPE === 'mega') {
    fm_mega_search_page();
    exit;
}

/*************************** ACTIONS ***************************/

// Handle all AJAX Request
if ((isset($_SESSION[FM_SESSION_ID]['logged'], $auth_users[$_SESSION[FM_SESSION_ID]['logged']]) || !FM_USE_AUTH) && isset($_POST['ajax'], $_POST['token'])) {
    if (!verifyToken($_POST['token'])) {
        header('HTTP/1.0 401 Unauthorized');
        die("Invalid Token.");
    }

    //search : get list of files from the current folder
    if (isset($_POST['type']) && $_POST['type'] == "search") {
        $dir = $_POST['path'] == "." ? '' : $_POST['path'];
        $response = scan(fm_clean_path($dir), $_POST['content']);
        echo json_encode($response);
        exit();
    }

    if(FM_READONLY){
        exit();
    }

    // save editor file
    if (isset($_POST['type']) && $_POST['type'] == "save") {
        // get current path
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        // check path
        if (!is_dir($path)) {
            fm_redirect(FM_SELF_URL . '?p=');
        }
        $file = $_GET['edit'];
        $file = fm_clean_path($file);
        $file = str_replace('/', '', $file);
        if ($file == '' || !is_file($path . '/' . $file)) {
            fm_set_msg(lng('File not found'), 'error');
            $FM_PATH = FM_PATH;
            fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
        }
        header('X-XSS-Protection:0');
        $file_path = $path . '/' . $file;

        $writedata = $_POST['content'];
        $fd = fopen($file_path, "w");
        $write_results = @fwrite($fd, $writedata);
        fclose($fd);
        if ($write_results === false) {
            header("HTTP/1.1 500 Internal Server Error");
            die("Could Not Write File! - Check Permissions / Ownership");
        }
        die(true);
    }

    // backup files
    if (isset($_POST['type']) && $_POST['type'] == "backup" && !empty($_POST['file'])) {
        $fileName = fm_clean_path($_POST['file']);
        $fullPath = FM_ROOT_PATH . '/';
        if (!empty($_POST['path'])) {
            $relativeDirPath = fm_clean_path($_POST['path']);
            $fullPath .= "{$relativeDirPath}/";
        }
        $date = date("dMy-His");
        $newFileName = "{$fileName}-{$date}.bak";
        $fullyQualifiedFileName = $fullPath . $fileName;
        try {
            if (!file_exists($fullyQualifiedFileName)) {
                throw new Exception("File {$fileName} not found");
            }
            if (copy($fullyQualifiedFileName, $fullPath . $newFileName)) {
                echo "Backup {$newFileName} created";
            } else {
                throw new Exception("Could not copy file {$fileName}");
            }
        } catch (Exception $e) {
            echo $e->getMessage();
        }
    }

    // Settings are browser-specific; refuse legacy server-side saves.
    if (isset($_POST['type']) && $_POST['type'] == "settings") {
        http_response_code(400);
        echo 'Preferences must be saved in this browser.';
    }

    // new password hash
    if (isset($_POST['type']) && $_POST['type'] == "pwdhash") {
        $res = isset($_POST['inputPassword2']) && !empty($_POST['inputPassword2']) ? password_hash($_POST['inputPassword2'], PASSWORD_DEFAULT) : '';
        echo $res;
    }

    // URL upload status: separate short request, so a slow MEGA response cannot
    // keep the upload form spinning after the operation has finished.
    if (isset($_POST['type']) && $_POST['type'] === 'url_upload_status') {
        header('Content-Type: application/json; charset=utf-8');
        $id = isset($_POST['upload_id']) ? (string)$_POST['upload_id'] : '';
        if (!preg_match('/^[a-zA-Z0-9_-]{12,64}$/', $id)) {
            echo json_encode(array('state' => 'invalid')); exit();
        }
        $key = hash('sha256', session_id() . ':' . $id);
        $statusFile = sys_get_temp_dir() . '/mega-url-status-' . $key . '.json';
        $data = @file_get_contents($statusFile);
        $state = $data ? json_decode($data, true) : null;
        echo json_encode(is_array($state) ? $state : array('state' => 'pending'));
        exit();
    }

    //upload using url
    if (isset($_POST['type']) && $_POST['type'] == "upload" && !empty($_REQUEST["uploadurl"])) {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }

        $urlUploadId = isset($_POST['upload_id']) ? (string)$_POST['upload_id'] : '';
        $urlStatusFile = null;
        if (preg_match('/^[a-zA-Z0-9_-]{12,64}$/', $urlUploadId)) {
            $urlStatusFile = sys_get_temp_dir() . '/mega-url-status-' . hash('sha256', session_id() . ':' . $urlUploadId) . '.json';
            @file_put_contents($urlStatusFile, json_encode(array('state' => 'uploading')));
        }
        // Allow status polls while MEGA is doing network operations.
        if (session_status() === PHP_SESSION_ACTIVE) session_write_close();

        function event_callback($message)
        {
            global $callback, $urlStatusFile;
            if ($urlStatusFile !== null) {
                $status = isset($message['done']) ? array('state' => 'done', 'name' => $message['done']->name ?? '') : array('state' => 'failed', 'message' => $message['fail']['message'] ?? 'URL upload failed');
                @file_put_contents($urlStatusFile, json_encode($status));
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($message);
        }

        function get_file_path()
        {
            global $path, $fileinfo, $temp_file;
            return $path . "/" . basename($fileinfo->name);
        }

        $url = !empty($_REQUEST["uploadurl"]) && preg_match("|^http(s)?://.+$|", stripslashes($_REQUEST["uploadurl"])) ? stripslashes($_REQUEST["uploadurl"]) : null;

        //prevent 127.* domain and known ports
        $domain = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT);
        $knownPorts = [22, 23, 25, 3306];

        if (preg_match("/^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$/i", $domain) || in_array($port, $knownPorts)) {
            $err = array("message" => "URL is not allowed");
            event_callback(array("fail" => $err));
            exit();
        }

        // Download to a local temporary file first; do not stream a remote URL
        // directly into MEGA. Network requests must have finite timeouts.
        $temp_file = tempnam(sys_get_temp_dir(), 'upload-');
        $fileinfo = new stdClass();
        $urlPath = parse_url($url, PHP_URL_PATH);
        $fileinfo->name = basename(rawurldecode((string)$urlPath));
        $fileinfo->name = trim($fileinfo->name, ".\x00..\x20");
        if ($fileinfo->name === '' || $fileinfo->name === '.' || $fileinfo->name === '..') $fileinfo->name = 'download';
        $allowed = FM_UPLOAD_EXTENSION ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $ext = strtolower(pathinfo($fileinfo->name, PATHINFO_EXTENSION));
        if ($allowed && !in_array($ext, $allowed, true)) {
            event_callback(array('fail' => array('message' => 'File extension is not allowed')));
            @unlink($temp_file);
            exit();
        }
        $success = false;
        $err = null;
        if (!function_exists('curl_init')) {
            $err = array('message' => 'cURL is required for URL upload');
        } else {
            $fp = @fopen($temp_file, 'wb');
            if (!$fp) {
                $err = array('message' => 'Cannot create temporary download file');
            } else {
                $ch = curl_init($url);
                curl_setopt_array($ch, array(
                    CURLOPT_FILE => $fp,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_CONNECTTIMEOUT => 15,
                    CURLOPT_TIMEOUT => 90,
                    CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
                    CURLOPT_USERAGENT => 'MEGA-FileManager/1.0',
                ));
                $downloaded = curl_exec($ch);
                $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError = curl_error($ch);
                curl_close($ch);
                fclose($fp);
                if (!$downloaded || $httpCode < 200 || $httpCode >= 300) {
                    $err = array('message' => $curlError ?: ('Download failed (HTTP ' . $httpCode . ')'));
                } else {
                    $fileinfo->size = filesize($temp_file);
                    $target = get_file_path();
                    if (strpos($target, 'mega://') === 0) {
                        try {
                            // Resolve the complete mega://root/... URL through MegaFS.
                            // MegaApi::find() expects a root-relative path (e.g. "share"),
                            // not "root/share". parentOf() handles this consistently.
                            $destination = MegaFS::parentOf($target);
                            if ($destination === null) {
                                $err = array('message' => 'Destination folder not found');
                            } elseif (MegaFS::node($target) !== null) {
                                $err = array('message' => 'File already exists: ' . $fileinfo->name);
                            } else {
                                $success = MegaApi::upload($temp_file, $destination[0], $destination[1]);
                            }
                        } catch (Throwable $e) {
                            error_log('MEGA URL upload failed: ' . $e->getMessage());
                            $err = array('message' => 'MEGA upload failed');
                        }
                    } else {
                        $localDestination = rtrim($target, '/') . '/' . $fileinfo->name;
                        if (is_dir($target) && !file_exists($localDestination)) {
                            $success = @rename($temp_file, $localDestination);
                        } else {
                            $err = array('message' => 'Destination unavailable or file already exists');
                        }
                    }
                    if (!$success && !$err) $err = array('message' => 'Could not save downloaded file');
                }
            }
        }
        @unlink($temp_file);
        if ($success) event_callback(array('done' => $fileinfo));
        else event_callback(array('fail' => $err ?: array('message' => 'URL upload failed')));
    }
    exit();
}

// Delete file / folder
if (isset($_GET['del'], $_POST['token']) && !FM_READONLY) {
    $del = str_replace('/', '', fm_clean_path($_GET['del']));
    if ($del != '' && $del != '..' && $del != '.' && verifyToken($_POST['token'])) {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        $is_dir = is_dir($path . '/' . $del);
        if (fm_delete_user_item($path . '/' . $del)) {
            $msg = $is_dir ? lng('Folder') . ' <b>%s</b> ' . lng('Deleted') : lng('File') . ' <b>%s</b> ' . lng('Deleted');
            fm_set_msg(sprintf($msg, fm_enc($del)));
        } else {
            $msg = $is_dir ? lng('Folder') . ' <b>%s</b> ' . lng('not deleted') : lng('File') . ' <b>%s</b> ' . lng('not deleted');
            fm_set_msg(sprintf($msg, fm_enc($del)), 'error');
        }
    } else {
        fm_set_msg(lng('Invalid file or folder name'), 'error');
    }
    $FM_PATH = FM_PATH;
    fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Create a new file/folder
if (isset($_POST['newfilename'], $_POST['newfile'], $_POST['token']) && !FM_READONLY) {
    $type = urldecode($_POST['newfile']);
    $new = str_replace('/', '', fm_clean_path(strip_tags($_POST['newfilename'])));
    if (fm_isvalid_filename($new) && $new != '' && $new != '..' && $new != '.' && verifyToken($_POST['token'])) {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        if ($type == "file") {
            if (!file_exists($path . '/' . $new)) {
                if (fm_is_valid_ext($new)) {
                    @fopen($path . '/' . $new, 'w') or die('Cannot open file:  ' . $new);
                    fm_set_msg(sprintf(lng('File') . ' <b>%s</b> ' . lng('Created'), fm_enc($new)));
                } else {
                    fm_set_msg(lng('File extension is not allowed'), 'error');
                }
            } else {
                fm_set_msg(lng('File already exists: ') . fm_enc($new), 'error');
            }
        } else {
            if (fm_mega_destination_exists($path . '/' . $new)) {
                fm_set_msg(lng('File already exists: ') . fm_enc($new), 'error');
            } elseif (fm_mkdir($path . '/' . $new, false) === true) {
                fm_set_msg(sprintf(lng('Folder') . ' <b>%s</b> ' . lng('Created'), $new));
            } elseif (fm_mkdir($path . '/' . $new, false) === $path . '/' . $new) {
                fm_set_msg(lng('File already exists: ') . fm_enc($new), 'error');
            } else {
                fm_set_msg(sprintf(lng('Folder') . ' <b>%s</b> ' . lng('not created'), fm_enc($new)), 'error');
            }
        }
    } else {
        fm_set_msg(lng('Invalid characters in file or folder name'), 'error');
    }
    $FM_PATH = FM_PATH;
    fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Single-item Copy/Move links use GET (folder picker), not the bulk POST form.
// Handle these requests explicitly; previously finish=1 was silently ignored.
if (isset($_GET['copy'], $_GET['finish']) && !FM_READONLY) {
    $copyRelative = fm_clean_path($_GET['copy']);
    $destinationRelative = FM_PATH;
    $source = rtrim(FM_ROOT_PATH, '/') . '/' . $copyRelative;
    $destinationFolder = rtrim(FM_ROOT_PATH, '/') . ($destinationRelative !== '' ? '/' . $destinationRelative : '');
    $destination = rtrim($destinationFolder, '/') . '/' . basename($copyRelative);
    $isMove = isset($_GET['move']);
    $failure = '';
    if ($copyRelative === '' || !file_exists($source)) {
        $failure = 'Source file or folder does not exist.';
    } elseif (!is_dir($destinationFolder)) {
        $failure = 'Destination folder does not exist or cannot be accessed.';
    } elseif (rtrim($source, '/') === rtrim($destination, '/')) {
        $failure = lng('Source and destination are the same folder.');
    } elseif (is_dir($source) && strpos(rtrim($destination, '/') . '/', rtrim($source, '/') . '/') === 0) {
        $failure = 'Cannot copy or move a folder into itself or a subfolder.';
    } elseif (file_exists($destination)) {
        $failure = lng('File already exists: ') . basename($copyRelative);
    } else {
        try {
            $done = $isMove ? fm_mega_move_checked($source, $destination) : fm_rcopy($source, $destination);
            clearstatcache(true);
            if ($done !== true || !file_exists($destination)) {
                $failure = 'MEGA operation failed or the destination could not be verified.';
            }
        } catch (Throwable $e) {
            error_log('MEGA single copy/move: ' . $e->getMessage());
            $failure = 'MEGA operation failed. Check the server PHP error log.';
        }
    }
    if ($failure !== '') {
        error_log('MEGA single copy/move failed: ' . $failure . ' source=' . $source . ' destination=' . $destination);
        $message = strpos($failure, lng('File already exists: ')) === 0
            ? fm_enc($failure)
            : ($isMove ? 'Move failed: ' : 'Copy failed: ') . fm_enc($failure);
        fm_set_msg($message, 'error');
    } else {
        fm_set_msg(($isMove ? 'Moved successfully: ' : 'Copied successfully: ') . fm_enc(basename($copyRelative)));
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    exit;
}

// Folder picker: lazy-load only the opened level and cache listings per session.
if (isset($_GET['mega_folder_picker']) && $_GET['mega_folder_picker'] === '1') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: private, no-store');
    if (FM_READONLY || !isset($_GET['token']) || !verifyToken($_GET['token'])) {
        http_response_code(403); echo json_encode(array('error' => 'Invalid request')); exit;
    }
    $relative = isset($_GET['dir']) ? fm_clean_path((string)$_GET['dir']) : '';
    if ($relative === '.' || $relative === '/') $relative = '';
    $segments = $relative === '' ? array() : explode('/', $relative);
    foreach ($segments as $segment) {
        if ($segment === '' || $segment === '.' || $segment === '..' || strpos($segment, "\\") !== false) {
            http_response_code(400); echo json_encode(array('error' => 'Invalid folder path')); exit;
        }
    }
    $target = rtrim(FM_ROOT_PATH, '/') . ($relative === '' ? '' : '/' . $relative);
    $cacheKey = hash('sha256', $target . '|' . (string)($_SESSION['mega_folder_cache_revision'] ?? 'initial'));
    if (!isset($_SESSION['mega_folder_picker_cache']) || !is_array($_SESSION['mega_folder_picker_cache'])) {
        $_SESSION['mega_folder_picker_cache'] = array();
    }
    $cached = isset($_SESSION['mega_folder_picker_cache'][$cacheKey]) ? $_SESSION['mega_folder_picker_cache'][$cacheKey] : null;
    if (is_array($cached) && isset($cached['at'], $cached['folders']) && time() - $cached['at'] < 45) {
        echo json_encode(array('path' => $relative, 'folders' => $cached['folders'], 'cached' => true)); exit;
    }
    try {
        if (!is_dir($target)) throw new Exception('Folder does not exist or is inaccessible');
        $snapshot = (strpos($target, 'mega://') === 0 && class_exists('MegaFS')) ? MegaFS::directorySnapshot($target) : false;
        if (is_array($snapshot)) {
            $result = $snapshot['folders'];
        } else {
            $entries = @scandir($target);
            if (!is_array($entries)) throw new Exception('Cannot list folders');
            $result = array();
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') continue;
                if (is_dir(rtrim($target, '/') . '/' . $entry)) $result[] = $entry;
            }
        }
        natcasesort($result); $result = array_values($result);
        if (count($_SESSION['mega_folder_picker_cache']) > 120) $_SESSION['mega_folder_picker_cache'] = array();
        $_SESSION['mega_folder_picker_cache'][$cacheKey] = array('at' => time(), 'folders' => $result);
        echo json_encode(array('path' => $relative, 'folders' => $result, 'cached' => false));
    } catch (Throwable $e) {
        http_response_code(400); echo json_encode(array('error' => $e->getMessage()));
    }
    exit;
}

// Preserve the selections from the Copy form even when browser-side scripts omit
// file[] during submission. Never accept an old selection from another folder.
if (isset($_POST['finish'], $_POST['copy_to'], $_POST['token']) && !FM_READONLY &&
    verifyToken($_POST['token']) && (empty($_POST['file']) || !is_array($_POST['file']))) {
    $saved = isset($_SESSION['mega_copy_selection']) ? $_SESSION['mega_copy_selection'] : null;
    if (is_array($saved) && isset($saved['path'], $saved['time'], $saved['files']) &&
        $saved['path'] === FM_PATH && time() - (int)$saved['time'] <= 900 &&
        is_array($saved['files']) && count($saved['files']) > 0) {
        $_POST['file'] = $saved['files'];
    }
}
// Reject incomplete bulk-copy submissions visibly rather than silently redirecting.
if (isset($_POST['finish']) && isset($_POST['copy_to']) && !isset($_POST['file']) && !FM_READONLY) {
    fm_show_header();
    fm_show_nav_path(FM_PATH);
    echo '<div class="alert alert-danger m-3">' . lng('Copy/Move failed') . ': ' . lng('No files or folders were submitted. Please select items again.') . '</div>';
    fm_show_footer();
    exit;
}

// Mass copy files/ folders
if (isset($_POST['file'], $_POST['copy_to'], $_POST['finish'], $_POST['token']) && !FM_READONLY) {

    if (!verifyToken($_POST['token'])) {
        fm_set_msg(lng('Invalid Token.'), 'error');
        die("Invalid Token.");
    }

    // from
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    // to
    $copy_to_path = FM_ROOT_PATH;
    $copy_to = fm_clean_path($_POST['copy_to']);
    if ($copy_to != '') {
        $copy_to_path .= '/' . $copy_to;
    }
    if ($path == $copy_to_path) {
        fm_set_msg(lng('Source and destination are the same folder.'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }
    // Copy/Move must target an existing folder. Never create the destination
    // implicitly: typos previously caused silent folder creation or no-op copies.
    $destinationValid = false;
    try {
        if (strpos($copy_to_path, 'mega://') === 0) {
            MegaApi::load();
            $remoteDestination = MegaFS::remote($copy_to_path);
            $destinationHandle = $remoteDestination === false ? null : MegaApi::find($remoteDestination);
            $destinationValid = $destinationHandle !== null &&
                isset(MegaApi::$nodes[$destinationHandle]) &&
                (int)MegaApi::$nodes[$destinationHandle]['t'] !== 0;
        } else {
            $destinationValid = is_dir($copy_to_path);
        }
    } catch (Throwable $e) {
        error_log('MEGA copy/move destination check: ' . $e->getMessage());
    }
    if (!$destinationValid) {
        fm_show_header();
        fm_show_nav_path(FM_PATH);
        echo '<div class="alert alert-danger mx-3 my-3" role="alert"><strong>' . lng('Copy/Move failed') . ':</strong> ' . lng('Destination folder does not exist or is not accessible') . ': <code>' .
            fm_enc($copy_to_path) . '</code>. Enter an existing MEGA folder path.</div>';
        echo '<p class="mx-3"><a class="btn btn-outline-primary" href="?p=' . urlencode(FM_PATH) . '&amp;copy=1">' . lng('Back') . '</a></p>';
        fm_show_footer();
        exit;
    }
    // move?
    $move = isset($_POST['move']);
    // copy/move
    $errors = 0;
    $conflicts = array();
    $processed = 0;
    $files = $_POST['file'];
    $seenCopyMove = array();
    unset($_SESSION['mega_copy_selection']);
    if (is_array($files) && count($files)) {
        foreach ($files as $f) {
            if ($f != '') {
                $processed++;
                $f = fm_clean_path($f);
                // Never process forged paths, nested entries or duplicate names.
                if ($f === '' || $f === '.' || $f === '..' || basename($f) !== $f ||
                    isset($seenCopyMove[$f])) {
                    $errors++;
                    continue;
                }
                $seenCopyMove[$f] = true;
                // abs path from
                $from = $path . '/' . $f;
                // abs path to
                $dest = $copy_to_path . '/' . $f;
                if (!file_exists($from)) {
                    $errors++;
                    continue;
                }
                // Do not allow copying/moving a folder into itself or a child.
                if (is_dir($from) && strpos(rtrim($dest, '/') . '/', rtrim($from, '/') . '/') === 0) {
                    $errors++;
                    continue;
                }
                // Detect filename collisions before any copy/move call.
                if (fm_mega_destination_exists($dest)) {
                    $errors++;
                    $conflicts[] = $f;
                    continue;
                }
                try {
                if ($move) {
                    $rename = fm_mega_move_checked($from, $dest);
                    clearstatcache(true);
                    if ($rename !== true) {
                        error_log('MEGA move failed: source=' . $from . ' destination=' . $dest);
                        $errors++;
                    }
                } else {
                    if (!fm_rcopy($from, $dest)) {
                        error_log('MEGA copy failed: source=' . $from . ' destination=' . $dest);
                        $errors++;
                    }
                }
                } catch (Throwable $e) {
                    error_log('MEGA bulk copy/move: ' . $e->getMessage());
                    $errors++;
                }
            }
        }
        if ($processed > 0 && $errors == 0) {
            $msg = $move ? lng('Selected files and folders moved') : lng('Selected files and folders copied');
            fm_set_msg($msg);
        } else {
            $msg = $move ? lng('Error while moving items') : lng('Error while copying items');
            if (!empty($conflicts)) {
                $names = array_values(array_unique(array_map('basename', $conflicts)));
                $message = lng('File already exists: ') . implode(', ', array_map('fm_enc', $names)) . ' (' . (int)($processed - $errors) . lng(' succeeded, ') . (int)$errors . lng(' failed') . ').';
                fm_set_msg($message, 'error');
                fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
            }
            fm_set_msg(fm_enc($msg) . ' (' . (int)$errors . ' of ' . (int)$processed . ' items failed).', 'error');
            fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
            exit;
        }
    } else {
        fm_set_msg(lng('Nothing selected'), 'alert');
    }
    $FM_PATH = FM_PATH;
    fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Rename
if (isset($_POST['rename_from'], $_POST['rename_to'], $_POST['token']) && !FM_READONLY) {
    if (!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
        die("Invalid Token.");
    }
    // old name
    $old = urldecode($_POST['rename_from']);
    $old = fm_clean_path($old);
    $old = str_replace('/', '', $old);
    // new name
    $new = urldecode($_POST['rename_to']);
    $new = fm_clean_path(strip_tags($new));
    $new = str_replace('/', '', $new);
    // path
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    // rename
    if (fm_isvalid_filename($new) && $old != '' && $new != '') {
        if ($old !== $new && fm_mega_destination_exists($path . '/' . $new)) {
            fm_set_msg(lng('File already exists: ') . fm_enc($new), 'error');
        } elseif (fm_rename($path . '/' . $old, $path . '/' . $new)) {
            fm_set_msg(sprintf(lng('Renamed from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($old), fm_enc($new)));
        } else {
            fm_set_msg(sprintf(lng('Error while renaming from') . ' <b>%s</b> ' . lng('to') . ' <b>%s</b>', fm_enc($old), fm_enc($new)), 'error');
        }
    } else {
        fm_set_msg(lng('Invalid characters in file name'), 'error');
    }
    $FM_PATH = FM_PATH;
    fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Authenticated inline image preview for MEGA-backed files.
if (isset($_GET['mega_image']) && strpos(FM_ROOT_PATH, 'mega://') === 0) {
    $imageName = (string) $_GET['mega_image'];
    $imageName = basename(str_replace('\\', '/', $imageName));
    $imageExt = strtolower(pathinfo($imageName, PATHINFO_EXTENSION));
    $imageTypes = array('jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png',
        'gif'=>'image/gif','webp'=>'image/webp','bmp'=>'image/bmp','ico'=>'image/x-icon','avif'=>'image/avif');
    if ($imageName === '' || $imageName === '.' || !isset($imageTypes[$imageExt])) {
        http_response_code(400); exit;
    }
    $imagePath = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '') . '/' . $imageName;
    if (!is_file($imagePath)) { http_response_code(404); exit; }
    $imageStream = @fopen($imagePath, 'rb');
    if (!$imageStream) { http_response_code(502); exit; }
    header('Content-Type: ' . $imageTypes[$imageExt]);
    header('Content-Disposition: inline');
    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    while (!feof($imageStream)) {
        $block = fread($imageStream, 65536);
        if ($block === false) break;
        echo $block;
    }
    fclose($imageStream);
    exit;
}

// Authenticated inline PDF preview. Never serve a login/error page as a PDF.
if (isset($_GET['mega_pdf']) && strpos(FM_ROOT_PATH, 'mega://') === 0) {
    $pdfName = basename(str_replace('\\', '/', (string) $_GET['mega_pdf']));
    if ($pdfName === '' || $pdfName === '.' || strtolower(pathinfo($pdfName, PATHINFO_EXTENSION)) !== 'pdf') {
        http_response_code(400); exit;
    }
    $pdfPath = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '') . '/' . $pdfName;
    if (!is_file($pdfPath)) { http_response_code(404); exit; }
    $stream = @fopen($pdfPath, 'rb');
    if (!$stream) { http_response_code(502); exit; }
    $first = fread($stream, 5);
    if ($first !== '%PDF-') {
        fclose($stream);
        http_response_code(502);
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store');
        echo 'PDF preview unavailable: cloud storage returned an invalid response. Please sign in again and retry.';
        exit;
    }
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="preview.pdf"');
    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    echo $first;
    while (!feof($stream)) {
        $chunk = fread($stream, 65536);
        if ($chunk === false || $chunk === '') break;
        echo $chunk;
    }
    fclose($stream);
    exit;
}

// Authenticated DOCX stream for in-page rendering (no public cloud URL).
if (isset($_GET['mega_docx']) && strpos(FM_ROOT_PATH, 'mega://') === 0) {
    $docName = basename(str_replace('\\', '/', (string) $_GET['mega_docx']));
    if ($docName === '' || $docName === '.' || strtolower(pathinfo($docName, PATHINFO_EXTENSION)) !== 'docx') {
        http_response_code(400); exit;
    }
    $docPath = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '') . '/' . $docName;
    if (!is_file($docPath)) { http_response_code(404); exit; }
    $stream = @fopen($docPath, 'rb');
    if (!$stream) { http_response_code(502); exit; }
    $first = fread($stream, 4);
    if ($first !== "PK\x03\x04") {
        fclose($stream);
        http_response_code(502);
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store');
        echo 'DOCX preview unavailable: MEGA did not return a valid DOCX file.';
        exit;
    }
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    header('Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    header('Content-Disposition: inline; filename="preview.docx"');
    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    echo $first;
    while (!feof($stream)) {
        $chunk = fread($stream, 65536);
        if ($chunk === false || $chunk === '') break;
        echo $chunk;
    }
    fclose($stream);
    exit;
}

// Authenticated XLS/XLSX/XLSM stream for read-only browser spreadsheet preview.
if (isset($_GET['mega_excel']) && strpos(FM_ROOT_PATH, 'mega://') === 0) {
    $excelName = basename(str_replace('\\', '/', (string) $_GET['mega_excel']));
    $excelExt = strtolower(pathinfo($excelName, PATHINFO_EXTENSION));
    if ($excelName === '' || $excelName === '.' || !in_array($excelExt, array('xls', 'xlsx', 'xlsm'), true)) {
        http_response_code(400); exit;
    }
    $excelPath = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '') . '/' . $excelName;
    if (!is_file($excelPath)) { http_response_code(404); exit; }
    $stream = @fopen($excelPath, 'rb');
    if (!$stream) { http_response_code(502); exit; }
    $first = fread($stream, 4);
    // Legacy .xls uses the OLE Compound File signature, not the ZIP signature.
    $validHeader = $excelExt === 'xls'
        ? $first === "\xD0\xCF\x11\xE0"
        : $first === "PK\x03\x04";
    if (!$validHeader) {
        fclose($stream);
        http_response_code(502);
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store');
        echo 'Excel preview unavailable: MEGA returned an unexpected file format.';
        exit;
    }
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    header('Content-Type: ' . ($excelExt === 'xls' ? 'application/vnd.ms-excel' : ($excelExt === 'xlsm' ? 'application/vnd.ms-excel.sheet.macroEnabled.12' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')));
    header('Content-Disposition: inline; filename="preview.' . $excelExt . '"');
    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    echo $first;
    while (!feof($stream)) {
        $chunk = fread($stream, 65536);
        if ($chunk === false || $chunk === '') break;
        echo $chunk;
    }
    fclose($stream);
    exit;
}

// Authenticated PPTX stream for read-only slide text preview.
if (isset($_GET['mega_pptx']) && strpos(FM_ROOT_PATH, 'mega://') === 0) {
    $pptName = basename(str_replace('\\', '/', (string) $_GET['mega_pptx']));
    if ($pptName === '' || $pptName === '.' || strtolower(pathinfo($pptName, PATHINFO_EXTENSION)) !== 'pptx') {
        http_response_code(400); exit;
    }
    $pptPath = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '') . '/' . $pptName;
    if (!is_file($pptPath)) { http_response_code(404); exit; }
    $stream = @fopen($pptPath, 'rb');
    if (!$stream) { http_response_code(502); exit; }
    $first = fread($stream, 4);
    if ($first !== "PK\x03\x04") {
        fclose($stream); http_response_code(502);
        header('Content-Type: text/plain; charset=UTF-8');
        echo 'PPTX preview unavailable: invalid file data from MEGA.';
        exit;
    }
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    header('Content-Type: application/vnd.openxmlformats-officedocument.presentationml.presentation');
    header('Content-Disposition: inline; filename="preview.pptx"');
    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    echo $first;
    while (!feof($stream)) {
        $chunk = fread($stream, 65536);
        if ($chunk === false || $chunk === '') break;
        echo $chunk;
    }
    fclose($stream);
    exit;
}

// Authenticated VSDX stream for the in-browser Visio preview.
if (isset($_GET['mega_vsdx']) && strpos(FM_ROOT_PATH, 'mega://') === 0) {
    $visioName = basename(str_replace('\\', '/', (string) $_GET['mega_vsdx']));
    if ($visioName === '' || $visioName === '.' || strtolower(pathinfo($visioName, PATHINFO_EXTENSION)) !== 'vsdx') {
        http_response_code(400); exit;
    }
    $visioPath = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '') . '/' . $visioName;
    if (!is_file($visioPath)) { http_response_code(404); exit; }
    $stream = @fopen($visioPath, 'rb');
    if (!$stream) { http_response_code(502); exit; }
    $first = fread($stream, 4);
    if ($first !== "PK\x03\x04") {
        fclose($stream);
        http_response_code(502);
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store');
        echo 'VSDX preview unavailable: MEGA did not return a valid VSDX file.';
        exit;
    }
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    header('Content-Type: application/vnd.ms-visio.drawing.main+xml');
    header('Content-Disposition: inline; filename="preview.vsdx"');
    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    echo $first;
    while (!feof($stream)) {
        $chunk = fread($stream, 65536);
        if ($chunk === false || $chunk === '') break;
        echo $chunk;
    }
    fclose($stream);
    exit;
}

// Download
if (isset($_GET['dl'], $_POST['token'])) {
    // Verify the token to ensure it's valid
    if (!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
        exit;
    }

    // Clean the download file path
    $dl = urldecode($_GET['dl']);
    $dl = fm_clean_path($dl);
    $dl = str_replace('/', '', $dl); // Prevent directory traversal attacks

    // Define the file path
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    // Check if the file exists and is valid
    if ($dl != '' && is_file($path . '/' . $dl)) {
        // Close the session to prevent session locking
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        // Call the download function
        fm_download_file($path . '/' . $dl, $dl, 1024); // Download with a buffer size of 1024 bytes
        exit;
    } else {
        // Handle the case where the file is not found
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }
}

// Upload
if (!empty($_FILES) && !FM_READONLY) {
    if (isset($_POST['token'])) {
        if (!verifyToken($_POST['token'])) {
            $response = array('status' => 'error', 'info' => lng("Invalid Token."));
            echo json_encode($response);
            exit();
        }
    } else {
        $response = array('status' => 'error', 'info' => "Token Missing.");
        echo json_encode($response);
        exit();
    }

    $chunkIndex = $_POST['dzchunkindex'];
    $chunkTotal = $_POST['dztotalchunkcount'];
    $fullPathInput = fm_clean_path($_REQUEST['fullpath']);

    $f = $_FILES;
    $path = FM_ROOT_PATH;
    $ds = DIRECTORY_SEPARATOR;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $errors = 0;
    $uploads = 0;
    $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
    $response = array(
        'status' => 'error',
        'info'   => 'Oops! Try again'
    );

    $filename = $f['file']['name'];
    $tmp_name = $f['file']['tmp_name'];
    $ext = pathinfo($filename, PATHINFO_FILENAME) != '' ? strtolower(pathinfo($filename, PATHINFO_EXTENSION)) : '';
    $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

    if (!fm_isvalid_filename($filename) && !fm_isvalid_filename($fullPathInput)) {
        $response = array(
            'status'    => 'error',
            'info'      => "Invalid File name!",
        );
        echo json_encode($response);
        exit();
    }

    $targetPath = $path . $ds;
    if (is_writable($targetPath)) {
        $fullPath = $path . '/' . $fullPathInput;
        $folder = substr($fullPath, 0, strrpos($fullPath, "/"));

        if (!is_dir($folder)) {
            $old = umask(0);
            mkdir($folder, 0777, true);
            umask($old);
        }

        if (empty($f['file']['error']) && !empty($tmp_name) && $tmp_name != 'none' && $isFileAllowed) {
            if ($chunkTotal) {
                $out = @fopen("{$fullPath}.part", $chunkIndex == 0 ? "wb" : "ab");
                if ($out) {
                    $in = @fopen($tmp_name, "rb");
                    if ($in) {
                        if (PHP_VERSION_ID < 80009) {
                            // workaround https://bugs.php.net/bug.php?id=81145
                            do {
                                for (;;) {
                                    $buff = fread($in, 4096);
                                    if ($buff === false || $buff === '') {
                                        break;
                                    }
                                    fwrite($out, $buff);
                                }
                            } while (!feof($in));
                        } else {
                            stream_copy_to_stream($in, $out);
                        }
                        $response = array(
                            'status'    => 'success',
                            'info' => "file upload successful"
                        );
                    } else {
                        $response = array(
                            'status'    => 'error',
                            'info' => "failed to open output stream",
                            'errorDetails' => error_get_last()
                        );
                    }
                    @fclose($in);
                    @fclose($out);
                    @unlink($tmp_name);

                    $response = array(
                        'status'    => 'success',
                        'info' => "file upload successful"
                    );
                } else {
                    $response = array(
                        'status'    => 'error',
                        'info' => "failed to open output stream"
                    );
                }

                if ($chunkIndex == $chunkTotal - 1) {
                    if (file_exists($fullPath)) {
                        $ext_1 = $ext ? '.' . $ext : '';
                        $fullPathTarget = $path . '/' . basename($fullPathInput, $ext_1) . '_' . date('ymdHis') . $ext_1;
                    } else {
                        $fullPathTarget = $fullPath;
                    }
                    rename("{$fullPath}.part", $fullPathTarget);
                }
            } else if (mega_move_uploaded($tmp_name, $fullPath)) {
                // Be sure that the file has been uploaded
                if (file_exists($fullPath)) {
                    $response = array(
                        'status'    => 'success',
                        'info' => "file upload successful"
                    );
                } else {
                    $response = array(
                        'status' => 'error',
                        'info'   => 'Couldn\'t upload the requested file.'
                    );
                }
            } else {
                $response = array(
                    'status'    => 'error',
                    'info'      => "Error while uploading files. Uploaded files $uploads",
                );
            }
        }
    } else {
        $response = array(
            'status' => 'error',
            'info'   => 'The specified folder for upload isn\'t writeable.'
        );
    }
    // Return the response
    echo json_encode($response);
    exit();
}

// Mass deleting
if (isset($_POST['group'], $_POST['delete'], $_POST['token']) && !FM_READONLY) {

    if (!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
        die("Invalid Token.");
    }

    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $errors = 0;
    $files = $_POST['file'];
    if (is_array($files) && count($files)) {
        foreach ($files as $f) {
            if ($f != '') {
                $new_path = $path . '/' . $f;
                if (!fm_delete_user_item($new_path)) {
                    $errors++;
                }
            }
        }
        if ($errors == 0) {
            fm_set_msg(lng('Selected files and folder deleted'));
        } else {
            fm_set_msg(lng('Error while deleting items'), 'error');
        }
    } else {
        fm_set_msg(lng('Nothing selected'), 'alert');
    }

    $FM_PATH = FM_PATH;
    fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Pack files zip, tar. MEGA is a remote stream wrapper, so ZipArchive and
// PharData must work with temporary LOCAL files, not mega:// URLs.
if (isset($_POST['group'], $_POST['token']) && (isset($_POST['zip']) || isset($_POST['tar'])) && !FM_READONLY) {
    if (!verifyToken($_POST['token'])) {
        fm_set_msg(lng('Invalid Token.'), 'error');
        die('Invalid Token.');
    }

    $ext = isset($_POST['tar']) ? 'tar' : 'zip';
    $files = isset($_POST['file']) && is_array($_POST['file']) ? $_POST['file'] : array();
    if (empty($files)) {
        fm_set_msg(lng('Nothing selected'), 'alert');
    } elseif (($ext === 'zip' && !class_exists('ZipArchive')) ||
              ($ext === 'tar' && !class_exists('PharData'))) {
        fm_set_msg(lng('Operations with archives are not available'), 'error');
    } else {
        $base = rtrim(FM_ROOT_PATH, '/');
        if (FM_PATH !== '') $base .= '/' . FM_PATH;
        $stage = sys_get_temp_dir() . '/mega_archive_' . bin2hex(random_bytes(12));
        $error = '';
        $success = false;
        if (!@mkdir($stage, 0700)) {
            $error = 'Cannot create temporary archive directory';
        } else {
            try {
                $names = array();
                foreach ($files as $item) {
                    // Selected items are immediate children of the current directory.
                    if (!is_string($item) || $item === '' || $item === '.' || $item === '..' ||
                        basename($item) !== $item || strpos($item, "\\") !== false ||
                        strpos($item, '/') !== false || strpos($item, "\0") !== false) {
                        throw new RuntimeException('Invalid selected file name');
                    }
                    $names[$item] = true;
                }
                if (!$names) throw new RuntimeException('No files selected');
                $names = array_keys($names);
                $count = 0;
                $bytes = 0;
                foreach ($names as $name) {
                    mega_archive_stage_item($base . '/' . $name, $stage . '/' . $name, $count, $bytes, 0);
                }
                $zipname = (count($names) === 1 ? $names[0] : 'archive') . '_' . date('ymd_His') . '.' . $ext;
                $localArchive = $stage . '/result.' . $ext;
                if ($ext === 'zip') {
                    $archive = new ZipArchive();
                    if ($archive->open($localArchive, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
                        throw new RuntimeException('Cannot initialize ZIP archive');
                    }
                    $added = true;
                    foreach ($names as $name) {
                        if (!mega_archive_add_zip($archive, $stage . '/' . $name, $name)) { $added = false; break; }
                    }
                    $closed = $archive->close();
                    if (!$added || !$closed) throw new RuntimeException('Failed to write ZIP archive');
                } else {
                    $archive = new PharData($localArchive);
                    foreach ($names as $name) {
                        mega_archive_add_tar($archive, $stage . '/' . $name, $name);
                    }
                    unset($archive);
                }
                if (!is_file($localArchive) || filesize($localArchive) === 0) {
                    throw new RuntimeException('Archive file is empty');
                }
                $destination = $base . '/' . $zipname;
                // Upload directly to MEGA and check the result; do not depend on
                // PHP stream_close(), which cannot return upload failures.
                if (strpos($destination, 'mega://') === 0) {
                    $parent = MegaFS::parentOf($destination);
                    if (!$parent) throw new RuntimeException('Destination folder not found in MEGA');
                    if (MegaFS::node($destination)) throw new RuntimeException('Archive already exists');
                    if (!MegaApi::upload($localArchive, $parent[0], $parent[1])) {
                        throw new RuntimeException('MEGA upload failed');
                    }
                } else {
                    if (file_exists($destination) || !@rename($localArchive, $destination)) {
                        throw new RuntimeException('Cannot save archive in local folder');
                    }
                }
                $success = true;
                fm_set_msg(sprintf(lng('Archive') . ' <b>%s</b> ' . lng('Created'), fm_enc($zipname)));
            } catch (Throwable $e) {
                $error = $e->getMessage();
                error_log('MEGA archive creation failed: ' . $error);
            }
            mega_archive_remove_temp($stage);
        }
        if (!$success) fm_set_msg(lng('Archive not created') . ': ' . $error, 'error');
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

/** Stage MEGA files locally, with bounds to protect shared hosting. */
function mega_archive_stage_item($remote, $local, &$count, &$bytes, $depth)
{
    if ($depth > 20 || ++$count > 1000) throw new RuntimeException('Archive exceeds 1000 items or 20 folder levels');
    if (is_dir($remote)) {
        if (!@mkdir($local, 0700)) throw new RuntimeException('Cannot create temporary folder');
        $items = @scandir($remote);
        if (!is_array($items)) throw new RuntimeException('Cannot list MEGA folder');
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            if ($item === '' || strpos($item, '/') !== false || strpos($item, "\\") !== false) {
                throw new RuntimeException('Invalid remote file name');
            }
            mega_archive_stage_item($remote . '/' . $item, $local . '/' . $item, $count, $bytes, $depth + 1);
        }
    } elseif (is_file($remote)) {
        $size = @filesize($remote);
        if ($size === false || $size < 0 || $bytes + $size > 268435456) {
            throw new RuntimeException('Archive exceeds 256 MiB staging limit');
        }
        $bytes += $size;
        $source = @fopen($remote, 'rb');
        if (!$source) throw new RuntimeException('Cannot read MEGA file');
        $target = @fopen($local, 'wb');
        if (!$target) { fclose($source); throw new RuntimeException('Cannot write temporary file'); }
        $copied = @stream_copy_to_stream($source, $target);
        fclose($source);
        fclose($target);
        if ($copied === false || $copied !== $size) throw new RuntimeException('Incomplete MEGA download');
    } else {
        throw new RuntimeException('Selected MEGA item not found');
    }
}

function mega_archive_add_zip($zip, $local, $name)
{
    if (is_dir($local)) {
        if (!$zip->addEmptyDir($name)) return false;
        $items = scandir($local);
        if ($items === false) return false;
        foreach ($items as $item) {
            if ($item !== '.' && $item !== '..' && !mega_archive_add_zip($zip, $local . '/' . $item, $name . '/' . $item)) return false;
        }
        return true;
    }
    return $zip->addFile($local, $name);
}

function mega_archive_add_tar($tar, $local, $name)
{
    if (is_dir($local)) {
        $tar->addEmptyDir($name);
        $items = scandir($local);
        if ($items === false) throw new RuntimeException('Cannot list temporary folder');
        foreach ($items as $item) {
            if ($item !== '.' && $item !== '..') mega_archive_add_tar($tar, $local . '/' . $item, $name . '/' . $item);
        }
    } else {
        $tar->addFile($local, $name);
    }
}

/** Copy validated, extracted archive contents into the local destination. */
function fm_local_extract_staged($stage, $destination, &$uploaded, $depth = 0)
{
    if ($depth > 32) throw new RuntimeException('Archive nesting limit exceeded');
    foreach (new DirectoryIterator($stage) as $entry) {
        if ($entry->isDot()) continue;
        $name = $entry->getFilename();
        if ($name === '' || $name === '.' || $name === '..' || $entry->isLink())
            throw new RuntimeException('Invalid archive entry');
        $target = $destination . '/' . $name;
        if (file_exists($target) || is_link($target)) throw new RuntimeException('Archive entry already exists: ' . $name);
        if ($entry->isDir()) {
            if (!@mkdir($target, 0775)) throw new RuntimeException('Cannot create extracted folder');
            fm_local_extract_staged($entry->getPathname(), $target, $uploaded, $depth + 1);
        } elseif ($entry->isFile()) {
            if (!@copy($entry->getPathname(), $target)) throw new RuntimeException('Cannot extract file');
            $uploaded++;
        }
    }
}

function mega_archive_remove_temp($path)
{
    if (!is_dir($path)) return;
    $items = scandir($path);
    if ($items !== false) foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $child = $path . '/' . $item;
        if (is_dir($child)) mega_archive_remove_temp($child);
        else @unlink($child);
    }
    @rmdir($path);
}

/** Extract a ZIP/TAR to local temporary storage before uploading files to MEGA. */
function mega_untar_stage($source, $stage)
{
    mega_unpack_stage($source, $stage, 'tar');
}

function mega_unpack_stage($source, $stage, $ext)
{
    $count = 0;
    $total = 0;
    $entries = [];
    if ($ext === 'zip') {
        $archive = new ZipArchive();
        if ($archive->open($source) !== true) throw new RuntimeException('Cannot open ZIP archive');
        try {
            for ($i = 0; $i < $archive->numFiles; $i++) {
                $info = $archive->statIndex($i);
                if (!$info) throw new RuntimeException('Cannot read ZIP entry');
                $entries[] = [$info['name'], (int)$info['size'], $i];
            }
            mega_unpack_validate($entries);
            foreach ($entries as $entry) {
                $name = $entry[0];
                $target = $stage . '/' . rtrim($name, '/');
                if (substr($name, -1) === '/') {
                    if (!is_dir($target) && !@mkdir($target, 0700, true)) throw new RuntimeException('Cannot create temporary folder');
                    continue;
                }
                $dir = dirname($target);
                if (!is_dir($dir) && !@mkdir($dir, 0700, true)) throw new RuntimeException('Cannot create temporary folder');
                $in = $archive->getStream($name);
                if (!$in) throw new RuntimeException('Cannot read archive entry: ' . $name);
                $out = @fopen($target, 'wb');
                if (!$out) { fclose($in); throw new RuntimeException('Cannot stage archive entry'); }
                $copied = stream_copy_to_stream($in, $out);
                fclose($in); fclose($out);
                if ($copied === false || $copied !== $entry[1]) throw new RuntimeException('Incomplete ZIP extraction: ' . $name);
            }
        } finally { $archive->close(); }
    } else {
        $archive = new PharData($source);
        $iter = new RecursiveIteratorIterator($archive, RecursiveIteratorIterator::SELF_FIRST);
        foreach ($iter as $item) {
            $name = str_replace('\\', '/', $iter->getSubPathName());
            if ($item->isLink()) throw new RuntimeException('Archive links are not supported');
            $entries[] = [$name . ($item->isDir() ? '/' : ''), $item->isDir() ? 0 : $item->getSize(), null];
        }
        mega_unpack_validate($entries);
        foreach ($entries as $entry) {
            $name = $entry[0];
            $target = $stage . '/' . rtrim($name, '/');
            if (substr($name, -1) === '/') {
                if (!is_dir($target) && !@mkdir($target, 0700, true)) throw new RuntimeException('Cannot stage folder');
            } else {
                if (!is_dir(dirname($target)) && !@mkdir(dirname($target), 0700, true)) throw new RuntimeException('Cannot stage folder');
                $in = @fopen('phar://' . $source . '/' . $name, 'rb');
                if (!$in) throw new RuntimeException('Cannot read TAR entry');
                $out = @fopen($target, 'wb');
                if (!$out) { fclose($in); throw new RuntimeException('Cannot stage TAR entry'); }
                $copied = stream_copy_to_stream($in, $out);
                fclose($in); fclose($out);
                if ($copied === false || $copied !== $entry[1]) throw new RuntimeException('Incomplete TAR extraction');
            }
        }
    }
}

/** Reject unsafe paths, duplicate entries, and archives too large for shared hosting. */
function mega_unpack_validate($entries)
{
    $bytes = 0; $seen = [];
    if (count($entries) > 1000) throw new RuntimeException('Archive exceeds 1000 entries');
    foreach ($entries as $entry) {
        $name = str_replace('\\', '/', $entry[0]);
        $trimmed = rtrim($name, '/');
        $segments = explode('/', $trimmed);
        if ($trimmed === '' || $name[0] === '/' || preg_match('/^[A-Za-z]:/', $name) || count($segments) > 20) throw new RuntimeException('Unsafe archive entry');
        foreach ($segments as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..' || strpos($segment, "\0") !== false) throw new RuntimeException('Unsafe archive entry');
        }
        if (isset($seen[$trimmed])) throw new RuntimeException('Duplicate archive entry');
        $seen[$trimmed] = true;
        $bytes += $entry[1];
        if ($bytes > 268435456) throw new RuntimeException('Archive exceeds 256 MiB extracted-size limit');
    }
}

/** Upload extracted files explicitly; do not use ZipArchive::extractTo(mega://...). */
function mega_unpack_upload($local, $remote, &$uploaded, $depth = 0)
{
    if ($depth > 20) throw new RuntimeException('Too many nested folders');
    $items = scandir($local);
    if ($items === false) throw new RuntimeException('Cannot list extracted files');
    foreach ($items as $name) {
        if ($name === '.' || $name === '..') continue;
        $src = $local . '/' . $name;
        $dst = $remote . '/' . $name;
        if (is_dir($src)) {
            if (!is_dir($dst) && !@mkdir($dst, 0777, true)) throw new RuntimeException('Cannot create MEGA folder: ' . $name);
            mega_unpack_upload($src, $dst, $uploaded, $depth + 1);
        } else {
            if (file_exists($dst)) throw new RuntimeException(lng('Destination already exists') . ': ' . $name);
            $parent = MegaFS::parentOf($dst);
            if (!$parent || !MegaApi::upload($src, $parent[0], $parent[1])) throw new RuntimeException('MEGA upload failed: ' . $name);
            $uploaded++;
        }
    }
}

// Unpack ZIP/TAR into MEGA (via safe local staging and explicit uploads).
if ((isset($_POST['unzip']) || isset($_POST['untar'])) && isset($_POST['token']) && !FM_READONLY) {
    if (!verifyToken($_POST['token'])) {
        fm_set_msg(lng('Invalid Token.'), 'error');
        die('Invalid Token.');
    }
    $unzip = str_replace('/', '', fm_clean_path(urldecode(isset($_POST['untar']) ? $_POST['untar'] : $_POST['unzip'])));
    $base = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '');
    $source = $base . '/' . $unzip;
    $ext = strtolower(pathinfo($unzip, PATHINFO_EXTENSION));
    $stage = false;
    $download = false;
    $uploaded = 0;
    $createdFolder = false;
    $destination = $base;
    try {
        if ($unzip === '' || !is_file($source)) throw new RuntimeException('Archive not found');
        if ($ext !== 'zip' && $ext !== 'tar') throw new RuntimeException('Unsupported archive format');
        if (isset($_POST['untar']) && $ext !== 'tar') throw new RuntimeException('Expected TAR archive');
        if ($ext === 'zip' && !class_exists('ZipArchive')) throw new RuntimeException('ZIP extension unavailable');
        if ($ext === 'tar' && !class_exists('PharData')) throw new RuntimeException('TAR extension unavailable');
        $size = filesize($source);
        if ($size === false || $size > 268435456) throw new RuntimeException('Archive exceeds 256 MiB limit');
        $stage = sys_get_temp_dir() . '/mega_unzip_' . bin2hex(random_bytes(8));
        if (!@mkdir($stage, 0700)) throw new RuntimeException('Cannot create temporary folder');
        $download = tempnam(sys_get_temp_dir(), 'mega_archive_');
        if ($download === false) throw new RuntimeException('Cannot create temporary archive');
        // PharData identifies TAR archives by their local filename extension.
        // Preserve the suffix while keeping the unique temporary basename.
        $namedDownload = $download . '.' . $ext;
        if (!@rename($download, $namedDownload)) throw new RuntimeException('Cannot name temporary archive');
        $download = $namedDownload;
        $in = @fopen($source, 'rb');
        if (!$in) throw new RuntimeException('Cannot download MEGA archive');
        $out = @fopen($download, 'wb');
        if (!$out) { fclose($in); throw new RuntimeException(lng('Cannot stage MEGA archive')); }
        $copied = stream_copy_to_stream($in, $out);
        fclose($in); fclose($out);
        if ($copied === false || $copied !== $size) throw new RuntimeException(lng('Incomplete MEGA archive download'));
        if ($ext === 'tar') mega_untar_stage($download, $stage);
        else mega_unpack_stage($download, $stage, $ext);
        if (isset($_POST['tofolder'])) {
            $folder = pathinfo($unzip, PATHINFO_FILENAME);
            $destination = $base . '/' . $folder;
            if (file_exists($destination)) {
                if (!is_dir($destination)) throw new RuntimeException(lng('Destination name is already used'));
            } else {
                if (!@mkdir($destination, 0777, true)) throw new RuntimeException(lng('Cannot create destination folder'));
                $createdFolder = true;
            }
        }
        if (strpos($destination, 'mega://') === 0) {
            // Batch mode: keep the MEGA tree cached during the loop (one reload instead of one per file).
            @ignore_user_abort(true);
            @set_time_limit(0);
            MegaApi::$batch = true;
            try {
                mega_unpack_upload($stage, $destination, $uploaded);
            } finally {
                MegaApi::$batch = false;
                MegaApi::invalidate();
            }
        } else {
            fm_local_extract_staged($stage, $destination, $uploaded);
        }
        fm_set_msg(lng('Archive unpacked') . ' (' . $uploaded . ' ' . lng('files') . ')');
    } catch (Throwable $e) {
        // Roll back a newly created empty destination, but never delete files already uploaded.
        if ($createdFolder && $uploaded === 0 && is_dir($destination)) @rmdir($destination);
        error_log('MEGA archive extraction failed: ' . $e->getMessage());
        fm_set_msg(lng('Archive not unpacked') . ': ' . $e->getMessage() . ($uploaded ? ' (' . $uploaded . ' ' . lng('files uploaded') . ')' : ''), 'error');
    } finally {
        if ($download !== false) @unlink($download);
        if ($stage !== false) mega_archive_remove_temp($stage);
    }
    fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
}

// Change Perms (not for Windows)
if (isset($_POST['chmod'], $_POST['token']) && !FM_READONLY && !FM_IS_WIN) {

    if (!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
        die("Invalid Token.");
    }

    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $file = $_POST['chmod'];
    $file = fm_clean_path($file);
    $file = str_replace('/', '', $file);
    if ($file == '' || (!is_file($path . '/' . $file) && !is_dir($path . '/' . $file))) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    $mode = 0;
    if (!empty($_POST['ur'])) {
        $mode |= 0400;
    }
    if (!empty($_POST['uw'])) {
        $mode |= 0200;
    }
    if (!empty($_POST['ux'])) {
        $mode |= 0100;
    }
    if (!empty($_POST['gr'])) {
        $mode |= 0040;
    }
    if (!empty($_POST['gw'])) {
        $mode |= 0020;
    }
    if (!empty($_POST['gx'])) {
        $mode |= 0010;
    }
    if (!empty($_POST['or'])) {
        $mode |= 0004;
    }
    if (!empty($_POST['ow'])) {
        $mode |= 0002;
    }
    if (!empty($_POST['ox'])) {
        $mode |= 0001;
    }

    if (@chmod($path . '/' . $file, $mode)) {
        fm_set_msg(lng('Permissions changed'));
    } else {
        fm_set_msg(lng('Permissions not changed'), 'error');
    }

    $FM_PATH = FM_PATH;
    fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

/*************************** ACTIONS ***************************/

// get current path
$path = FM_ROOT_PATH;
if (FM_PATH != '') {
    $path .= '/' . FM_PATH;
}

// check path
if (!is_dir($path)) {
    fm_redirect(FM_SELF_URL . '?p=');
}

// get parent folder
$parent = fm_get_parent_path(FM_PATH);

// The MEGA wrapper has the complete decrypted node tree in memory. Read one
// directory snapshot instead of performing a separate stat lookup per entry.
$megaFastListing = (strpos($path, 'mega://') === 0 && class_exists('MegaFS'))
    ? MegaFS::directorySnapshot($path) : false;
$objects = is_array($megaFastListing)
    ? array_merge(array('.', '..'), $megaFastListing['folders'], $megaFastListing['files'])
    : (is_readable($path) ? scandir($path) : array());
$folders = array();
$files = array();
$current_path = array_slice(explode("/", $path), -1)[0];
$megaFastFileSet = is_array($megaFastListing) ? array_fill_keys($megaFastListing['files'], true) : array();
$megaFastFolderSet = is_array($megaFastListing) ? array_fill_keys($megaFastListing['folders'], true) : array();
if (is_array($objects) && fm_is_exclude_items($current_path, $path)) {
    foreach ($objects as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }
        if (!FM_SHOW_HIDDEN && substr($file, 0, 1) === '.') {
            continue;
        }
        $new_path = $path . '/' . $file;
        if (is_array($megaFastListing)) {
            // Fast membership checks, with the original exclude/hidden rules intact.
            if (isset($megaFastFileSet[$file]) && fm_is_exclude_items($file, $new_path)) $files[] = $file;
            elseif (isset($megaFastFolderSet[$file]) && fm_is_exclude_items($file, $new_path)) $folders[] = $file;
        } elseif (@is_file($new_path) && fm_is_exclude_items($file, $new_path)) {
            $files[] = $file;
        } elseif (@is_dir($new_path) && $file != '.' && $file != '..' && fm_is_exclude_items($file, $new_path)) {
            $folders[] = $file;
        }
    }
}

if (!empty($files)) {
    natcasesort($files);
}
if (!empty($folders)) {
    natcasesort($folders);
}

// Full-page New Item form (same behavior and CSRF protection as previous modal).
if (isset($_GET['new_item']) && !FM_READONLY) {
    fm_show_header();
    fm_show_nav_path(FM_PATH);
    ?>
    <main class="fm-page-content container-fluid">
      <div class="card fm-new-item-card fm-form-panel" data-bs-theme="<?php echo FM_THEME; ?>">
        <div class="card-header"><i class="fa fa-plus-square fa-fw"></i> <?php echo lng('NewItem'); ?></div>
        <div class="card-body">
          <div class="fm-upload-destination fm-new-item-destination"><strong><?php echo lng('DestinationFolder'); ?></strong><span class="fm-destination-value">: <?php echo fm_enc(fm_convert_win(FM_PATH)); ?></span></div>
          <form method="post" action="?p=<?php echo urlencode(FM_PATH); ?>" novalidate id="mega-new-item-form">
            <label class="form-label d-block"><?php echo lng('ItemType'); ?></label>
            <div class="form-check form-check-inline">
              <input class="form-check-input" type="radio" name="newfile" id="newItemFile" value="file">
              <label class="form-check-label" for="newItemFile"><?php echo lng('File'); ?></label>
            </div>
            <div class="form-check form-check-inline">
              <input class="form-check-input" type="radio" name="newfile" id="newItemFolder" value="folder" checked>
              <label class="form-check-label" for="newItemFolder"><?php echo lng('Folder'); ?></label>
            </div>
            <label class="form-label d-block mt-3" for="newfilename"><?php echo lng('ItemName'); ?></label>
            <input type="text" name="newfilename" id="newfilename" class="form-control" maxlength="255" placeholder="<?php echo lng('Enter here...'); ?>" required>
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($_SESSION['token'], ENT_QUOTES, 'UTF-8'); ?>">
            <div class="d-flex gap-2 mt-4 mega-two-action-row">
              <a class="btn btn-outline-secondary" href="?p=<?php echo urlencode(FM_PATH); ?>"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></a>
              <button class="btn btn-primary" type="submit"><i class="fa fa-plus" aria-hidden="true"></i> <?php echo lng('Create'); ?></button>
            </div>
          </form>
        </div>
      </div>
    </main>
    <?php
    fm_show_footer();
    exit;
}

// upload form
if (isset($_GET['upload']) && !FM_READONLY) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    //get the allowed file extensions
    function getUploadExt()
    {
        $extArr = explode(',', FM_UPLOAD_EXTENSION);
        if (FM_UPLOAD_EXTENSION && $extArr) {
            array_walk($extArr, function (&$x) {
                $x = ".$x";
            });
            return implode(',', $extArr);
        }
        return '';
    }
    ?>
    <?php print_external('css-dropzone'); ?>
    <div class="path fm-upload-page-path">
        <div id="megaUrlUploadResultHost" class="mega-url-result-host" aria-live="polite"></div>

        <div class="card mb-2 fm-upload-wrapper fm-form-panel" data-bs-theme="<?php echo FM_THEME; ?>">
            <div class="card-header">
                <ul class="nav nav-tabs card-header-tabs">
                    <li class="nav-item">
                        <a class="nav-link active" href="#fileUploader" data-target="#fileUploader"><i class="fa fa-arrow-circle-o-up"></i> <?php echo lng('UploadingFiles') ?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#urlUploader" class="js-url-upload" data-target="#urlUploader"><i class="fa fa-link"></i> <?php echo lng('Upload from URL') ?></a>
                    </li>
                </ul>
            </div>
            <div class="card-body">
                <div class="fm-upload-destination"><strong><?php echo lng('DestinationFolder') ?></strong><span class="fm-destination-value">: <?php echo fm_enc(fm_convert_win(FM_PATH)) ?></span></div>

                <form action="<?php echo htmlspecialchars(FM_SELF_URL) . '?p=' . fm_enc(FM_PATH) ?>" class="dropzone card-tabs-container" id="fileUploader" enctype="multipart/form-data">
                    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="fullpath" id="fullpath" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <div class="fallback">
                        <input name="file" type="file" multiple />
                    </div>
                </form>
                <div class="fm-file-upload-actions fm-unified-actions">
                    <a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-secondary fm-unified-button"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></a>
                </div>

                <div class="upload-url-wrapper card-tabs-container hidden" id="urlUploader">
                    <form id="js-form-url-upload" class="fm-url-upload-form" data-no-processing="true" data-type="ajax" onsubmit="return upload_from_url(this);" method="POST" action="">
                        <input type="hidden" name="type" value="upload" aria-label="hidden" aria-hidden="true">
                        <input type="url" placeholder="<?php echo lng('Enter URL'); ?>" name="uploadurl" required class="form-control fm-url-input">
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <div class="fm-unified-actions fm-url-actions">
                            <a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-secondary fm-unified-button"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></a>
                            <button type="submit" class="btn btn-primary fm-unified-button fm-url-submit"><i class="fa fa-upload" aria-hidden="true"></i> <?php echo lng('Upload') ?></button>
                        </div>
                        <div class="lds-facebook">
                            <div></div>
                            <div></div>
                            <div></div>
                        </div>
                    </form>
                    <div id="js-url-upload__list" class="col-9 mt-3"></div>
                </div>
            </div>
        </div>
    </div>
    <?php print_external('js-dropzone'); ?>
    <script>
        Dropzone.options.fileUploader = {
            dictDefaultMessage: <?php echo json_encode(html_entity_decode(lng('Drop files here to upload'), ENT_QUOTES, 'UTF-8'), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG); ?>,
            chunking: true,
            chunkSize: <?php echo UPLOAD_CHUNK_SIZE; ?>,
            forceChunking: true,
            retryChunks: true,
            retryChunksLimit: 3,
            parallelUploads: 1,
            parallelChunkUploads: false,
            timeout: 120000,
            maxFilesize: "<?php echo MAX_UPLOAD_SIZE; ?>",
            acceptedFiles: "<?php echo getUploadExt() ?>",
            init: function() {
                this.on("sending", function(file, xhr, formData) {
                    let _path = (file.fullPath) ? file.fullPath : file.name;
                    document.getElementById("fullpath").value = _path;
                    xhr.ontimeout = (function() {
                        toast('Error: Server Timeout');
                    });
                }).on("success", function(res) {
                    try {
                        let _response = JSON.parse(res.xhr.response);

                        if (_response.status == "error") {
                            toast(_response.info);
                        }
                    } catch (e) {
                        toast("Error: Invalid JSON response");
                    }
                }).on("error", function(file, response) {
                    toast(response);
                });
            }
        }
    </script>
<?php
    fm_show_footer();
    exit;
}

?>
<?php
function fm_mega_folder_picker_ui($initialPath, $mode, $copySource = '') {
    $initialJson = json_encode($initialPath, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    $modeJson = json_encode($mode);
    $sourceJson = json_encode($copySource, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    $tokenJson = json_encode($_SESSION['token']);
    echo '<div id="mega-folder-picker" class="my-3 p-3 border rounded" style="max-height:340px;overflow-y:auto;background:var(--bs-body-bg,#fff)">';
    echo '<div class="mb-2"><strong>' . lng('Select destination folder') . '</strong></div>';
    echo '<div class="mb-2"><button type="button" class="btn btn-sm btn-outline-secondary" id="mega-folder-root">' . lng('Root') . '</button> <button type="button" class="btn btn-sm btn-outline-secondary" id="mega-folder-up">' . lng('Up') . '</button> <span id="mega-folder-location" class="ms-2 text-break"></span></div>';
    echo '<div id="mega-folder-status" class="small text-muted mb-2"></div><div id="mega-folder-entries"></div></div>';
    echo '<script>(function(){
';
    echo 'var current=' . $initialJson . ', mode=' . $modeJson . ', source=' . $sourceJson . ', token=' . $tokenJson . ';';
    ?>
    var pickerI18n=<?php echo json_encode(array(
        'cached'=>html_entity_decode(lng('Cached folder list'), ENT_QUOTES, 'UTF-8'),
        'browse'=>html_entity_decode(lng('Tap a folder to browse and select it'), ENT_QUOTES, 'UTF-8'),
        'empty'=>html_entity_decode(lng('No subfolders'), ENT_QUOTES, 'UTF-8'),
        'loading'=>html_entity_decode(lng('Loading folders...'), ENT_QUOTES, 'UTF-8'),
        'failed'=>html_entity_decode(lng('Unable to load folders'), ENT_QUOTES, 'UTF-8')
    ), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE); ?>;
    var root=document.getElementById('mega-folder-root');
    var up=document.getElementById('mega-folder-up');
    var status=document.getElementById('mega-folder-status');
    var entries=document.getElementById('mega-folder-entries');
    var pickerRequestId=0;
    var pickerController=null;
    var locationLabel=document.getElementById('mega-folder-location');
    var input=document.getElementById('inp_copy_to');
    var copyLink=document.getElementById('mega-picker-copy-link');
    var moveLink=document.getElementById('mega-picker-move-link');
    function setDestination(path){
        current=path;
        if(input)input.value=path;
        locationLabel.textContent=(window.FM_STORAGE_TYPE==='local'?'Local / ':'mega://root/')+path;
        if(mode==='single'){
            var base='?p='+encodeURIComponent(path)+'&copy='+encodeURIComponent(source)+'&finish=1';
            if(copyLink)copyLink.href=base;
            if(moveLink)moveLink.href=base+'&move=1';
        }
    }
    var pickerMemo=Object.create(null);
    function navigate(path){
        setDestination(path);
        var requestId=++pickerRequestId;
        if(pickerController && typeof pickerController.abort==='function')pickerController.abort();
        pickerController=(typeof AbortController!=='undefined')?new AbortController():null;
        status.textContent='';
        entries.textContent='';
        setTimeout(function(){if(requestId===pickerRequestId && !entries.hasChildNodes() && status.textContent==='')status.textContent=pickerI18n.loading;},150);
        var url='?p=&mega_folder_picker=1&dir='+encodeURIComponent(path)+'&token='+encodeURIComponent(token);
        var memo=pickerMemo[path];
        var load=(memo && Date.now()-memo.at<20000)
            ? Promise.resolve(memo.data)
            : fetch(url,{credentials:'same-origin',headers:{'Accept':'application/json'},signal:pickerController?pickerController.signal:undefined}).then(function(r){return r.text().then(function(body){var j;try{j=JSON.parse(body);}catch(e){throw new Error('Server returned HTML instead of folder data (HTTP '+r.status+').');}if(!r.ok)throw new Error(j.error||'Unable to load folders');return j;});});
        load.then(function(data){
            pickerMemo[path]={at:Date.now(),data:data};
            if(requestId!==pickerRequestId)return;
            status.textContent=data.folders.length?pickerI18n.browse:pickerI18n.empty;
            var names=data.folders, offset=0;
            function renderBatch(){
                if(requestId!==pickerRequestId)return;
                var fragment=document.createDocumentFragment(), end=Math.min(offset+80,names.length);
                for(;offset<end;offset++){
                    var name=names[offset], next=path?path+'/'+name:name;
                    var button=document.createElement('button');button.type='button';
                    button.className='btn btn-outline-primary btn-sm text-start d-block w-100 mb-1';
                    button.textContent='📁 '+name;
                    button.onclick=(function(folder){return function(){navigate(folder);};})(next);
                    fragment.appendChild(button);
                }
                entries.appendChild(fragment);
                if(offset<names.length){
                    status.textContent='Showing '+offset+' of '+names.length+' folders...';
                    setTimeout(renderBatch,0);
                }else if(names.length){status.textContent=pickerI18n.browse;}
            }
            renderBatch();
        }).catch(function(e){if(requestId!==pickerRequestId || e.name==='AbortError')return;status.textContent=pickerI18n.failed+': '+e.message;});
    }
    root.onclick=function(){navigate('');};
    up.onclick=function(){var p=current.lastIndexOf('/');navigate(p<0?'':current.slice(0,p));};
    if(input)input.addEventListener('change',function(){navigate(input.value.replace(/^\/+|\/+$/g,''));});
    navigate(current);
    })();</script>
    <?php
}
?>

<?php
// Route row-level Copy/Move through the same bulk Copy/Move screen.
// The row link carries a single source path; the shared form carries the
// selection as hidden file[] inputs and uses the same cached folder picker.
if (isset($_GET['copy']) && !isset($_GET['finish']) && !FM_READONLY) {
    $megaSingleSource = fm_clean_path($_GET['copy']);
    $megaSingleParent = trim(dirname($megaSingleSource), './');
    if ($megaSingleSource === '' || $megaSingleParent !== trim(FM_PATH, '/') ||
        !file_exists(rtrim(FM_ROOT_PATH, '/') . '/' . $megaSingleSource)) {
        fm_set_msg(lng('File not found'), 'error');
        fm_redirect(FM_SELF_URL . '?p=' . urlencode(FM_PATH));
    }
    $_POST['copy'] = '1';
    $_POST['file'] = array(basename($megaSingleSource));
}

// copy form POST
if (isset($_POST['copy']) && !FM_READONLY) {
    $copy_files = isset($_POST['file']) ? $_POST['file'] : null;
    if (is_array($copy_files) && count($copy_files)) {
        $_SESSION['mega_copy_selection'] = array(
            'path' => FM_PATH, 'time' => time(), 'files' => array_values($copy_files)
        );
    }
    if (!is_array($copy_files) || empty($copy_files)) {
        fm_set_msg(lng('Nothing selected'), 'alert');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
?>
    <div class="path">
        <div class="card fm-form-panel" data-bs-theme="<?php echo FM_THEME; ?>">
            <div class="card-header">
                <h6><?php echo lng('Copy/Move'); ?></h6>
            </div>
            <div class="card-body">
                <form action="" method="post" id="mega-copy-form">
                    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="finish" value="1">
                    <?php
                    foreach ($copy_files as $cf) {
                        echo '<input type="hidden" name="file[]" value="' . fm_enc($cf) . '">' . PHP_EOL;
                    }
                    ?>
                    <style>
                        /* Copy/Move has no item-selection checkbox: selection is carried by hidden file[] inputs. */
                        #mega-copy-form input[type="checkbox"],
                        #mega-copy-form .custom-control:has(input[type="checkbox"]) {
                            display: none !important;
                        }
                        /* Keep file summary, destination input, picker, and actions on the same left edge. */
                        #mega-copy-form > p,
                        #mega-copy-form > #mega-folder-picker {
                            margin-left: 0 !important;
                            padding-left: 0 !important;
                            text-indent: 0 !important;
                        }
                        #mega-copy-form > #mega-folder-picker {
                            padding: 1rem !important;
                            width: 100%;
                            box-sizing: border-box;
                        }
                        #mega-copy-form #inp_copy_to {
                            max-width: 100% !important;
                            min-width: 0;
                        }
                    </style>
                    <p class="break-word"><strong><?php echo lng('Files') ?></strong>: <b><?php echo implode('</b>, <b>', $copy_files) ?></b></p>
                    <p class="break-word"><strong><?php echo lng('SourceFolder') ?></strong>: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?><br>
                        <label for="inp_copy_to"><strong><?php echo lng('DestinationFolder') ?></strong>:</label>
                        <?php echo FM_ROOT_PATH ?>/<input type="text" name="copy_to" id="inp_copy_to" value="<?php echo fm_enc(FM_PATH) ?>" class="form-control d-inline-block" style="max-width:300px">
                    </p>
                    <section id="mega-copy-v43" class="mega-copy-v43" aria-label="<?php echo lng('Select destination folder'); ?>">
                      <div class="mega-copy-v43-source">
                        <i class="fa fa-file-o" aria-hidden="true"></i>
                        <div><strong id="mega-copy-v43-files"></strong><small><?php echo lng('SourceFolder'); ?>: <?php echo fm_enc(FM_ROOT_PATH . '/' . FM_PATH); ?></small></div>
                      </div>
                      <div class="mega-copy-v43-heading"><?php echo lng('DestinationFolder'); ?></div>
                      <nav id="mega-copy-v43-crumbs" class="mega-copy-v43-crumbs" aria-label="<?php echo lng('DestinationFolder'); ?>"></nav>
                      <?php fm_mega_folder_picker_ui(FM_PATH, 'bulk'); ?>
                      <div class="mega-copy-v43-target"><small><?php echo lng('DestinationFolder'); ?></small><strong><i class="fa fa-folder-open-o" aria-hidden="true"></i> <span id="mega-copy-v43-path"></span></strong></div>
                      <details class="mega-copy-v43-advanced"><summary><?php echo lng('DestinationFolder'); ?> · <?php echo lng('Edit'); ?></summary><div id="mega-copy-v43-manual"></div></details>
                      <div class="mega-copy-v43-actions">
                        <a href="?p=<?php echo urlencode(FM_PATH); ?>" id="mega-copy-v100-cancel" class="btn btn-outline-secondary mega-copy-v43-cancel"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></a>
                        <button type="button" id="mega-copy-v43-move" class="btn btn-success"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 10h8"/><path d="m16 6 4 4-4 4"/><path d="M20 10V5a2 2 0 0 0-2-2H8l-2 3H4a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3"/></svg> <?php echo lng('Move'); ?></button>
                        <button type="button" id="mega-copy-v43-copy" class="btn btn-primary"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg> <?php echo lng('Copy'); ?></button>
                      </div>
                    </section>
                    <style id="mega-copy-v43-style">
                    .mega-copy-v43{display:none}
                    #mega-copy-form .mega-copy-v43-actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}
                    #mega-copy-form .mega-copy-v43-actions .btn{min-height:52px;font-weight:650;min-width:0}
                    @media<?php echo fm_layout_media_query(); ?>{
                      #mega-copy-form>p.break-word,#mega-copy-form>div[role="group"]{display:none!important}
                      #mega-copy-form .mega-copy-v43{display:flex!important;flex-direction:column;gap:12px;min-width:0}
                      #mega-copy-form .mega-copy-v43-source{display:flex;align-items:center;gap:14px;padding:17px;border-radius:15px;background:var(--bs-secondary-bg,#eef0f3);min-width:0}
                      #mega-copy-form .mega-copy-v43-source>i{font-size:25px;color:var(--bs-secondary-color,#6b7680);width:35px;text-align:center}
                      #mega-copy-form .mega-copy-v43-source>div{min-width:0;display:flex;flex-direction:column;gap:6px;overflow-wrap:anywhere}
                      #mega-copy-form .mega-copy-v43-source strong{font-size:1.12rem}
                      #mega-copy-form .mega-copy-v43-source small{color:var(--bs-secondary-color,#6b7680)}
                      #mega-copy-form .mega-copy-v43-heading{font-weight:650;margin-top:6px}
                      #mega-copy-form .mega-copy-v43-crumbs{display:flex;align-items:center;flex-wrap:wrap;gap:3px;min-height:42px}
                      #mega-copy-form .mega-copy-v43-crumbs button{min-height:42px;border:0;background:transparent;color:var(--bs-link-color,#267bc4);padding:7px;border-radius:8px}
                      #mega-copy-form .mega-copy-v43-crumbs button[aria-current="location"]{font-weight:700;color:var(--bs-body-color,#222)}
                      #mega-copy-form .mega-copy-v43-crumbs .sep{color:var(--bs-secondary-color,#888)}
                      #mega-copy-form #mega-folder-picker{margin:0!important;padding:0!important;width:100%!important;max-height:none!important;overflow:hidden!important;border:1px solid var(--bs-border-color,#d9dfe5)!important;border-radius:16px!important;background:var(--bs-body-bg,#fff)!important}
                      #mega-copy-form #mega-folder-picker>div:first-child,#mega-copy-form #mega-folder-picker>div:nth-child(2){display:none!important}
                      #mega-copy-form #mega-folder-status{padding:12px 16px!important;margin:0!important;min-height:25px;font-size:.85rem}
                      #mega-copy-form #mega-folder-entries{display:flex!important;flex-direction:column!important;gap:0!important;max-height:40dvh;overflow-y:auto;overscroll-behavior:contain}
                      #mega-copy-form #mega-folder-entries>button{display:flex!important;align-items:center!important;position:relative;min-height:62px!important;width:100%!important;border:0!important;border-top:1px solid var(--bs-border-color,#e3e7eb)!important;border-radius:0!important;padding:12px 38px 12px 18px!important;margin:0!important;background:transparent!important;color:var(--bs-body-color,#222)!important;font-weight:600!important;font-size:1rem!important;text-align:left!important;box-shadow:none!important;white-space:normal!important;overflow-wrap:anywhere!important}
                      #mega-copy-form #mega-folder-entries>button:after{content:'›';position:absolute;right:16px;color:var(--bs-secondary-color,#888);font-size:25px}
                      #mega-copy-form .mega-copy-v43-target{display:flex;flex-direction:column;gap:8px;padding:15px;background:var(--bs-secondary-bg,#eef0f3);border-radius:14px;overflow-wrap:anywhere}
                      #mega-copy-form .mega-copy-v43-target small{color:var(--bs-secondary-color,#6b7680)}
                      #mega-copy-form .mega-copy-v43-target strong i{color:#218452;margin-right:8px}
                      #mega-copy-form .mega-copy-v43-advanced summary{padding:8px 0;cursor:pointer;color:var(--bs-secondary-color,#687580)}
                      #mega-copy-form .mega-copy-v43-advanced input{width:100%!important;max-width:100%!important;display:block!important}
                      #mega-copy-form .mega-copy-v43-mode{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin:0;padding:5px;border:0;border-radius:13px;background:var(--bs-secondary-bg,#eef0f3)}
                      #mega-copy-form .mega-copy-v43-mode label{position:relative;min-height:46px;display:flex;align-items:center;justify-content:center;margin:0;border-radius:10px;cursor:pointer}
                      #mega-copy-form .mega-copy-v43-mode input{position:absolute;opacity:0;width:1px;height:1px}
                      #mega-copy-form .mega-copy-v43-mode label:has(input:checked){background:var(--bs-body-bg,#fff);box-shadow:0 1px 5px rgba(0,0,0,.1);font-weight:650}
                      #mega-copy-form .mega-copy-v43-submit{width:100%!important;min-height:52px!important;margin:0!important;font-weight:650}
                      #mega-copy-form .mega-copy-v43-cancel{width:100%!important;min-height:46px!important}
                      body.theme-dark #mega-copy-form .mega-copy-v43-source,body.theme-dark #mega-copy-form .mega-copy-v43-target,body.theme-dark #mega-copy-form .mega-copy-v43-mode{background:#303b46}
                      body.theme-dark #mega-copy-form .mega-copy-v43-mode label:has(input:checked){background:#465461}
                    }
                    </style>
                    <style id="mega-copy-v100-three-actions">
                    /* Keep the same three actions in the same order at all sizes. */
                    @media<?php echo fm_layout_media_query(); ?>{
                      #mega-copy-form .mega-copy-v43-actions{
                        display:grid!important;
                        grid-template-columns:repeat(3,minmax(0,1fr))!important;
                        gap:8px!important;
                        width:100%!important;
                      }
                      #mega-copy-form .mega-copy-v43-actions > .btn{
                        display:inline-flex!important;
                        align-items:center!important;
                        justify-content:center!important;
                        width:100%!important;
                        min-width:0!important;
                        max-width:none!important;
                        flex:initial!important;
                        min-height:44px!important;
                        padding:8px 4px!important;
                        white-space:nowrap!important;
                        font-size:clamp(12px,3.3vw,16px)!important;
                      }
                      #mega-copy-form .mega-copy-v43-actions > .btn i{flex:none}
                    }
                    @media<?php echo fm_desktop_media_query(); ?>{
                      #mega-copy-form .mega-copy-v43-actions > .btn{
                        display:inline-flex!important;
                        align-items:center!important;
                        justify-content:center!important;
                      }
                    }
                    </style>
                    <style id="mega-copy-v101-icons">#mega-copy-form .mega-copy-v43-actions > .btn svg{display:inline-block;vertical-align:middle;flex:none;margin-right:6px;stroke:currentColor}</style>
                    <style id="mega-copy-v82-desktop-style">
                    /* Desktop Copy/Move: use the existing working folder picker and
                       actions already used on mobile; leave mobile rules untouched. */
                    @media <?php echo fm_desktop_media_query(); ?> {
                      #mega-copy-form > p.break-word,
                      #mega-copy-form > div[role="group"] {display:none!important}
                      #mega-copy-form .mega-copy-v43 {display:flex!important;flex-direction:column;gap:12px;min-width:0}
                      #mega-copy-form .mega-copy-v43-source {display:flex;align-items:center;gap:14px;padding:15px;border-radius:12px;background:var(--bs-secondary-bg,#eef0f3);min-width:0}
                      #mega-copy-form .mega-copy-v43-source > i {font-size:25px;color:var(--bs-secondary-color,#6b7680);width:35px;text-align:center}
                      #mega-copy-form .mega-copy-v43-source > div {min-width:0;display:flex;flex-direction:column;gap:6px;overflow-wrap:anywhere}
                      #mega-copy-form .mega-copy-v43-source small {color:var(--bs-secondary-color,#6b7680)}
                      #mega-copy-form .mega-copy-v43-heading {font-weight:650;margin-top:4px}
                      #mega-copy-form .mega-copy-v43-crumbs {display:flex;align-items:center;flex-wrap:wrap;gap:3px;min-height:36px}
                      #mega-copy-form .mega-copy-v43-crumbs button {min-height:36px;border:0;background:transparent;color:var(--bs-link-color,#267bc4);padding:6px 9px;border-radius:8px}
                      #mega-copy-form .mega-copy-v43-crumbs button[aria-current="location"] {font-weight:700;color:var(--bs-body-color,#222)}
                      #mega-copy-form .mega-copy-v43-crumbs .sep {color:var(--bs-secondary-color,#888)}
                      #mega-copy-form #mega-folder-picker {margin:0!important;padding:0!important;width:100%!important;max-height:none!important;overflow:hidden!important;border:1px solid var(--bs-border-color,#d9dfe5)!important;border-radius:12px!important;background:var(--bs-body-bg,#fff)!important}
                      #mega-copy-form #mega-folder-picker > div:first-child,
                      #mega-copy-form #mega-folder-picker > div:nth-child(2) {display:none!important}
                      #mega-copy-form #mega-folder-status {padding:12px 16px!important;margin:0!important;min-height:25px;font-size:.9rem}
                      #mega-copy-form #mega-folder-entries {display:flex!important;flex-direction:column!important;gap:0!important;max-height:340px;overflow-y:auto}
                      #mega-copy-form #mega-folder-entries > button {display:flex!important;align-items:center!important;position:relative;min-height:52px!important;width:100%!important;border:0!important;border-top:1px solid var(--bs-border-color,#e3e7eb)!important;border-radius:0!important;padding:10px 38px 10px 18px!important;margin:0!important;background:transparent!important;color:var(--bs-body-color,#222)!important;font-weight:600!important;text-align:left!important;white-space:normal!important;overflow-wrap:anywhere!important}
                      #mega-copy-form #mega-folder-entries > button:after {content:'›';position:absolute;right:16px;color:var(--bs-secondary-color,#888);font-size:24px}
                      #mega-copy-form .mega-copy-v43-target {display:flex;flex-direction:column;gap:8px;padding:14px;background:var(--bs-secondary-bg,#eef0f3);border-radius:12px;overflow-wrap:anywhere}
                      #mega-copy-form .mega-copy-v43-target small {color:var(--bs-secondary-color,#6b7680)}
                      #mega-copy-form .mega-copy-v43-target strong i {color:#218452;margin-right:8px}
                      #mega-copy-form .mega-copy-v43-advanced summary {padding:8px 0;cursor:pointer;color:var(--bs-secondary-color,#687580)}
                      #mega-copy-form .mega-copy-v43-advanced input {width:100%!important;max-width:100%!important;display:block!important}
                      #mega-copy-form .mega-copy-v43-actions {display:flex!important;justify-content:center!important;gap:12px!important}
                      #mega-copy-form .mega-copy-v43-actions .btn {width:120px!important;min-width:120px!important;max-width:120px!important;flex:0 0 120px!important;min-height:42px!important}
                      body.theme-dark #mega-copy-form .mega-copy-v43-source,
                      body.theme-dark #mega-copy-form .mega-copy-v43-target {background:#303b46}
                    }
                    </style>
                    <script id="mega-copy-v43-script">
                    (function(){
                      var form=document.getElementById('mega-copy-form');
                      if(!form)return;
                      var input=document.getElementById('inp_copy_to');
                      var target=document.getElementById('mega-copy-v43-path');
                      var crumbs=document.getElementById('mega-copy-v43-crumbs');
                      var label=form.querySelector('label[for="inp_copy_to"]');
                      var manual=document.getElementById('mega-copy-v43-manual');
                      var files=Array.from(form.querySelectorAll('input[name="file[]"]')).map(function(x){return x.value;});
                      document.getElementById('mega-copy-v43-files').textContent=files.length===1?files[0]:files.length+' '+<?php echo json_encode(html_entity_decode(lng('Files'), ENT_QUOTES, 'UTF-8')); ?>;
                      if(label)manual.appendChild(label);
                      if(input)manual.appendChild(input);
                      var pickerLocation=document.getElementById('mega-folder-location');
                      function navigate(path){
                        if(!input)return;
                        input.value=path;
                        input.dispatchEvent(new Event('change',{bubbles:true}));
                      }
                      function update(){
                        var path=input?input.value.replace(/^\/+|\/+$/g,''):'';
                        target.textContent=(window.FM_STORAGE_TYPE==='local'?'Local / ':'mega://root/')+(path?path+'/':'');
                        crumbs.textContent='';
                        var parts=path?path.split('/'):[];
                        function add(text,value,last){
                          var b=document.createElement('button');b.type='button';b.textContent=text;
                          if(last)b.setAttribute('aria-current','location');
                          b.addEventListener('click',function(){navigate(value);});
                          crumbs.appendChild(b);
                        }
                        // Use the same Font Awesome home icon as the main breadcrumb.
                        var home=document.createElement('button');
                        home.type='button';
                        home.setAttribute('aria-label','Home');
                        home.setAttribute('title','Home');
                        var homeIcon=document.createElement('i');
                        homeIcon.className='fa fa-home';
                        homeIcon.setAttribute('aria-hidden','true');
                        home.appendChild(homeIcon);
                        if(parts.length===0)home.setAttribute('aria-current','location');
                        home.addEventListener('click',function(){navigate('');});
                        crumbs.appendChild(home);
                        parts.forEach(function(part,i){var sep=document.createElement('span');sep.className='sep';sep.textContent='›';crumbs.appendChild(sep);add(part,parts.slice(0,i+1).join('/'),i===parts.length-1);});
                      }
                      if(pickerLocation && window.MutationObserver)new MutationObserver(update).observe(pickerLocation,{childList:true,characterData:true,subtree:true});
                      if(input)input.addEventListener('input',update);
                      update();
                      function perform(action){
                        var selector=action==='move'?'div[role="group"] button[type="submit"][name="move"]':'div[role="group"] button[type="submit"]:not([name="move"])';
                        var original=form.querySelector(selector);
                        if(original)original.click();
                      }
                      document.getElementById('mega-copy-v43-move').addEventListener('click',function(){perform('move');});
                      document.getElementById('mega-copy-v43-copy').addEventListener('click',function(){perform('copy');});
                    })();
                    </script>
                    <div class="d-flex flex-wrap align-items-center gap-2 mt-3" role="group" aria-label="<?php echo lng('Copy or move selected items') ?>">
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <button type="submit" class="btn btn-success"><i class="fa fa-check" aria-hidden="true"></i> <?php echo lng('Copy') ?></button>
                        <button type="submit" name="move" value="1" class="btn btn-primary"><i class="fa fa-check" aria-hidden="true"></i> <?php echo lng('Move') ?></button>
                    </div>
                </form>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

// copy form
if (isset($_GET['copy']) && !isset($_GET['finish']) && !FM_READONLY) {
    $copy = $_GET['copy'];
    $copy = fm_clean_path($copy);
    if ($copy == '' || !file_exists(FM_ROOT_PATH . '/' . $copy)) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
?>
    <div class="path">
        <p><b><?php echo lng('Copy/Move'); ?></b></p>
        <p class="break-word">
            <strong><?php echo lng('Source path') ?>:</strong> <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . $copy)) ?><br>
            <strong><?php echo lng('Destination folder') ?>:</strong> <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?>
        </p>
        <div class="d-flex flex-wrap align-items-center gap-2 my-3">
            <a class="btn btn-outline-secondary" href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel') ?></a>
            <a class="btn btn-success" id="mega-picker-copy-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1"><i class="fa fa-check" aria-hidden="true"></i> <?php echo lng('Copy') ?></a>
            <a class="btn btn-primary" id="mega-picker-move-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1&amp;move=1"><i class="fa fa-check" aria-hidden="true"></i> <?php echo lng('Move') ?></a>
        </div>
        <?php fm_mega_folder_picker_ui(FM_PATH, 'single', $copy); ?>
    </div>
<?php
    fm_show_footer();
    exit;
}

if (isset($_GET['settings']) && !FM_READONLY) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    global $cfg, $lang, $lang_list;
?>

    <style>
        /* Compact Settings layout, scoped to this page only. */
        .mega-settings-panel { padding-top: .65rem !important; }
        .mega-settings-panel .card-body { padding: 1rem 1.15rem; }
        .mega-settings-panel .card-header { padding: .65rem 1rem; }
        .mega-settings-panel .form-group.row,
        .mega-settings-panel form > .row { margin-top: 0 !important; margin-bottom: .75rem !important; }
        .mega-settings-panel form > .row:last-child { margin-bottom: 0 !important; }
        .mega-settings-panel .col-form-label { padding-top: .35rem; padding-bottom: .35rem; }
        .mega-settings-panel .form-check { min-height: 1.35rem; margin-bottom: 0; }
        @media (max-width: 575.98px) {
            .mega-settings-panel .card-body { padding: .85rem 1rem; }
            .mega-settings-panel .form-group.row,
            .mega-settings-panel form > .row { margin-bottom: .65rem !important; }
            .mega-settings-panel .col-form-label { padding-top: 0; padding-bottom: .2rem; }
            .mega-settings-panel .form-select { min-height: 2.35rem; padding-top: .3rem; padding-bottom: .3rem; }
        }
    </style>
    <div class="col-md-8 offset-md-2 pt-3 mega-settings-panel" data-bs-theme="<?php echo FM_THEME; ?>">
        <div class="card mb-2 fm-form-panel" data-bs-theme="<?php echo FM_THEME; ?>">
            <h6 class="card-header d-flex justify-content-between">
                <span><i class="fa fa-cog"></i> <?php echo lng('Settings') ?></span>
            </h6>
            <div class="card-body">
                <form id="js-settings-form" action="" method="post" data-type="ajax" onsubmit="return save_settings(this)">
                    <input type="hidden" name="type" value="settings" aria-label="hidden" aria-hidden="true">
                    <div class="form-group row">
                        <label for="js-language" class="col-sm-3 col-form-label"><?php echo lng('Language') ?></label>
                        <div class="col-sm-5">
                            <select class="form-select" id="js-language" name="js-language">
                                <?php
                                function getSelected($l)
                                {
                                    global $lang;
                                    return ($lang == $l) ? 'selected' : '';
                                }
                                foreach ($lang_list as $k => $v) {
                                    echo "<option value='$k' " . getSelected($k) . ">$v</option>";
                                }
                                ?>
                            </select>
                        </div>
                    </div>
                    <div class="mt-3 mb-3 row ">
                        <label for="js-error-report" class="col-sm-3 col-form-label"><?php echo lng('ErrorReporting') ?></label>
                        <div class="col-sm-9">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="js-error-report" name="js-error-report" value="true" <?php echo $report_errors ? 'checked' : ''; ?> disabled />
                                <small class="text-muted"><?php echo lng('Server administrator setting (not saved in browser).'); ?></small>
                            </div>
                        </div>
                    </div>

                    <div class="mb-3 row">
                        <label for="js-show-hidden" class="col-sm-3 col-form-label"><?php echo lng('ShowHiddenFiles') ?></label>
                        <div class="col-sm-9">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="js-show-hidden" name="js-show-hidden" value="true" <?php echo $show_hidden_files ? 'checked' : ''; ?> />
                            </div>
                        </div>
                    </div>

                    <div class="mb-3 row">
                        <label for="js-3-0" class="col-sm-3 col-form-label"><?php echo lng('Theme') ?></label>
                        <div class="col-sm-5">
                            <select class="form-select w-100 text-capitalize" id="js-3-0" name="js-theme-3">
                                <option value='light' <?php if ($theme == "light") {
                                                            echo "selected";
                                                        } ?>>
                                    <?php echo lng('light') ?>
                                </option>
                                <option value='dark' <?php if ($theme == "dark") {
                                                            echo "selected";
                                                        } ?>>
                                    <?php echo lng('dark') ?>
                                </option>
                            </select>
                        </div>
                    </div>

                    <?php if (FM_STORAGE_TYPE === 'mega'): ?>
                    <div class="mb-3 row"><label for="js-delete-mode" class="col-sm-3 col-form-label"><?php echo lng('Delete behavior'); ?></label><div class="col-sm-5"><select class="form-select w-100" id="js-delete-mode"><option value="rubbish" <?php echo FM_DELETE_MODE==='rubbish'?'selected':''; ?>><?php echo lng('Move to Rubbish Bin'); ?></option><option value="permanent" <?php echo FM_DELETE_MODE==='permanent'?'selected':''; ?>><?php echo lng('Delete permanently'); ?></option></select></div></div>
                    <?php endif; ?>
                    <div class="mb-3 row">
                        <label for="js-view-mode" class="col-sm-3 col-form-label"><?php echo lng('Layout'); ?></label>
                        <div class="col-sm-5">
                            <select class="form-select w-100" id="js-view-mode" name="js-view-mode">
                                <?php foreach (array('auto' => 'Auto (browser detection)', 'mobile' => 'Mobile', 'desktop' => 'Desktop') as $value => $label): ?>
                                <option value="<?php echo $value; ?>" <?php echo FM_VIEW_MODE === $value ? 'selected' : ''; ?>><?php echo lng($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>

                    <div class="mb-3 row">
                        <div class="col-sm-10 mega-two-action-row">
                            <a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-secondary me-2"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></a>
                            <button type="submit" class="btn btn-primary mega-save-action"><i class="fa fa-floppy-o mega-save-icon" aria-hidden="true"></i> <?php echo lng('Save'); ?></button>
                        </div>
                    </div>

                </form>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

if (isset($_GET['help'])) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    global $cfg, $lang;
?>

    <div class="col-md-8 offset-md-2 pt-3 fm-form-panel-shell">
        <div class="card mb-2 fm-form-panel" data-bs-theme="<?php echo FM_THEME; ?>">
            <h6 class="card-header d-flex justify-content-between">
                <span><i class="fa fa-exclamation-circle"></i> <?php echo lng('Help') ?></span>
                <a href="?p=<?php echo FM_PATH ?>" class="text-danger"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel') ?></a>
            </h6>
            <div class="card-body">
                <div class="row">
                    <div class="col-xs-12 col-sm-6">
                        <p>
                        <h3><a href="https://github.com/prasathmani/tinyfilemanager" target="_blank" class="app-v-title"> <?php echo lng("AppName")." ".VERSION; ?></a></h3>
                        </p>
                        <p><strong><?php echo lng('Author') ?></strong>: PRAŚATH MANİ</p>
                        <p><strong><?php echo lng('Mail Us') ?></strong>: <a href="mailto:ccpprogrammers@gmail.com">ccpprogrammers [at] gmail [dot] com</a></p>
                    </div>
                    <div class="col-xs-12 col-sm-6">
                        <div class="card">
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item"><a href="https://github.com/prasathmani/tinyfilemanager/wiki" target="_blank"><i class="fa fa-question-circle"></i> <?php echo lng('Help Documents') ?> </a> </li>
                                <li class="list-group-item"><a href="https://github.com/prasathmani/tinyfilemanager/issues" target="_blank"><i class="fa fa-bug"></i> <?php echo lng('Report Issue') ?></a></li>
                                <?php if (!FM_READONLY) { ?>
                                    <li class="list-group-item"><a href="javascript:show_new_pwd();"><i class="fa fa-lock"></i> <?php echo lng('Generate new password hash') ?></a></li>
                                <?php } ?>
                            </ul>
                        </div>
                    </div>
                </div>
                <div class="row js-new-pwd hidden mt-2">
                    <div class="col-12">
                        <form class="form-inline" onsubmit="return new_password_hash(this)" method="POST" action="">
                            <input type="hidden" name="type" value="pwdhash" aria-label="hidden" aria-hidden="true">
                            <div class="form-group mb-2">
                                <label for="staticEmail2"><?php echo lng('Generate new password hash') ?></label>
                            </div>
                            <div class="form-group mx-sm-3 mb-2">
                                <label for="inputPassword2" class="sr-only"><?php echo lng('Password') ?></label>
                                <input type="text" class="form-control btn-sm" id="inputPassword2" name="inputPassword2" placeholder="<?php echo lng('Password') ?>" required>
                            </div>
                            <button type="submit" class="btn btn-success btn-sm mb-2"><i class="fa fa-check" aria-hidden="true"></i> <?php echo lng('Generate') ?></button>
                        </form>
                        <textarea class="form-control" rows="2" readonly id="js-pwd-result"></textarea>
                    </div>
                </div>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

// Legacy Office read-only text preview. Conversion is optional; no changes to originals.
function mega_legacy_office_preview($source, $ext, $bytes) {
    if (!in_array($ext, array('doc', 'ppt'), true)) return array(false, 'Unsupported file format.');
    if ($bytes > 12 * 1024 * 1024) return array(false, 'Legacy Office preview is limited to 12 MB. Download the file to view it.');
    if (!function_exists('exec') || !is_callable('exec')) return array(false, 'Server conversion is unavailable. Download the file to view it.');
    $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'mega-office-' . bin2hex(random_bytes(8));
    if (!@mkdir($dir, 0700)) return array(false, 'Temporary preview storage is unavailable.');
    $input = $dir . DIRECTORY_SEPARATOR . 'source.' . $ext;
    $out = '';
    try {
        $in = @fopen($source, 'rb');
        $dest = @fopen($input, 'wb');
        if (!$in || !$dest) return array(false, 'Unable to load this document.');
        $copied = 0;
        while (!feof($in)) {
            $chunk = fread($in, 65536);
            if ($chunk === false) break;
            $copied += strlen($chunk);
            if ($copied > 12 * 1024 * 1024) break;
            if (fwrite($dest, $chunk) !== strlen($chunk)) break;
        }
        fclose($in); fclose($dest);
        if ($copied > 12 * 1024 * 1024 || $copied === 0) return array(false, 'Unable to preview this file (empty or too large).');
        if ($ext === 'doc') {
            $cmd = 'timeout 20s antiword -w 120 ' . escapeshellarg($input) . ' 2>/dev/null';
            $lines = array(); $code = 1;
            @exec($cmd, $lines, $code);
            if ($code === 0 && trim(implode("\n", $lines)) !== '') return array(true, substr(implode("\n", $lines), 0, 250000));
            // Some .doc files require LibreOffice instead of antiword.
        }
        $profile = $dir . DIRECTORY_SEPARATOR . 'profile';
        $cmd = 'timeout 25s libreoffice -env:UserInstallation=' . escapeshellarg('file://' . $profile)
             . ' --headless --convert-to pdf --outdir ' . escapeshellarg($dir) . ' ' . escapeshellarg($input) . ' >/dev/null 2>&1';
        $lines = array(); $code = 1;
        @exec($cmd, $lines, $code);
        $pdf = $dir . DIRECTORY_SEPARATOR . 'source.pdf';
        if ($code !== 0 || !is_file($pdf)) return array(false, 'Legacy ' . strtoupper($ext) . ' preview requires LibreOffice on the server. Download the file to view it.');
        $cmd = 'timeout 15s pdftotext -layout -enc UTF-8 ' . escapeshellarg($pdf) . ' - 2>/dev/null';
        $lines = array(); $code = 1;
        @exec($cmd, $lines, $code);
        $out = trim(implode("\n", $lines));
        if ($code !== 0 || $out === '') return array(false, 'Text extraction requires pdftotext on the server. Download the file to view it.');
        return array(true, substr($out, 0, 250000));
    } finally {
        foreach (array('source.doc', 'source.ppt', 'source.pdf') as $f) @unlink($dir . DIRECTORY_SEPARATOR . $f);
        // LibreOffice profile can create nested directories; remove only inside our random temp directory.
        if (is_dir($dir . DIRECTORY_SEPARATOR . 'profile')) {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir . DIRECTORY_SEPARATOR . 'profile', FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $entry) { if ($entry->isDir()) @rmdir($entry->getPathname()); else @unlink($entry->getPathname()); }
            @rmdir($dir . DIRECTORY_SEPARATOR . 'profile');
        }
        @rmdir($dir);
    }
}

// file viewer
if (isset($_GET['view'])) {
    $file = $_GET['view'];
    $file = fm_clean_path($file, false);
    $file = str_replace('/', '', $file);
    if ($file == '' || !is_file($path . '/' . $file) || !fm_is_exclude_items($file, $path . '/' . $file)) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path

    $file_url = FM_ROOT_URL . fm_convert_win((FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file);
    // MEGA files are not served by the web server at FM_ROOT_URL.
    // Serve authenticated image previews through the PHP stream wrapper.
    if (strpos($path, 'mega://') === 0) {
        $previewExt = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $endpoint = $previewExt === 'pptx' ? 'mega_pptx' : ($previewExt === 'pdf' ? 'mega_pdf' : ($previewExt === 'docx' ? 'mega_docx' : ($previewExt === 'vsdx' ? 'mega_vsdx' : (in_array($previewExt, array('xls', 'xlsx', 'xlsm'), true) ? 'mega_excel' : 'mega_image'))));
        $file_url = FM_SELF_URL . '?p=' . rawurlencode(FM_PATH) . '&' . $endpoint . '=' . rawurlencode($file);
    }

    $file_path = $path . '/' . $file;

    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    $mime_type = fm_get_mime_type($file_path);
    $filesize_raw = fm_get_size($file_path);
    $filesize = fm_get_filesize($filesize_raw);

    $is_zip = false;
    $is_gzip = false;
    $is_image = false;
    $is_audio = false;
    $is_video = false;
    $is_text = false;
    $is_onlineViewer = false;

    $view_title = 'File';
    $filenames = false; // for zip
    $content = ''; // for text
    $online_viewer = strtolower(FM_DOC_VIEWER);

    if ($ext === 'pptx' && strpos($path, 'mega://') === 0) {
        $view_title = 'PowerPoint';
    } elseif ($ext === 'pdf' && strpos($path, 'mega://') === 0) {
        $view_title = 'PDF';
    } elseif ($online_viewer && $online_viewer !== 'false' && in_array($ext, fm_get_onlineViewer_exts())) {
        $is_onlineViewer = true;
    } elseif ($ext == 'zip' || $ext == 'tar') {
        $is_zip = true;
        $view_title = 'Archive';
        $filenames = fm_get_zip_info($file_path, $ext);
    } elseif (in_array($ext, fm_get_image_exts())) {
        $is_image = true;
        $view_title = 'Image';
    } elseif (in_array($ext, fm_get_audio_exts())) {
        $is_audio = true;
        $view_title = 'Audio';
    } elseif (in_array($ext, fm_get_video_exts())) {
        $is_video = true;
        $view_title = 'Video';
    } elseif (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
        $is_text = true;
        $content = file_get_contents($file_path);
    }

?>
    <div class="row">
        <div class="col-12">
            <ul class="list-group mega-file-details my-3" data-bs-theme="<?php echo FM_THEME; ?>">
                <li class="list-group-item active" aria-current="true"><strong><?php echo lng($view_title) ?>:</strong> <span class="mega-detail-value" title="<?php echo fm_enc(fm_convert_win($file)) ?>"><?php echo fm_enc(fm_convert_win($file)) ?></span></li>
                <?php $display_path = fm_get_display_path($file_path); ?>
                <li class="list-group-item"><strong><?php echo $display_path['label']; ?>:</strong> <span class="mega-detail-value" title="<?php echo $display_path['path']; ?>"><?php echo $display_path['path']; ?></span></li>
                <li class="list-group-item"><strong><?php echo lng('Date Modified') ?>:</strong> <?php echo date(FM_DATETIME_FORMAT, filemtime($file_path)); ?></li>
                <li class="list-group-item"><strong><?php echo lng('File size') ?>:</strong> <?php echo ($filesize_raw <= 1000) ? "$filesize_raw bytes" : $filesize; ?></li>
                <li class="list-group-item"><strong><?php echo lng('MIME-type') ?>:</strong> <?php echo $mime_type ?></li>
                <?php
                // ZIP info
                if (($is_zip || $is_gzip) && $filenames !== false) {
                    $total_files = 0;
                    $total_comp = 0;
                    $total_uncomp = 0;
                    foreach ($filenames as $fn) {
                        if (!$fn['folder']) {
                            $total_files++;
                        }
                        $total_comp += $fn['compressed_size'];
                        $total_uncomp += $fn['filesize'];
                    }
                ?>
                    <li class="list-group-item"><?php echo lng('Files in archive') ?>: <?php echo $total_files ?></li>
                    <li class="list-group-item"><?php echo lng('Total size') ?>: <?php echo fm_get_filesize($total_uncomp) ?></li>
                    <li class="list-group-item"> <?php echo lng('Size in archive') ?>: <?php echo fm_get_filesize($total_comp) ?></li>
                    <li class="list-group-item"><?php echo lng('Compression') ?>: <?php echo round(($total_comp / max($total_uncomp, 1)) * 100) ?>%</li>
                <?php
                }
                // Image info
                if ($is_image) {
                    $image_size = getimagesize($file_path);
                    echo '<li class="list-group-item"><strong>' . lng('Image size') . ':</strong> ' . (isset($image_size[0]) ? $image_size[0] : '0') . ' x ' . (isset($image_size[1]) ? $image_size[1] : '0') . '</li>';
                }
                // Text info
                if ($is_text) {
                    $is_utf8 = fm_is_utf8($content);
                    if (function_exists('iconv')) {
                        if (!$is_utf8) {
                            $content = iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $content);
                        }
                    }
                    echo '<li class="list-group-item"><strong>' . lng('Charset') . ':</strong> ' . ($is_utf8 ? 'utf-8' : '8 bit') . '</li>';
                }
                ?>
            </ul>
            <style>
              /* Full-width details; keep long names and paths inside the card. */
              .mega-file-details{width:100%!important;max-width:100%!important;min-width:0!important}
              .mega-file-details .list-group-item{min-width:0;max-width:100%;overflow:hidden}
              .mega-file-details .mega-detail-value{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%;min-width:0}
              .mega-file-details .list-group-item.active .mega-detail-value{margin-top:3px}
              @media<?php echo fm_desktop_media_query(); ?>{.mega-file-details{max-width:100%!important}}
            </style>
            <style>
              .mega-preview-actions{display:flex;flex-wrap:wrap;gap:9px;margin:18px 0}
              .mega-preview-actions .btn,.mega-preview-actions form{margin:0!important}
              .mega-preview-actions .btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;border:1px solid #e0e6ed!important;background:#f8fafc!important;color:#334155!important;border-radius:11px!important;padding:10px 14px!important;font-weight:600!important;min-height:44px;box-shadow:none!important;text-decoration:none!important}
              .mega-preview-actions .btn:hover{background:#eaf2fa!important}
              .mega-preview-actions .btn .fa{font-size:1rem;line-height:1.2}
              .mega-preview-actions form .btn-link{font-size:inherit!important;padding:0!important;min-height:0!important;border:0!important;background:transparent!important}
              .mega-preview-actions .mega-danger{color:#be3344!important;background:#fff5f5!important;border-color:#f4d5d9!important}
              .mega-preview-actions form .btn{height:100%}
              @media(max-width:500px){.mega-preview-actions .btn{flex:1 1 auto;font-size:13px!important;padding:10px!important}}
              @media<?php echo fm_layout_media_query(); ?>{.mega-preview-actions{display:flex!important;gap:8px!important}.mega-preview-actions>.mega-preview-cancel,.mega-preview-actions>.mega-danger,.mega-preview-actions>form[data-no-processing="download"]{flex:1 1 0!important;min-width:0!important;width:0!important;max-width:none!important}.mega-preview-actions>form[data-no-processing="download"]{display:flex!important}.mega-preview-actions>form[data-no-processing="download"]>.btn{width:100%!important;white-space:nowrap!important}.mega-preview-actions>.mega-preview-cancel,.mega-preview-actions>.mega-danger{white-space:nowrap!important}.mega-preview-actions>.mega-preview-cancel{order:0!important}}
            </style>
            <style id="mega-preview-mobile-action-grid-v59">
              /* Shared actions for every file preview: no more than three per row. */
              @media screen and <?php echo fm_layout_media_query(); ?>{
                .mega-preview-actions{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:9px!important;align-items:stretch!important;width:100%!important}
                .mega-preview-actions>a,.mega-preview-actions>form{display:flex!important;box-sizing:border-box!important;width:100%!important;min-width:0!important;max-width:none!important;margin:0!important;flex:none!important;order:initial!important}
                .mega-preview-actions>a.btn,.mega-preview-actions>form>.btn{box-sizing:border-box!important;width:100%!important;min-width:0!important;max-width:none!important;height:100%!important;min-height:46px!important;display:flex!important;align-items:center!important;justify-content:center!important;gap:5px!important;padding:9px 5px!important;font-size:clamp(10px,2.8vw,14px)!important;line-height:1.2!important;white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important;text-align:center!important}
                .mega-preview-actions>form.mega-unzip-form{padding:0!important;border:0!important;background:transparent!important;box-shadow:none!important}
                .mega-preview-actions>form.mega-unzip-form>.btn{border:1px solid #e0e6ed!important;background:#f8fafc!important;color:#334155!important;border-radius:11px!important;font-weight:600!important;text-decoration:none!important}
                .mega-preview-actions>form:is([data-mega-operation="unzip-folder"],[data-mega-operation="untar-folder"]){grid-column:span 2!important}
                .mega-preview-actions .mega-preview-cancel{order:0!important}
                .mega-preview-actions .mega-danger{order:1!important}
                .mega-preview-actions>form[data-no-processing="download"]{order:2!important}
                .mega-preview-actions>form:is([data-mega-operation="unzip"],[data-mega-operation="untar"]){order:3!important}
                .mega-preview-actions>form:is([data-mega-operation="unzip-folder"],[data-mega-operation="untar-folder"]){order:4!important}
              }
            </style>
            <style id="mega-preview-mobile-action-grid-v60">
            /* The three common actions occupy row one in every previewer.
               Reset legacy flex sizing (including width:0) on the download form. */
            @media screen and <?php echo fm_layout_media_query(); ?>{
              html body .mega-preview-actions{
                display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;
                grid-auto-flow:row!important;gap:8px!important;align-items:stretch!important;
                width:100%!important;max-width:100%!important;
              }
              html body .mega-preview-actions > a,
              html body .mega-preview-actions > form,
              html body .mega-preview-actions > form[data-no-processing="download"]{
                display:flex!important;box-sizing:border-box!important;
                flex:none!important;width:100%!important;min-width:0!important;
                max-width:100%!important;margin:0!important;align-self:stretch!important;
                grid-column:auto!important;
              }
              html body .mega-preview-actions > a.btn,
              html body .mega-preview-actions > form > button.btn,
              html body .mega-preview-actions > form[data-no-processing="download"] > button.btn{
                display:inline-flex!important;flex:1 1 auto!important;
                width:100%!important;min-width:0!important;max-width:100%!important;
                box-sizing:border-box!important;height:auto!important;min-height:44px!important;
                margin:0!important;padding:8px 3px!important;gap:4px!important;
                align-items:center!important;justify-content:center!important;
                font-size:clamp(10px,2.8vw,14px)!important;line-height:1.2!important;
                white-space:nowrap!important;word-break:normal!important;overflow-wrap:normal!important;
                text-align:center!important;
              }
              html body .mega-preview-actions > form.mega-unzip-form > button.btn{
                border:1px solid #e0e6ed!important;background:#f8fafc!important;
                color:#334155!important;border-radius:11px!important;font-weight:600!important;
              }
              html body .mega-preview-actions > .mega-preview-cancel{
                grid-column:1!important;grid-row:1!important;order:0!important;
              }
              html body .mega-preview-actions > .mega-danger{
                grid-column:2!important;grid-row:1!important;order:1!important;
              }
              html body .mega-preview-actions > form[data-no-processing="download"]{
                grid-column:3!important;grid-row:1!important;order:2!important;
              }
              html body .mega-preview-actions > form:is([data-mega-operation="unzip"],[data-mega-operation="untar"]){order:3!important}
              html body .mega-preview-actions > form:is([data-mega-operation="unzip-folder"],[data-mega-operation="untar-folder"]){
                grid-column:span 2!important;order:4!important;
              }
              html body .mega-preview-actions > a:not(.mega-preview-cancel):not(.mega-danger){order:5!important}
              /* Read-only previewers have no Delete: keep Download usable in column two. */
              html body .mega-preview-actions:not(:has(> .mega-danger)) > form[data-no-processing="download"]{
                grid-column:2!important;
              }
            }
            </style>
            
<style id="mega-v106-extract-icons">
.mega-preview-actions .mega-unzip-form > button.btn {display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px!important;}
.mega-preview-actions .mega-unzip-form .mega-extract-icon {display:inline-block!important;flex:0 0 16px!important;width:16px!important;height:16px!important;vertical-align:middle!important;}
</style>
<div class="mega-preview-actions" role="group">
                <a class="btn mega-preview-cancel" href="?p=<?php echo urlencode(FM_PATH) ?>"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel') ?></a>
                <?php if (!FM_READONLY): ?>
                    <a class="btn mega-danger" title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($file) ?>" onclick="confirmDialog(event, 1209, '<?php echo lng('Delete') . ' ' . lng('File'); ?>','<?php echo urlencode($file); ?>', this.href);"> <i class="fa fa-trash"></i> <?php echo lng('Delete'); ?></a>
                <?php endif; ?>
                <form method="post" class="d-inline mb-0" data-no-processing="download" action="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($file) ?>">
                    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                    <button type="submit" class="btn"><i class="fa fa-cloud-download"></i> <?php echo lng('Download') ?></button>
                </form>
                <?php
                // ZIP actions
                if (!FM_READONLY && ($is_zip || $is_gzip) && $filenames !== false) {
                    $zip_name = pathinfo($file_path, PATHINFO_FILENAME);
                    $is_tar_action = strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'tar';
                ?>
                    <form method="post" class="d-inline btn btn-outline-primary mb-0 mega-unzip-form" data-mega-operation="<?php echo $is_tar_action ? 'untar' : 'unzip'; ?>">
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <input type="hidden" name="<?php echo $is_tar_action ? 'untar' : 'unzip'; ?>" value="<?php echo urlencode($file); ?>">
                        <button type="submit" class="btn btn-link text-decoration-none fw-bold p-0 border-0" ><svg class="mega-extract-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M12 12v6m-3-3 3 3 3-3"/></svg> <?php echo lng($is_tar_action ? 'UnTar' : 'UnZip') ?></button>
                    </form>
                    <form method="post" class="d-inline btn btn-outline-primary mb-0 mega-unzip-form" data-mega-operation="<?php echo $is_tar_action ? 'untar-folder' : 'unzip-folder'; ?>">
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <input type="hidden" name="<?php echo $is_tar_action ? 'untar' : 'unzip'; ?>" value="<?php echo urlencode($file); ?>">
                        <input type="hidden" name="tofolder" value="1">
                        <button type="submit" class="btn btn-link text-decoration-none fw-bold p-0"  title="<?php echo fm_enc(lng($is_tar_action ? 'UnTarToFolder' : 'UnZipToFolder') . ': '. $zip_name); ?>"><svg class="mega-extract-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 7h6l2 2h10v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 11v7m-3-3 3 3 3-3"/></svg> <?php echo lng($is_tar_action ? 'UnTarToFolder' : 'UnZipToFolder') ?></button>
                    </form>
                <?php
                }
                if ($is_text && !FM_READONLY) {
                ?>
                    <a class="fw-bold btn btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>" class="edit-file">
                        <i class="fa fa-pencil"></i> <?php echo lng('Edit') ?>
                    </a>
                    <a class="fw-bold btn btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>&env=ace"
                        class="edit-file"><i class="fa fa-pencil"></i> <?php echo lng('AdvancedEditor') ?>
                    </a>
                <?php } ?>
            </div>
            
<!-- Shared preview and editor palette: applies only to the selected dark theme.
     Keep photographs, video, embedded images and authored SVG colors unchanged. -->
<style id="mega-all-viewers-selected-theme">
body.theme-dark .mega-preview-content {
  color:#e6edf5;
  color-scheme:dark;
}
body.theme-dark .mega-preview-content #mega-pdf-viewer,
body.theme-dark .mega-preview-content #mega-docx-viewer,
body.theme-dark .mega-preview-content #mega-excel-viewer,
body.theme-dark .mega-preview-content #mega-vsdx-viewer,
body.theme-dark .mega-preview-content #mega-pptx-viewer {
  background:#202830!important;
  color:#e6edf5!important;
  border-color:#485666!important;
}
body.theme-dark .mega-preview-content #mega-pdf-viewer > div:first-child,
body.theme-dark .mega-preview-content #mega-docx-toolbar,
body.theme-dark .mega-preview-content #mega-excel-viewer > div:first-child,
body.theme-dark .mega-preview-content #mega-vsdx-viewer > div:first-child,
body.theme-dark .mega-preview-content #mega-pptx-viewer > div:first-child {
  background:#303c47!important;
  color:#edf3fa!important;
  border-color:#485666!important;
}
body.theme-dark .mega-preview-content #mega-pdf-pages,
body.theme-dark .mega-preview-content #mega-docx-pages,
body.theme-dark .mega-preview-content #mega-excel-scroll,
body.theme-dark .mega-preview-content #mega-vsdx-scroll,
body.theme-dark .mega-preview-content #mega-pptx-slides {
  background:#1b232b!important;
  color:#e6edf5!important;
}
body.theme-dark .mega-preview-content #mega-pdf-status,
body.theme-dark .mega-preview-content #mega-docx-status,
body.theme-dark .mega-preview-content #mega-excel-status,
body.theme-dark .mega-preview-content #mega-vsdx-status,
body.theme-dark .mega-preview-content #mega-pptx-status {
  background:#202830!important;
  color:#dbe5ef!important;
}
body.theme-dark .mega-preview-content .btn-outline-secondary,
body.theme-dark .mega-preview-content select,
body.theme-dark .mega-preview-content .form-select {
  background:#364450!important;
  border-color:#647487!important;
  color:#f1f5fa!important;
}
body.theme-dark .mega-preview-content #mega-excel-grid table,
body.theme-dark .mega-preview-content #mega-excel-grid td {
  background:#202a34!important;
  color:#edf3fa!important;
  border-color:#4a5969!important;
}
body.theme-dark .mega-preview-content #mega-excel-grid thead th {
  background:#354453!important;
  color:#f1f5fa!important;
  border-color:#536474!important;
}
body.theme-dark .mega-preview-content #mega-excel-grid tbody th {
  background:#2d3a46!important;
  color:#dce6f1!important;
  border-color:#536474!important;
}
/* Text, archives and other plain-text previews (not images/media). */
body.theme-dark .mega-preview-content pre,
body.theme-dark .mega-preview-content pre code,
body.theme-dark .mega-preview-content code.maxheight,
body.theme-dark .mega-preview-content .highlight,
body.theme-dark .mega-preview-content .hljs {
  background:#1c252e!important;
  color:#e5edf5!important;
  border-color:#485666!important;
}
body.theme-dark .mega-preview-content .list-group-item,
body.theme-dark .mega-preview-content .table {
  background:#26313b;
  color:#e5edf5;
  border-color:#485666;
}
/* Plain editor and Ace editor both inherit the user's selected palette. */
body.theme-dark textarea#editor,
body.theme-dark #editor:not(.ace_editor),
body.theme-dark .CodeMirror {
  background:#1d252e!important;
  color:#e6edf5!important;
  border-color:#526172!important;
  caret-color:#69b0ff;
}
body.theme-dark .CodeMirror-gutters {
  background:#2b3743!important;
  border-color:#526172!important;
}
body.theme-dark .CodeMirror-linenumber {color:#b9c8d8!important;}
/* Retain original image, SVG, and video colors rather than inverting artwork. */
body.theme-dark .mega-preview-content img,
body.theme-dark .mega-preview-content video,
body.theme-dark .mega-preview-content svg {filter:none;}
@media <?php echo fm_layout_media_query(); ?> {
  body.theme-dark .mega-preview-content {min-width:0;}
  body.theme-dark .mega-preview-content pre {overflow-x:auto;}
}
</style>

            <?php fm_render_readonly_preview(compact('content','ext','file','file_path','file_url','filenames','filesize_raw','is_audio','is_image','is_onlineViewer','is_text','is_video','is_zip','online_viewer','path')); ?>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

// file editor
if (isset($_GET['edit']) && !FM_READONLY) {
    $file = $_GET['edit'];
    $file = fm_clean_path($file, false);
    $file = str_replace('/', '', $file);
    if ($file == '' || !is_file($path . '/' . $file) || !fm_is_exclude_items($file, $path . '/' . $file)) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }
    $editFile = ' : <i><b>' . $file . '</b></i>';
    header('X-XSS-Protection:0');
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path

    $file_url = FM_ROOT_URL . fm_convert_win((FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file);
    $file_path = $path . '/' . $file;

    // normal editer
    $isNormalEditor = true;
    if (isset($_GET['env'])) {
        if ($_GET['env'] == "ace") {
            $isNormalEditor = false;
        }
    }

    // Save File
    if (isset($_POST['savedata'])) {
        $writedata = $_POST['savedata'];
        $fd = fopen($file_path, "w");
        @fwrite($fd, $writedata);
        fclose($fd);
        fm_set_msg(lng('File Saved Successfully'));
    }

    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    $mime_type = fm_get_mime_type($file_path);
    $filesize = filesize($file_path);
    $is_text = false;
    $content = ''; // for text

    if (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
        $is_text = true;
        $content = file_get_contents($file_path);
    }

?>
    <style id="mega-editor-toolbar-v2">
    .mega-editor-shell{margin:10px 0 12px;padding:12px;border:1px solid #d5dce5;border-radius:12px;background:#f8fafc}
    .mega-editor-top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px;min-width:0}
    .mega-editor-filename{font-size:15px;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
    .mega-editor-mode-label{font-size:12px;color:#687787;margin-top:2px}
    .mega-editor-actions{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
    .mega-editor-actions .btn{border-radius:8px!important;display:inline-flex;align-items:center;justify-content:center;gap:5px;min-height:38px;padding:7px 11px;white-space:nowrap}
    .mega-editor-actions .mega-editor-save{margin-left:auto}
    .mega-editor-tools{display:flex;align-items:center;gap:5px;flex-wrap:wrap;border-top:1px solid #dce2e9;padding-top:10px;margin-top:10px}
    .mega-editor-tools .btn{height:36px;width:38px;display:inline-flex;align-items:center;justify-content:center;border-radius:7px!important;padding:0}
    .mega-editor-tools select{max-width:145px;height:36px;border:1px solid #aeb8c4;border-radius:7px;padding:0 6px;background:transparent;color:inherit}
    .mega-editor-tool-label{font-size:12px;color:#687787;margin-right:6px}
    .mega-editor-shell .js-ace-toolbar{display:flex;align-items:center;gap:5px;flex-wrap:wrap}
    body.theme-dark .mega-editor-shell{background:#242b31;border-color:#4a5560;color:#f1f5f9}
    body.theme-dark .mega-editor-tools{border-color:#4a5560}
    body.theme-dark .mega-editor-mode-label,body.theme-dark .mega-editor-tool-label{color:#bac7d4}
    body.theme-dark .mega-editor-tools select{background:#29333d;border-color:#647383;color:#f1f5f9}
    @media(max-width:560px){.mega-editor-shell{padding:10px}.mega-editor-actions{display:grid;grid-template-columns:1fr 1fr;gap:7px}.mega-editor-actions .btn{font-size:13px;padding:7px 8px;min-width:0}.mega-editor-actions .mega-editor-save{margin:0}.mega-editor-tools{gap:4px}.mega-editor-tools .btn{height:34px;width:36px}}
    /* Ace was absolutely positioned at top:150px on mobile, covering the toolbar. */
    .mega-editor-shell{position:relative;z-index:2}
    .mega-editor-shell .mega-editor-actions,
    .mega-editor-shell .mega-editor-tools{position:relative;z-index:3;visibility:visible}
    #editor{position:relative!important;top:auto!important;right:auto!important;bottom:auto!important;left:auto!important;width:100%!important;height:calc(100dvh - 340px)!important;min-height:340px!important;margin-top:10px!important;z-index:1}
    @supports not (height:100dvh){#editor{height:calc(100vh - 340px)!important}}
    </style>
    <div class="path">
      <div class="mega-editor-shell">
        <div class="mega-editor-top">
          <div style="min-width:0">
            <div class="mega-editor-filename"><i class="fa fa-file-text-o" aria-hidden="true"></i> <?php echo htmlspecialchars($file, ENT_QUOTES, 'UTF-8'); ?></div>
            <div class="mega-editor-mode-label"><?php echo $isNormalEditor ? lng('NormalEditor') : lng('AdvancedEditor'); ?></div>
          </div>
        </div>
        <div class="mega-editor-actions">
          <a title="<?php echo lng('Back') ?>" class="btn btn-outline-secondary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;view=<?php echo urlencode($file) ?>"><i class="fa fa-arrow-left"></i> <?php echo lng('Back') ?></a>
          <a title="<?php echo lng('BackUp') ?>" class="btn btn-outline-secondary" href="javascript:void(0);" onclick="backup('<?php echo urlencode(trim(FM_PATH)) ?>','<?php echo urlencode($file) ?>')"><i class="fa fa-database"></i> <?php echo lng('BackUp') ?></a>
          <?php if ($is_text) { ?>
            <?php if ($isNormalEditor) { ?>
              <a class="btn btn-outline-secondary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>&amp;env=ace"><i class="fa fa-code"></i> <?php echo lng('AdvancedEditor') ?></a>
              <button type="button" class="btn btn-outline-secondary mega-editor-save mega-save-action" name="Save" data-url="<?php echo fm_enc($file_url) ?>" onclick="edit_save(this,'nrl')"><i class="fa fa-floppy-o mega-save-icon" aria-hidden="true"></i> <?php echo lng('Save') ?></button>
            <?php } else { ?>
              <a class="btn btn-outline-secondary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>"><i class="fa fa-font"></i> <?php echo lng('NormalEditor') ?></a>
              <button type="button" class="btn btn-outline-secondary mega-editor-save mega-save-action" name="Save" data-url="<?php echo fm_enc($file_url) ?>" onclick="edit_save(this,'ace')"><i class="fa fa-floppy-o mega-save-icon" aria-hidden="true"></i> <?php echo lng('Save') ?></button>
            <?php } ?>
          <?php } ?>
        </div>
        <div id="megaEditorResult" class="mega-inline-notice mega-inline-notice--success" role="status" aria-live="polite" hidden style="display:none"></div>
        <?php if (!$isNormalEditor) { ?>
          <style>
          @media (max-width:700px){.mega-editor-tools .js-ace-toolbar{display:flex;flex-wrap:nowrap;overflow-x:auto;max-width:100%;-webkit-overflow-scrolling:touch;gap:6px;padding-bottom:5px}.mega-editor-tools .js-ace-toolbar button{flex:0 0 auto;min-width:43px;min-height:43px}.mega-editor-tool-label{flex:0 0 auto}}
          </style>
          <div class="mega-editor-tools" role="toolbar" aria-label="<?php echo lng('Tools') ?>">
            <span class="mega-editor-tool-label"> <?php echo lng('Tools') ?></span>
            <div class="js-ace-toolbar">
              <button data-cmd="none" data-option="fullscreen" class="btn btn-outline-secondary" id="js-ace-fullscreen" title="<?php echo lng('Fullscreen') ?>" aria-label="Fullscreen"><i class="fa fa-expand"></i></button>
              <button data-cmd="find" class="btn btn-outline-secondary" id="js-ace-search" title="<?php echo lng('Search') ?>" aria-label="Search"><i class="fa fa-search"></i></button>
              <button type="button" data-cmd="none" data-option="tab" class="btn btn-outline-secondary" title="Tab" aria-label="Tab"><i class="fa fa-indent"></i></button>
              <button type="button" data-cmd="none" data-option="outdent" class="btn btn-outline-secondary" title="Shift+Tab" aria-label="Shift+Tab"><i class="fa fa-outdent"></i></button>
              <button type="button" data-cmd="replace" class="btn btn-outline-secondary" title="<?php echo lng('Replace') ?>" aria-label="<?php echo lng('Replace') ?>"><i class="fa fa-exchange"></i></button>
              <button type="button" data-cmd="gotoline" class="btn btn-outline-secondary" title="<?php echo lng('Go to Line') ?>" aria-label="<?php echo lng('Go to Line') ?>"><i class="fa fa-list-ol"></i></button>
              <button type="button" data-cmd="none" data-option="save" class="btn btn-outline-secondary mega-save-action" title="<?php echo lng('Save') ?>" aria-label="<?php echo lng('Save') ?>"><i class="fa fa-floppy-o mega-save-icon" aria-hidden="true"></i></button>
              <button data-cmd="undo" class="btn btn-outline-secondary" id="js-ace-undo" title="<?php echo lng('Undo') ?>" aria-label="Undo"><i class="fa fa-undo"></i></button>
              <button data-cmd="redo" class="btn btn-outline-secondary" id="js-ace-redo" title="<?php echo lng('Redo') ?>" aria-label="Redo"><i class="fa fa-repeat"></i></button>
              <button data-cmd="none" data-option="wrap" class="btn btn-outline-secondary" id="js-ace-wordWrap" title="<?php echo lng('Word Wrap') ?>" aria-label="Word Wrap"><i class="fa fa-text-width"></i></button>
              <select id="js-ace-mode" data-type="mode" title="<?php echo lng('Select Document Type') ?>" class="d-none d-md-block"><option>-- <?php echo lng('Select Mode') ?> --</option></select>
              <select id="js-ace-theme" data-type="theme" title="<?php echo lng('Select Theme') ?>" class="d-none d-lg-block"><option>-- <?php echo lng('Select Theme') ?> --</option></select>
              <select id="js-ace-fontSize" data-type="fontSize" title="<?php echo lng('Select Font Size') ?>" class="d-none d-lg-block"><option>-- <?php echo lng('Select Font Size') ?> --</option></select>
            </div>
          </div>
        <?php } ?>
      </div>
        <?php
        if ($is_text && $isNormalEditor) {
            echo '<textarea class="mt-2" id="normal-editor" rows="33" cols="120" style="width: 99.5%;">' . htmlspecialchars($content) . '</textarea>';
            echo '<script>document.addEventListener("keydown", function(e) {if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey)  && e.keyCode == 83) { e.preventDefault();edit_save(this,"nrl");}}, false);</script>';
        } elseif ($is_text) {
            echo '<div id="editor" contenteditable="true">' . htmlspecialchars($content) . '</div>';
        } else {
            fm_set_msg(lng('FILE EXTENSION IS NOT SUPPORTED'), 'error');
        }
        ?>
    </div>
<?php
    fm_show_footer();
    exit;
}

// chmod (not for Windows)
if (isset($_GET['chmod']) && !FM_READONLY && !FM_IS_WIN) {
    $file = $_GET['chmod'];
    $file = fm_clean_path($file);
    $file = str_replace('/', '', $file);
    if ($file == '' || (!is_file($path . '/' . $file) && !is_dir($path . '/' . $file))) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path

    $file_url = FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file;
    $file_path = $path . '/' . $file;

    $mode = fileperms($path . '/' . $file);
?>
    <div class="path">
        <div class="card mb-2 fm-form-panel" data-bs-theme="<?php echo FM_THEME; ?>">
            <h6 class="card-header">
                <?php echo lng('ChangePermissions') ?>
            </h6>
            <div class="card-body">
                <p class="card-text">
                    <?php $display_path = fm_get_display_path($file_path); ?>
                    <?php echo $display_path['label']; ?>: <?php echo $display_path['path']; ?><br>
                </p>
                <form action="" method="post">
                    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                    <input type="hidden" name="chmod" value="<?php echo fm_enc($file) ?>">

                    <table class="table compact-table" data-bs-theme="<?php echo FM_THEME; ?>">
                        <tr>
                            <td></td>
                            <td><b><?php echo lng('Owner') ?></b></td>
                            <td><b><?php echo lng('Group') ?></b></td>
                            <td><b><?php echo lng('Other') ?></b></td>
                        </tr>
                        <tr>
                            <td style="text-align: right"><b><?php echo lng('Read') ?></b></td>
                            <td><label><input type="checkbox" name="ur" value="1" <?php echo ($mode & 00400) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="gr" value="1" <?php echo ($mode & 00040) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="or" value="1" <?php echo ($mode & 00004) ? ' checked' : '' ?>></label></td>
                        </tr>
                        <tr>
                            <td style="text-align: right"><b><?php echo lng('Write') ?></b></td>
                            <td><label><input type="checkbox" name="uw" value="1" <?php echo ($mode & 00200) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="gw" value="1" <?php echo ($mode & 00020) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="ow" value="1" <?php echo ($mode & 00002) ? ' checked' : '' ?>></label></td>
                        </tr>
                        <tr>
                            <td style="text-align: right"><b><?php echo lng('Execute') ?></b></td>
                            <td><label><input type="checkbox" name="ux" value="1" <?php echo ($mode & 00100) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="gx" value="1" <?php echo ($mode & 00010) ? ' checked' : '' ?>></label></td>
                            <td><label><input type="checkbox" name="ox" value="1" <?php echo ($mode & 00001) ? ' checked' : '' ?>></label></td>
                        </tr>
                    </table>

                    <p>
                        <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                        <b><a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-secondary"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel') ?></a></b>&nbsp;
                        <button type="submit" class="btn btn-success"><i class="fa fa-check" aria-hidden="true"></i> <?php echo lng('Change') ?></button>
                    </p>
                </form>
            </div>
        </div>
    </div>
<?php
    fm_show_footer();
    exit;
}

// --- TINYFILEMANAGER MAIN ---
fm_show_header(); // HEADER
fm_show_nav_path(FM_PATH); // current path

// show alert messages
fm_show_message();

$num_files = count($files);
$num_folders = count($folders);
$all_files_size = 0;
?>
<form action="" method="post" class="<?php echo !empty($GLOBALS['fm_has_inline_conflict']) ? 'pt-0' : 'pt-3'; ?>">
    <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
    <input type="hidden" name="group" value="1">
    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
    <div class="mega-view-controls" id="mega-view-controls">
      <?php if (!FM_READONLY): ?><button type="button" class="btn btn-sm btn-outline-secondary" id="mega-select-toggle" onclick="mega_toggle_all_selection()" title="<?php echo lng('SelectAll'); ?>"><?php echo lng('SelectAll'); ?></button><?php endif; ?>
      <label for="mega-mobile-sort"><?php echo lng('Sort'); ?></label>
      <select id="mega-mobile-sort" class="form-select form-select-sm" aria-label="<?php echo lng('Sort'); ?>">
        <option value="name"><?php echo lng('Name'); ?></option>
        <option value="size"><?php echo lng('Size'); ?></option>
        <option value="date"><?php echo lng('Modified'); ?></option>
      </select>
      <button type="button" id="mega-sort-custom-trigger" aria-haspopup="listbox" aria-expanded="false"><span id="mega-sort-custom-label"><?php echo lng('Name'); ?></span><span aria-hidden="true" class="mega-sort-chevron">⌄</span></button>
      <div id="mega-sort-custom-menu" role="listbox" aria-label="<?php echo lng('Sort'); ?>" hidden></div>
      <button type="button" id="mega-sort-direction" class="btn btn-sm btn-outline-secondary" aria-label="<?php echo lng('Sort'); ?>" title="<?php echo lng('Sort'); ?>">↑</button>
    </div>
    <style id="mega-responsive-file-list-style">
      .mega-view-controls{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin:0 0 10px;padding:8px;border:1px solid var(--bs-border-color,#d5dce4);border-radius:10px}
      .mega-view-controls label{font-size:12px;margin:0}
      .mega-view-controls select{width:auto;min-width:95px;max-width:140px}
      .mega-view-controls .btn{white-space:nowrap}
      body.mega-mobile-list .fm-file-list{overflow:visible!important;width:100%;max-width:100%}
      body.mega-mobile-list #main-table,body.mega-mobile-list #main-table tbody{display:block;width:100%;border:0;background:transparent}
      body.mega-mobile-list #main-table thead{display:none}
      body.mega-mobile-list #main-table tbody tr{display:flex;align-items:center;gap:9px;position:relative;width:100%;max-width:100%;min-width:0;margin:0 0 6px;padding:10px 8px;border:1px solid var(--bs-border-color,#d5dce4);border-radius:10px;background:var(--bs-body-bg,#fff);box-sizing:border-box}
      body.mega-mobile-list #main-table tbody tr>td{border:0!important;background:transparent!important;padding:2px!important;min-width:0;vertical-align:middle}
      body.mega-mobile-list #main-table tbody tr>td.custom-checkbox-td{display:flex;align-items:center;flex:0 0 30px;min-width:30px}
      body.mega-mobile-list #main-table tbody tr>td.custom-checkbox-td .custom-control{margin:0}
      body.mega-mobile-list #main-table tbody tr>td[data-sort]{flex:1 1 0;min-width:0;overflow-wrap:anywhere}
      body.mega-mobile-list #main-table tbody tr>td[data-sort] .filename{min-width:0;overflow-wrap:anywhere}
      body.mega-mobile-list #main-table tbody tr>td[data-sort] .filename a{display:inline-block;max-width:100%;overflow-wrap:anywhere;text-decoration:none}
      body.mega-mobile-list #main-table tbody tr>td[data-order],body.mega-mobile-list #main-table tbody tr>td:not([data-sort]):not(.custom-checkbox-td):not(.inline-actions){display:none!important}
      body.mega-mobile-list #main-table tbody tr>td.inline-actions{flex:0 0 38px;display:flex;align-items:center;justify-content:flex-end;position:relative}
      body.mega-mobile-list #main-table .inline-actions>a{display:none!important}

      /* Generated row menus must never appear in the desktop details table. */
      #main-table .mega-row-more,#main-table .mega-row-actions-menu{display:none!important}
      /* In mobile mode the original actions, including download, live only in ⋮. */
      body.mega-mobile-list #main-table td.inline-actions > a,
      body.mega-mobile-list #main-table td.inline-actions > form.mega-row-download{display:none!important}
      body.mega-mobile-list #main-table td.inline-actions > .mega-row-more{display:flex!important}
      body.mega-mobile-list #main-table td.inline-actions > .mega-row-actions-menu.mega-open{display:block!important}
      body.mega-mobile-list #main-table td.inline-actions > .mega-row-actions-menu:not(.mega-open){display:none!important}
      body.mega-mobile-list #main-table .mega-row-actions-menu form.mega-row-download{display:block!important;margin:0}
      body.mega-mobile-list #main-table .mega-row-actions-menu .mega-download-action{display:flex;align-items:center;gap:10px;width:100%;padding:10px 12px;border:0;border-radius:5px;background:transparent;color:var(--bs-body-color,#222);font:inherit;text-align:left;box-shadow:none}
      body.mega-mobile-list #main-table .mega-row-actions-menu .mega-download-action:hover{background:var(--bs-secondary-bg,#e8edf2)}
      body.mega-mobile-list #main-table .mega-row-actions-menu{z-index:110;max-width:min(260px,80vw)}

      body.mega-mobile-list .mega-row-more{display:flex;align-items:center;justify-content:center;width:36px;height:38px;background:transparent;border:1px solid var(--bs-border-color,#9ba9b8);border-radius:8px;color:inherit;font-size:20px}
      body.mega-mobile-list .mega-row-actions-menu{display:none;position:absolute;right:0;top:100%;z-index:100;min-width:155px;padding:5px;border:1px solid var(--bs-border-color,#9ba9b8);border-radius:9px;background:var(--bs-body-bg,#fff);box-shadow:0 5px 18px #0003}
      body.mega-mobile-list .mega-row-actions-menu.mega-open{display:block}
      body.mega-mobile-list .mega-row-actions-menu a{display:flex;align-items:center;gap:10px;padding:10px 12px;text-decoration:none;color:var(--bs-body-color,#222);white-space:nowrap}
      body.mega-mobile-list .mega-row-actions-menu a:hover{background:var(--bs-secondary-bg,#e8edf2)}
      body.mega-mobile-list .mega-file-meta{display:block;font-size:12px;color:var(--bs-secondary-color,#687483);margin:3px 0 0 20px;line-height:1.35}
      body.mega-mobile-list #main-table tbody tr.fm-parent-folder-row{padding:7px}
      body.mega-mobile-list .mega-actions{position:sticky;bottom:0;z-index:40;background:var(--bs-body-bg,#fff);box-shadow:0 -3px 12px #0002}
      body.mega-mobile-list .mega-action-grid{grid-template-columns:repeat(4,minmax(0,1fr))}
      body.mega-mobile-list .mega-action{min-width:0}
      body.mega-mobile-list #main-table tbody tr.mega-selected-row{border-color:#3b8cce;background:var(--bs-secondary-bg,#eef5ff)}
      /* The details table already sorts via column headers and has its own
         select-all checkbox; don't duplicate those controls. */
      body:not(.mega-mobile-list) #mega-mobile-sort,
      body:not(.mega-mobile-list) label[for="mega-mobile-sort"],
      body:not(.mega-mobile-list) #mega-sort-direction,
      body:not(.mega-mobile-list) #mega-select-toggle{display:none!important}
      /* Hide the original download control in list mode, including on rows
         redrawn by DataTables; only the ⋮ menu download remains visible. */
      body.mega-mobile-list #main-table td.inline-actions > button.mega-download-direct{display:none!important}
      body.mega-mobile-list #main-table td.inline-actions > .mega-row-actions-menu .mega-menu-download{
        display:flex!important;align-items:center!important;justify-content:flex-start!important;
        gap:10px!important;width:100%!important;height:auto!important;min-height:40px!important;
        padding:10px 12px!important;margin:0!important;border:0!important;border-radius:5px!important;
        background:transparent!important;color:var(--bs-body-color,#222)!important;
        font:inherit!important;font-size:inherit!important;text-align:left!important;
        box-shadow:none!important;white-space:nowrap!important;cursor:pointer
      }
      body.mega-mobile-list #main-table .mega-row-actions-menu .mega-menu-download:hover{background:var(--bs-secondary-bg,#e8edf2)!important}
      body.mega-mobile-list #main-table .mega-row-actions-menu .mega-menu-download i{display:inline-block!important;width:16px!important;min-width:16px!important;text-align:center!important;background:transparent!important;color:inherit!important}
      body.mega-mobile-list #main-table .mega-row-actions-menu a i{display:inline-block;width:16px;min-width:16px;text-align:center}

      /* Match all existing three-dot menu entries in both themes. */
      body.mega-mobile-list #main-table .mega-row-actions-menu .mega-row-archive-action{
        display:flex!important;align-items:center!important;justify-content:flex-start!important;
        gap:10px!important;width:100%!important;min-height:44px!important;
        padding:10px 12px!important;margin:0!important;border:0!important;border-radius:5px!important;
        background:transparent!important;color:var(--bs-body-color,#222)!important;
        font:inherit!important;text-align:left!important;box-shadow:none!important;cursor:pointer
      }
      body.mega-mobile-list #main-table .mega-row-actions-menu .mega-row-archive-action:hover{
        background:var(--bs-secondary-bg,#e8edf2)!important
      }
      body.mega-mobile-list #main-table .mega-row-actions-menu .mega-row-archive-action i{
        width:16px!important;min-width:16px!important;text-align:center!important;
        color:inherit!important;background:transparent!important
      }
      /* Automatic mobile list: compact touch-friendly rows and no page overflow. */
      @media<?php echo fm_layout_media_query(); ?>{
        html,body{max-width:100%;overflow-x:hidden}
        body.mega-mobile-list .mega-view-controls{padding:9px 10px;margin:0 0 12px;gap:8px;align-items:center;border-radius:12px}
        body.mega-mobile-list .mega-view-controls label[for="mega-mobile-sort"]{font-size:13px;font-weight:600}
        body.mega-mobile-list #mega-mobile-sort{flex:1 1 125px;max-width:none;min-width:90px;min-height:40px}
        body.mega-mobile-list #mega-sort-direction{width:42px;min-height:40px;flex:0 0 42px}
        body.mega-mobile-list #mega-select-toggle{min-height:40px;flex:0 0 auto;margin-left:auto}
        body.mega-mobile-list #main-table tbody tr{padding:10px 10px;min-height:66px;gap:10px;margin-bottom:7px;border-radius:12px;overflow:visible}
        body.mega-mobile-list #main-table tbody tr>td.custom-checkbox-td{flex:0 0 32px;min-width:32px}
        body.mega-mobile-list #main-table tbody tr>td[data-sort]{flex:1 1 auto;min-width:0;overflow:hidden}
        body.mega-mobile-list #main-table tbody tr>td[data-sort] .filename{display:block;max-width:100%;min-width:0;overflow:hidden}
        body.mega-mobile-list #main-table tbody tr>td[data-sort] .filename a{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle}
        body.mega-mobile-list .mega-file-meta{font-size:12px;line-height:1.4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:4px}
        body.mega-mobile-list #main-table tbody tr>td.inline-actions{flex:0 0 42px;min-width:42px}
        body.mega-mobile-list .mega-row-more{min-width:42px;width:42px;min-height:44px;height:44px;border-radius:10px;font-size:22px}
        body.mega-mobile-list .mega-row-actions-menu{right:0;min-width:175px;max-width:min(240px,calc(100vw - 32px));padding:6px;z-index:200}
        body.mega-mobile-list .mega-row-actions-menu a,body.mega-mobile-list .mega-row-actions-menu button{min-height:44px!important}
        body.mega-mobile-list .mega-actions{position:fixed;bottom:0;left:0;right:0;z-index:90;margin:0;padding:10px 12px max(12px,env(safe-area-inset-bottom));border-radius:16px 16px 0 0;box-shadow:0 -5px 22px #0002;max-height:38vh;overflow-y:auto}
        body.mega-mobile-list .mega-actions:not(.mega-has-selection){display:none!important}
        body.mega-mobile-list:has(.mega-actions.mega-has-selection) .fm-file-list{padding-bottom:145px}
        body.mega-mobile-list .mega-actions-top{margin-bottom:8px}
        body.mega-mobile-list .mega-action{min-height:57px;padding:7px 3px}
        body.mega-mobile-list .mega-action-grid.operations{gap:6px}
      }
      @media(max-width:450px){.mega-view-controls{gap:5px}.mega-view-controls label{font-size:11px}.mega-view-controls select{min-width:82px;max-width:110px}.mega-view-controls .btn{font-size:12px}}
    </style>
    <div class="table-responsive fm-file-list">
        <table class="table table-bordered table-hover table-sm" id="main-table" data-bs-theme="<?php echo FM_THEME; ?>">
            <thead class="thead-white">
                <tr>
                    <?php if (!FM_READONLY): ?>
                        <th style="width:3%" class="custom-checkbox-header">
                            <div class="custom-control custom-checkbox">
                                <input type="checkbox" class="custom-control-input" id="js-select-all-items" onclick="checkbox_toggle()">
                                <label class="custom-control-label" for="js-select-all-items"></label>
                            </div>
                        </th><?php endif; ?>
                    <th><?php echo lng('Name') ?></th>
                    <th><?php echo lng('Size') ?></th>
                    <th><?php echo lng('Modified') ?></th>
                    <?php if (!FM_IS_WIN && !$hide_Cols): ?>
                        <th><?php echo lng('Perms') ?></th>
                        <th><?php echo lng('Owner') ?></th><?php endif; ?>
                    <th><?php echo lng('Actions') ?></th>
                </tr>
            </thead>
            <?php
            // link to parent folder
            if ($parent !== false) {
            ?>
                <tr class="fm-parent-folder-row"><?php if (!FM_READONLY): ?>
                        <td class="nosort"></td><?php endif; ?>
                    <td class="border-0" data-sort><a href="?p=<?php echo urlencode($parent) ?>"><i class="fa fa-chevron-circle-left go-back"></i> ..</a></td>
                    <td class="border-0" data-order></td>
                    <td class="border-0" data-order></td>
                    <td class="border-0"></td>
                    <?php if (!FM_IS_WIN && !$hide_Cols) { ?>
                        <td class="border-0"></td>
                        <td class="border-0"></td>
                    <?php } ?>
                </tr>
            <?php
            }
            $ii = 3399;
            foreach ($folders as $f) {
                $is_link = is_link($path . '/' . $f);
                $img = $is_link ? 'icon-link_folder' : 'fa fa-folder-o';
                $modif_raw = filemtime($path . '/' . $f);
                $modif = date(FM_DATETIME_FORMAT, $modif_raw);
                $date_sorting = strtotime(date("F d Y H:i:s.", $modif_raw));
                $filesize_raw = "";
                $filesize = lng('Folder');
                $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
                $owner = array('name' => '?'); 
                $group = array('name' => '?');
                if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
                    try {
                        $owner_id = fileowner($path . '/' . $f);
                        if ($owner_id != 0) {
                            $owner_info = posix_getpwuid($owner_id);
                            if ($owner_info) {
                                $owner =  $owner_info;
                            }
                        }
                        $group_id = filegroup($path . '/' . $f);
                        $group_info = posix_getgrgid($group_id);
                        if ($group_info) {
                            $group =  $group_info;
                        }
                    } catch (Exception $e) {
                        error_log("exception:" . $e->getMessage());
                    }
                }
            ?>
                <tr class="fm-folder-row">
                    <?php if (!FM_READONLY): ?>
                        <td class="custom-checkbox-td">
                            <div class="custom-control custom-checkbox">
                                <input type="checkbox" class="custom-control-input" id="<?php echo $ii ?>" name="file[]" value="<?php echo fm_enc($f) ?>">
                                <label class="custom-control-label" for="<?php echo $ii ?>"></label>
                            </div>
                        </td>
                    <?php endif; ?>
                    <td data-sort=<?php echo fm_convert_win(fm_enc($f)) ?>>
                        <div class="filename">
                            <a href="?p=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="<?php echo $img ?>"></i> <?php echo fm_convert_win(fm_enc($f)) ?></a>
                            <?php echo ($is_link ? ' &rarr; <i>' . readlink($path . '/' . $f) . '</i>' : '') ?>
                        </div>
                    </td>
                    <td data-order="a-<?php echo str_pad($filesize_raw, 18, "0", STR_PAD_LEFT); ?>">
                        <?php echo $filesize; ?>
                    </td>
                    <td data-order="a-<?php echo $date_sorting; ?>"><?php echo $modif ?></td>
                    <?php if (!FM_IS_WIN && !$hide_Cols): ?>
                        <td>
                            <?php if (!FM_READONLY): ?><a title="Change Permissions" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?>
                        </td>
                        <td>
                            <?php echo $owner['name'] . ':' . $group['name'] ?>
                        </td>
                    <?php endif; ?>
                    <td class="inline-actions"><?php if (!FM_READONLY): ?>
                            <a title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="confirmDialog(event, '1028','<?php echo lng('Delete') . ' ' . lng('Folder'); ?>','<?php echo urlencode($f) ?>', this.href);"> <i class="fa fa-trash-o" aria-hidden="true"></i></a>
                            <a title="<?php echo lng('Rename') ?>" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f)) ?>');return false;"><i class="fa fa-pencil-square-o" aria-hidden="true"></i></a>
                            <a title="<?php echo lng('CopyTo') ?>..." href="?p=&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="fa fa-files-o" aria-hidden="true"></i></a>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php
                flush();
                $ii++;
            }
            $ik = 8002;
            foreach ($files as $f) {
                $is_link = is_link($path . '/' . $f);
                $img = $is_link ? 'fa fa-file-text-o' : fm_get_file_icon_class($path . '/' . $f);
                $modif_raw = filemtime($path . '/' . $f);
                $modif = date(FM_DATETIME_FORMAT, $modif_raw);
                $date_sorting = strtotime(date("F d Y H:i:s.", $modif_raw));
                $filesize_raw = fm_get_size($path . '/' . $f);
                $filesize = fm_get_filesize($filesize_raw);
                $filelink = '?p=' . urlencode(FM_PATH) . '&amp;view=' . urlencode($f);
                $all_files_size += $filesize_raw;
                $perms = substr(decoct(fileperms($path . '/' . $f)), -4);
                $owner = array('name' => '?'); 
                $group = array('name' => '?');
                if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid')) {
                    try {
                        $owner_id = fileowner($path . '/' . $f);
                        if ($owner_id != 0) {
                            $owner_info = posix_getpwuid($owner_id);
                            if ($owner_info) {
                                $owner =  $owner_info;
                            }
                        }
                        $group_id = filegroup($path . '/' . $f);
                        $group_info = posix_getgrgid($group_id);
                        if ($group_info) {
                            $group =  $group_info;
                        }
                    } catch (Exception $e) {
                        error_log("exception:" . $e->getMessage());
                    }
                }
            ?>
                <tr>
                    <?php if (!FM_READONLY): ?>
                        <td class="custom-checkbox-td">
                            <div class="custom-control custom-checkbox">
                                <input type="checkbox" class="custom-control-input" id="<?php echo $ik ?>" name="file[]" value="<?php echo fm_enc($f) ?>">
                                <label class="custom-control-label" for="<?php echo $ik ?>"></label>
                            </div>
                        </td><?php endif; ?>
                    <td data-sort=<?php echo fm_enc($f) ?>>
                        <div class="filename">
                            <?php
                            if (in_array(strtolower(pathinfo($f, PATHINFO_EXTENSION)), array('gif', 'jpg', 'jpeg', 'png', 'bmp', 'ico', 'svg', 'webp', 'avif'))): ?>
                                <?php $imagePreview = fm_enc(FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $f); ?>
                                <a href="<?php echo $filelink ?>" data-preview-image="<?php echo $imagePreview ?>" title="<?php echo fm_enc($f) ?>">
                                <?php else: ?>
                                    <a href="<?php echo $filelink ?>" title="<?php echo $f ?>">
                                    <?php endif; ?>
                                    <i class="<?php echo $img ?>"></i> <?php echo fm_convert_win(fm_enc($f)) ?>
                                    </a>
                                    <?php echo ($is_link ? ' &rarr; <i>' . readlink($path . '/' . $f) . '</i>' : '') ?>
                        </div>
                    </td>
                    <td data-order="b-<?php echo str_pad($filesize_raw, 18, "0", STR_PAD_LEFT); ?>"><span title="<?php printf('%s bytes', $filesize_raw) ?>">
                            <?php echo $filesize; ?>
                        </span></td>
                    <td data-order="b-<?php echo $date_sorting; ?>"><?php echo $modif ?></td>
                    <?php if (!FM_IS_WIN && !$hide_Cols): ?>
                        <td><?php if (!FM_READONLY): ?><a title="<?php echo 'Change Permissions' ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a><?php else: ?><?php echo $perms ?><?php endif; ?>
                        </td>
                        <td><?php echo fm_enc($owner['name'] . ':' . $group['name']) ?></td>
                    <?php endif; ?>
                    <td class="inline-actions">
                        <?php if (!FM_READONLY): ?>
                            <a title="<?php echo lng('Delete') ?>" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="confirmDialog(event, 1209, '<?php echo lng('Delete') . ' ' . lng('File'); ?>','<?php echo urlencode($f); ?>', this.href);"> <i class="fa fa-trash-o"></i></a>
                            <a title="<?php echo lng('Rename') ?>" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>', '<?php echo fm_enc(addslashes($f)) ?>');return false;"><i class="fa fa-pencil-square-o"></i></a>
                            <a title="<?php echo lng('CopyTo') ?>..."
                                href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH . '/' . $f, '/')) ?>"><i class="fa fa-files-o"></i></a>
                        <?php endif; ?>
                        <?php if (FM_STORAGE_TYPE === 'mega'): ?><a title="<?php echo lng('Create MEGA Link'); ?>" aria-label="<?php echo lng('Create MEGA Link'); ?>" href="?mega_link=1&amp;p=<?php echo rawurlencode(FM_PATH); ?>&amp;file=<?php echo rawurlencode($f); ?>"><i class="fa fa-link" aria-hidden="true"></i></a><?php endif; ?>
                        <button type="button" data-mega-download-url="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($f) ?>" title="<?php echo lng('Download') ?>" aria-label="<?php echo lng('Download') ?>" class="mega-download-action mega-download-direct"><i class="fa fa-download"></i></button>
                    </td>
                </tr>
            <?php
                flush();
                $ik++;
            }

            if (empty($folders) && empty($files)) { ?>
                <tfoot>
                    <tr><?php if (!FM_READONLY): ?>
                            <td></td><?php endif; ?>
                        <td colspan="<?php echo (!FM_IS_WIN && !$hide_Cols) ? '6' : '4' ?>"><em><?php echo lng('Folder is empty') ?></em></td>
                    </tr>
                </tfoot>
            <?php
            } else { ?>
                <tfoot>
                    <tr>
                        <td class="gray fs-7" colspan="<?php echo (!FM_IS_WIN && !$hide_Cols) ? (FM_READONLY ? '6' : '7') : (FM_READONLY ? '4' : '5') ?>">
                            <?php fm_file_list_summary($all_files_size,$num_files,$num_folders); ?>
                        </td>
                    </tr>
                </tfoot>
            <?php } ?>
        </table>
    </div>

    <!-- v63: Remove the empty grey strip below the mobile statistics row. -->
    <style id="mega-mobile-v63-no-bottom-gap">
    @media screen and <?php echo fm_layout_media_query(); ?> {
      html body.mega-mobile-list #main-table {
        margin-bottom:0!important;
        border-bottom:0!important;
      }
      html body.mega-mobile-list .fm-file-list {
        margin-bottom:0!important;
        padding-bottom:0!important;
        border-bottom:0!important;
      }
      html body.mega-mobile-list #main-table tfoot {
        margin-bottom:0!important;
        padding-bottom:0!important;
        border-bottom:0!important;
      }
      html body.mega-mobile-list #main-table tfoot tr,
      html body.mega-mobile-list #main-table tfoot td {
        margin-bottom:0!important;
        border-bottom:0!important;
      }
      html body.mega-mobile-list #main-table tfoot tr::before {
        bottom:0!important;
      }
    }
    </style>

    <!-- v62: remove Bootstrap table-cell inset borders and footer separator rules. -->
    <style id="mega-mobile-v62-footer-no-lines">
    @media screen and <?php echo fm_layout_media_query(); ?> {
      html body.mega-mobile-list #main-table tfoot,
      html body.mega-mobile-list #main-table tfoot tr,
      html body.mega-mobile-list #main-table tfoot td {
        --bs-table-border-color:transparent!important;
        --bs-table-bg:#fff!important;
        border:0!important;
        border-top:0!important;
        border-bottom:0!important;
        box-shadow:none!important;
        outline:0!important;
        background-color:#fff!important;
        background-image:none!important;
      }
      html body.mega-mobile-list #main-table tfoot td {
        box-shadow:none!important;
        padding-top:4px!important;
        padding-bottom:4px!important;
      }
      html body.mega-mobile-list #main-table tbody tr:last-child {
        border-bottom:0!important;
        box-shadow:none!important;
      }
      html body.mega-mobile-list #main-table tfoot tr::before,
      html body.mega-mobile-list #main-table tfoot tr::after,
      html body.mega-mobile-list #main-table tfoot td::before,
      html body.mega-mobile-list #main-table tfoot td::after {
        border:0!important;
        box-shadow:none!important;
        outline:0!important;
      }
    }
    </style>

    <!-- v58: Full-width white statistics footer, including outer mobile gutters. -->
    <style id="mega-mobile-v58-white-statistics-bar">
    @media screen and <?php echo fm_layout_media_query(); ?> {
      html body.mega-mobile-list #main-table tfoot,
      html body.mega-mobile-list #main-table tfoot tr,
      html body.mega-mobile-list #main-table tfoot td {
        background-color:#ffffff!important;
      }
      html body.mega-mobile-list #main-table tfoot tr {
        position:relative!important;
        isolation:isolate;
      }
      html body.mega-mobile-list #main-table tfoot tr::before {
        content:"";
        position:absolute;
        top:0;
        bottom:-16px;
        left:-8px;
        right:-8px;
        background:#ffffff;
        z-index:-1;
        pointer-events:none;
      }
      html body.mega-mobile-list #main-table tfoot td {
        border:0!important;
        color:#202124!important;
        padding-top:12px!important;
        padding-bottom:18px!important;
      }
      html body.mega-mobile-list #main-table tfoot .badge {
        color:#202124!important;
        background:#ffffff!important;
      }
    }
    </style>

    <style id="mega-mobile-statistics-v60">
    @media screen and <?php echo fm_layout_media_query(); ?>{
      html body.mega-mobile-list .fm-file-list{overflow:visible!important;}
      html body.mega-mobile-list #main-table tfoot{
        display:table-footer-group!important;background:#fff!important;
      }
      html body.mega-mobile-list #main-table tfoot tr{
        position:relative!important;isolation:isolate!important;background:#fff!important;
      }
      /* Paint beyond the intrinsic table width to the viewport's right edge. */
      html body.mega-mobile-list #main-table tfoot tr::before{
        content:""!important;position:absolute!important;left:0!important;right:auto!important;
        top:0!important;bottom:0!important;width:100vw!important;
        transform:none!important;background:#fff!important;z-index:-1!important;
        pointer-events:none!important;
      }
      html body.mega-mobile-list #main-table tfoot td{
        background:transparent!important;border:0!important;
        padding:6px 10px!important;line-height:1.5!important;
        height:auto!important;color:#202124!important;
      }
      html body.mega-mobile-list #main-table tfoot .badge{
        background:#fff!important;color:#202124!important;
      }
    }
    </style>
    <!-- v65: statistics footer follows the active light/dark theme. -->
    <style id="mega-mobile-v65-theme-statistics">
    @media screen and <?php echo fm_layout_media_query(); ?> {
      html body.mega-mobile-list.theme-dark #main-table tfoot,
      html body.mega-mobile-list.theme-dark #main-table tfoot tr,
      html[data-bs-theme="dark"] body.mega-mobile-list #main-table tfoot,
      html[data-bs-theme="dark"] body.mega-mobile-list #main-table tfoot tr {
        background:#20282d!important;
      }
      html body.mega-mobile-list.theme-dark #main-table tfoot tr::before,
      html[data-bs-theme="dark"] body.mega-mobile-list #main-table tfoot tr::before {
        background:#20282d!important;
      }
      html body.mega-mobile-list.theme-dark #main-table tfoot td,
      html[data-bs-theme="dark"] body.mega-mobile-list #main-table tfoot td {
        background:transparent!important;color:#e8edf4!important;
        border:0!important;
      }
      html body.mega-mobile-list.theme-dark #main-table tfoot .badge,
      html[data-bs-theme="dark"] body.mega-mobile-list #main-table tfoot .badge {
        background:transparent!important;color:#f1f5f9!important;
      }
    }
    </style>
    <style>
      .mega-actions{margin:16px 0 22px;padding:14px;background:#fff;border:1px solid #e5eaf0;border-radius:14px;box-shadow:0 2px 10px rgba(20,38,60,.05)}
      .mega-actions-top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
      .mega-selection-count{font-weight:600;color:#334155;font-size:14px}
      .mega-clear{border:1px solid #d8e1ea;border-radius:9px;background:#fff;color:#475569;padding:7px 13px;min-height:38px}
      .mega-action-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}
      .mega-action-grid.operations{grid-template-columns:repeat(4,minmax(0,1fr))}
      .mega-action{border:1px solid #e2e8f0;background:#f8fafc;border-radius:11px;color:#334155;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;min-height:68px;padding:9px 3px;text-align:center;text-decoration:none!important;font-size:13px;line-height:1.15;cursor:pointer}
      .mega-action i{font-size:19px;color:#4778ad}
      .mega-action.danger i,.mega-action.danger{color:#c53d4b}
      .mega-action:hover:not(.disabled){background:#edf4fc;color:#234b7b}
      .mega-action.disabled{opacity:.4;pointer-events:none;cursor:not-allowed}
      .mega-action-separator{height:1px;background:#e9edf2;margin:13px 0}
      @media(max-width:380px){.mega-actions{padding:10px}.mega-action-grid{gap:6px}.mega-action{font-size:11px;min-height:64px}}
    </style>
    <?php if (!FM_READONLY): ?>
    <div class="mega-actions" aria-label="<?php echo lng('File selection actions') ?>">
      <div class="mega-actions-top">
        <span class="mega-selection-count" id="mega-selected-count" aria-live="polite">0 selected</span>
      </div>
      <div class="mega-action-grid operations">
        <input type="submit" class="hidden" name="delete" id="a-delete" value="Delete">
        <button type="button" class="mega-action danger mega-needs-selection" onclick="megaConfirmBulk('delete')"><i class="fa fa-trash-o"></i><span><?php echo lng('Delete') ?></span></button>
        <input type="submit" class="hidden" name="zip" id="a-zip" value="zip">
        <button type="button" class="mega-action mega-needs-selection" onclick="megaConfirmBulk('zip')"><i class="fa fa-file-archive-o"></i><span><?php echo lng('Zip') ?></span></button>
        <input type="submit" class="hidden" name="tar" id="a-tar" value="tar">
        <button type="button" class="mega-action mega-needs-selection" onclick="megaConfirmBulk('tar')"><i class="fa fa-file-archive-o"></i><span><?php echo lng('Tar') ?></span></button>
        <input type="submit" class="hidden" name="copy" id="a-copy" value="Copy">
        <button type="button" class="mega-action mega-needs-selection" onclick="document.getElementById('a-copy').click()"><i class="fa fa-files-o"></i><span><?php echo lng('Copy') ?></span></button>
      </div>
    </div>
    <?php endif; ?>
</form>
<script id="mega-responsive-file-list-script">
(function(){
  var table=document.getElementById('main-table');
  if(!table)return;
  window.megaCloseRowMenus = function() {
    document.querySelectorAll('.mega-row-actions-menu.mega-open').forEach(function(menu) {
      menu.classList.remove('mega-open');
      var cell = menu.closest('td.inline-actions');
      var toggle = cell && cell.querySelector('.mega-row-more');
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
    });
  };
  function positionRowMenu(menu, button) {
    if(!menu.querySelector('.mega-menu-drag-handle')){
      var grip=document.createElement('div');
      grip.className='mega-menu-drag-handle';grip.setAttribute('aria-hidden','true');
      menu.insertBefore(grip,menu.firstChild);
    }
    var vv = window.visualViewport;
    var topEdge = (vv ? vv.offsetTop : 0) || 0;
    var leftEdge = (vv ? vv.offsetLeft : 0) || 0;
    var height = vv ? vv.height : window.innerHeight;
    var width = vv ? vv.width : window.innerWidth;
    var bottomEdge = topEdge + height - 12;
    topEdge += 12;
    document.querySelectorAll('.mega-mobile-header,.main-nav').forEach(function(header) {
      var r = header.getBoundingClientRect();
      if (r.height > 0 && r.top < topEdge && r.bottom > topEdge) topEdge = Math.min(bottomEdge - 1, r.bottom + 8);
    });
    menu.style.position = 'fixed';
    menu.style.top = topEdge + 'px'; menu.style.bottom = 'auto';
    menu.style.left = (leftEdge + 12) + 'px'; menu.style.right = 'auto';
    menu.style.maxWidth = Math.max(1, width - 24) + 'px';
    menu.style.maxHeight = Math.max(1, bottomEdge - topEdge) + 'px';
    menu.style.overflowY = 'auto'; menu.style.zIndex = '1040';
    menu.scrollTop = 0;
    var anchor = button.getBoundingClientRect(), bounds = menu.getBoundingClientRect();
    var top = anchor.bottom + 4;
    if (top + bounds.height > bottomEdge && anchor.top - 4 - bounds.height >= topEdge) top = anchor.top - 4 - bounds.height;
    top = Math.max(topEdge, Math.min(top, bottomEdge - bounds.height));
    var left = Math.max(leftEdge + 12, Math.min(anchor.right - bounds.width, leftEdge + width - 12 - bounds.width));
    menu.style.top = Math.round(top) + 'px'; menu.style.left = Math.round(left) + 'px';
  }
  // Capture runs before cloned inline onclick handlers (delete/rename/etc.).
  document.addEventListener('click', function(e) {
    if (e.target.closest('.mega-row-actions-menu a,.mega-row-actions-menu button')) window.megaCloseRowMenus();
  }, true);
  document.addEventListener('show.bs.modal', window.megaCloseRowMenus);
  window.addEventListener('scroll', window.megaCloseRowMenus);
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', window.megaCloseRowMenus);
    window.visualViewport.addEventListener('scroll', window.megaCloseRowMenus);
  }
  var sort=document.getElementById('mega-mobile-sort');
  var direction=document.getElementById('mega-sort-direction');
  var asc=true;
  var media=window.matchMedia('<?php echo fm_layout_media_query(); ?>');
  function applyView(){
    var mobile=media.matches;
    document.body.classList.toggle('mega-mobile-list',mobile);
    document.body.classList.toggle('mega-desktop-details',!mobile);
    document.querySelectorAll('.mega-row-actions-menu.mega-open').forEach(function(menu){menu.classList.remove('mega-open');});
  }
  if(media.addEventListener)media.addEventListener('change',applyView);
  else if(media.addListener)media.addListener(applyView);
  window.addEventListener('resize',applyView);
  function text(cell){return cell?cell.textContent.trim():'';}
  function setupRow(row){
    if(row.dataset.megaPrepared)return;
    row.dataset.megaPrepared='1';
    var cells=row.children;
    var nameCell=row.querySelector('td[data-sort]');
    if(!nameCell)return;
    var sizeCell=row.querySelector('td[data-order]');
    var dateCell=sizeCell&&sizeCell.nextElementSibling;
    var meta=document.createElement('span');meta.className='mega-file-meta';
    meta.textContent=[text(sizeCell),text(dateCell)].filter(Boolean).join(' · ');
    nameCell.appendChild(meta);
    var actionCell=row.querySelector('td.inline-actions');
    if(actionCell){
      var links=Array.prototype.slice.call(actionCell.querySelectorAll('a'));
      if(links.length){
        var button=document.createElement('button');button.type='button';button.className='mega-row-more';button.textContent='⋮';
        button.setAttribute('aria-label',<?php echo json_encode(lng('Actions')); ?>);
        button.setAttribute('aria-expanded','false');
        var menu=document.createElement('div');menu.className='mega-row-actions-menu';
        links.forEach(function(link){var clone=link.cloneNode(true);clone.removeAttribute('id');var label=link.getAttribute('title')||link.textContent.trim();clone.appendChild(document.createTextNode(' '+label));menu.appendChild(clone);});
        // Use the same download action in both layouts. A nested form inside
        // the bulk-action form is invalid HTML and may be moved by the browser.
        var downloadButton=actionCell.querySelector('button.mega-download-direct');
        if(downloadButton){
          var downloadClone=downloadButton.cloneNode(true);
          downloadClone.classList.add('mega-menu-download');
          downloadClone.removeAttribute('id');
          downloadClone.appendChild(document.createTextNode(' '+(downloadButton.getAttribute('title')||<?php echo json_encode(lng('Download')); ?>)));
          menu.appendChild(downloadClone);
        }
        // Single-item ZIP/TAR actions reuse the existing authenticated bulk
        // archive endpoint without altering any checked files or folders.
        var rowFile=row.querySelector('input[name="file[]"]');
        if(rowFile){
          ['zip','tar'].forEach(function(kind){
            var archiveAction=document.createElement('button');
            archiveAction.type='button';
            archiveAction.className='mega-row-archive-action';
            archiveAction.setAttribute('data-mega-archive-kind',kind);
            archiveAction.innerHTML='<i class="fa fa-file-archive-o" aria-hidden="true"></i> ';
            archiveAction.appendChild(document.createTextNode(kind==='zip'?<?php echo json_encode(lng('Zip')); ?>:<?php echo json_encode(lng('Tar')); ?>));
            menu.appendChild(archiveAction);
          });
        }
        button.addEventListener('click',function(e){
          e.preventDefault();e.stopPropagation();
          var wasOpen = menu.classList.contains('mega-open');
          window.megaCloseRowMenus();
          menu.classList.toggle('mega-open', !wasOpen);
          if(menu.classList.contains('mega-open')){
            positionRowMenu(menu, button);
          }
          button.setAttribute('aria-expanded',menu.classList.contains('mega-open')?'true':'false');
        });
        actionCell.appendChild(button);actionCell.appendChild(menu);
      }
    }
    var checkbox=row.querySelector('input[name="file[]"]');
    if(checkbox){checkbox.addEventListener('change',function(){row.classList.toggle('mega-selected-row',checkbox.checked);});row.classList.toggle('mega-selected-row',checkbox.checked);}
  }
  function prepare(){Array.prototype.forEach.call(table.querySelectorAll('tbody tr'),setupRow);}
  // A row archive submits exactly that row, never the current multi-selection.
  // The existing server-side ZIP/TAR handler and confirmation wording are reused.
  document.addEventListener('click',function(e){
    var trigger=e.target.closest('button.mega-row-archive-action');
    if(!trigger)return;
    e.preventDefault();e.stopPropagation();
    var kind=trigger.getAttribute('data-mega-archive-kind');
    if(kind!=='zip'&&kind!=='tar')return;
    var row=trigger.closest('tr');
    var file=row&&row.querySelector('input[name="file[]"]');
    var bulk=file&&file.form;
    if(!file||!bulk)return;
    if (window.megaCloseRowMenus) window.megaCloseRowMenus();
    if (typeof window.megaConfirmBulk !== 'function') return;
    window.megaConfirmBulk(kind, function() {
      var request=document.createElement('form');
      request.method='post';request.action=bulk.action||window.location.href;
      request.style.display='none';
      function add(name,value){var el=document.createElement('input');el.type='hidden';el.name=name;el.value=value;request.appendChild(el);}
      add('group','1'); add('file[]',file.value); add(kind,kind);
      var token=bulk.querySelector('input[name="token"]');if(token)add('token',token.value);
      var path=bulk.querySelector('input[name="p"]');if(path)add('p',path.value);
      document.body.appendChild(request);
      request.submit();
    }, file.value);
  });
  // Download POST must not be nested in the bulk form. Create a temporary
  // standalone form at click time to preserve the existing download endpoint.
  document.addEventListener('click',function(e){
    var trigger=e.target.closest('button.mega-download-direct');
    if(!trigger)return;
    e.preventDefault();
    e.stopPropagation();
    var url=trigger.getAttribute('data-mega-download-url');
    if(!url)return;
    var form=document.createElement('form');
    form.method='post';form.action=url;form.style.display='none';
    form.setAttribute('data-no-processing','download');
    var token=document.querySelector('#main-table')?.closest('form')?.querySelector('input[name="token"]');
    if(!token)token=document.querySelector('input[name="token"]');
    if(token){var hidden=document.createElement('input');hidden.type='hidden';hidden.name='token';hidden.value=token.value;form.appendChild(hidden);}
    document.body.appendChild(form);
    form.submit();
    setTimeout(function(){if(form.parentNode)form.parentNode.removeChild(form);},1000);
  });
  document.addEventListener('click',function(e){if(!e.target.closest('.mega-row-more,.mega-row-actions-menu'))document.querySelectorAll('.mega-row-actions-menu.mega-open').forEach(function(m){m.classList.remove('mega-open');});});
  function applySort(){
    // Reuse the existing DataTables sorting so sorting and selection stay synchronized.
    if(!window.jQuery||!jQuery.fn.DataTable||!jQuery.fn.DataTable.isDataTable(table))return;
    var dt=jQuery(table).DataTable();
    var header=table.querySelectorAll('thead th');
    var idx=-1;
    Array.prototype.forEach.call(header,function(th,i){var v=th.textContent.trim().toLowerCase();var wanted=sort.value==='name'?<?php echo json_encode(mb_strtolower(lng('Name'),'UTF-8')); ?>:sort.value==='size'?<?php echo json_encode(mb_strtolower(lng('Size'),'UTF-8')); ?>:<?php echo json_encode(mb_strtolower(lng('Modified'),'UTF-8')); ?>;if(v===wanted)idx=i;});
    if(idx>=0){dt.order([idx,asc?'asc':'desc']).draw();prepare();}
  }
  sort.addEventListener('change',applySort);
  direction.addEventListener('click',function(){asc=!asc;direction.textContent=asc?'↑':'↓';applySort();});
  document.addEventListener('change',function(e){if(e.target&&e.target.name==='file[]')setTimeout(prepare,0);});
  // DataTables redraws the existing row elements after sorting/filtering.
  if(window.jQuery)jQuery(table).on('draw.dt',prepare);
  prepare();applyView();
  if(typeof mega_update_selection==='function')mega_update_selection();
  if(window.jQuery)jQuery(function(){prepare();applyView();});
})();
</script>
<?php if (!FM_READONLY): ?>
<!-- Use the same Bootstrap confirmation layout as individual file operations. -->
<div class="modal modal-alert" id="megaBulkConfirm" tabindex="-1" role="dialog" data-bs-backdrop="static" data-bs-keyboard="false" data-bs-theme="<?php echo FM_THEME; ?>">
  <div class="modal-dialog" role="document">
    <div class="modal-content rounded-3 shadow">
      <div class="modal-body p-4 text-center">
        <h5 class="mb-2" id="megaBulkConfirmTitle"></h5>
        <p class="mb-1" id="megaBulkConfirmDetail"></p>
      </div>
      <div class="modal-footer flex-nowrap p-0">
        <button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></button>
        <button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0" id="megaBulkConfirmOK"><i class="fa fa-check" aria-hidden="true"></i> <strong><?php echo lng('Okay'); ?></strong></button>
      </div>
    </div>
  </div>
</div>
<script>
(function () {
  var pending = null;
  window.megaConfirmBulk = function (action, onConfirm, detail) {
    var submit = document.getElementById('a-' + action);
    if (typeof onConfirm !== 'function' && (!submit || !submit.form)) return;
    if (window.megaCloseRowMenus) window.megaCloseRowMenus();
    pending = { action: action, submit: submit, callback: onConfirm };
    var messages = <?php echo json_encode(array(
      'delete'=>html_entity_decode(lng('Are you sure to delete selected files and folders?'), ENT_QUOTES, 'UTF-8'),
      'zip'=>html_entity_decode(lng('Are you sure to create zip archive?'), ENT_QUOTES, 'UTF-8'),
      'tar'=>html_entity_decode(lng('Are you sure to create tar archive?'), ENT_QUOTES, 'UTF-8')
    ), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE); ?>;
    document.getElementById('megaBulkConfirmTitle').textContent = messages[action] || <?php echo json_encode(html_entity_decode(lng('Are you sure?'), ENT_QUOTES, 'UTF-8'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE); ?>;
    var count = document.querySelectorAll('input[type="checkbox"]:checked');
    document.getElementById('megaBulkConfirmDetail').textContent = detail || '';
    document.getElementById('megaBulkConfirmDetail').title = detail || '';
    var modal = document.getElementById('megaBulkConfirm');
    if (window.bootstrap && bootstrap.Modal) bootstrap.Modal.getOrCreateInstance(modal).show();
    else if (window.jQuery) jQuery(modal).modal('show');
  };
  document.getElementById('megaBulkConfirm').addEventListener('hidden.bs.modal', function() { pending = null; });
  document.getElementById('megaBulkConfirmOK').addEventListener('click', function () {
    if (!pending) return;
    var operation = pending;
    pending = null;
    if (window.megaRememberDialog) window.megaRememberDialog(document.getElementById('megaBulkConfirm'));
    if (window.megaDialogManager) window.megaDialogManager.hide('megaBulkConfirm');
    else if (window.bootstrap && bootstrap.Modal) bootstrap.Modal.getOrCreateInstance(document.getElementById('megaBulkConfirm')).hide();
    if (window.megaShowWorking) window.megaShowWorking(operation.action);
    // Let the processing indicator paint before navigation starts.
    var frame = window.requestAnimationFrame || function(fn) { setTimeout(fn, 0); };
    frame(function() { frame(function() {
      if (typeof operation.callback === 'function') { operation.callback(); return; }
      var submit = operation.submit, form = submit.form;
      var hidden = document.createElement('input');
      hidden.type = 'hidden'; hidden.name = submit.name; hidden.value = submit.value;
      form.appendChild(hidden);
      form.submit();
    }); });
  });
})();
</script>
<?php endif; ?>

<?php
fm_show_footer();

// --- END HTML ---

// Functions

/**
 * It prints the css/js files into html
 * @param key The key of the external file to print.
 */
function print_external($key)
{
    global $external;

    if (!array_key_exists($key, $external)) {
        // throw new Exception('Key missing in external: ' . key);
        echo "<!-- EXTERNAL: MISSING KEY $key -->";
        return;
    }

    echo "$external[$key]";
}

/**
 * Verify CSRF TOKEN and remove after certified
 * @param string $token
 * @return bool
 */
function verifyToken($token)
{
    if (hash_equals($_SESSION['token'], $token)) {
        return true;
    }
    return false;
}

/**
 * Delete  file or folder (recursively)
 * @param string $path
 * @return bool
 */
function fm_delete_user_item($path) {
    if (FM_READONLY) return false;
    if (FM_STORAGE_TYPE==='mega' && FM_DELETE_MODE==='rubbish') {
        $node=MegaFS::node($path);
        return $node && MegaApi::trash($node['h']);
    }
    return fm_rdelete($path);
}

function fm_rdelete($path)
{
    if (is_link($path)) {
        return unlink($path);
    } elseif (is_dir($path)) {
        $objects = scandir($path);
        $ok = true;
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rdelete($path . '/' . $file)) {
                        $ok = false;
                    }
                }
            }
        }
        return ($ok) ? rmdir($path) : false;
    } elseif (is_file($path)) {
        return unlink($path);
    }
    return false;
}

/**
 * Recursive chmod
 * @param string $path
 * @param int $filemode
 * @param int $dirmode
 * @return bool
 * @todo Will use in mass chmod
 */
function fm_rchmod($path, $filemode, $dirmode)
{
    if (is_dir($path)) {
        if (!chmod($path, $dirmode)) {
            return false;
        }
        $objects = scandir($path);
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (!fm_rchmod($path . '/' . $file, $filemode, $dirmode)) {
                        return false;
                    }
                }
            }
        }
        return true;
    } elseif (is_link($path)) {
        return true;
    } elseif (is_file($path)) {
        return chmod($path, $filemode);
    }
    return false;
}

/**
 * Check the file extension which is allowed or not
 * @param string $filename
 * @return bool
 */
function fm_is_valid_ext($filename)
{
    $allowed = (FM_FILE_EXTENSION) ? explode(',', FM_FILE_EXTENSION) : false;

    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

    return ($isFileAllowed) ? true : false;
}

/**
 * Safely rename
 * @param string $old
 * @param string $new
 * @return bool|null
 */
function fm_rename($old, $new)
{
    $isFileAllowed = fm_is_valid_ext($new);

    if (!is_dir($old)) {
        if (!$isFileAllowed) return false;
    }

    return (!file_exists($new) && file_exists($old)) ? rename($old, $new) : null;
}

/**
 * Copy file or folder (recursively).
 * @param string $path
 * @param string $dest
 * @param bool $upd Update files
 * @param bool $force Create folder with same names instead file
 * @return bool
 */
function fm_rcopy($path, $dest, $upd = true, $force = true)
{
    if (!is_dir($path) && !is_file($path)) {
        return false;
    }

    // MEGA folders must be copied using remote node traversal, not PHP's
    // local filesystem recursion and stream-wrapper copy semantics.
    if (strpos($path, 'mega://') === 0 && strpos($dest, 'mega://') === 0) {
        return fm_mega_copy_tree_checked($path, $dest);
    }

    if (is_dir($path)) {
        if (!fm_mkdir($dest, $force)) {
            return false;
        }

        $objects = array_diff(scandir($path), ['.', '..']);

        foreach ($objects as $file) {
            if (!fm_rcopy("$path/$file", "$dest/$file", $upd, $force)) {
                return false;
            }
        }

        return true;
    }

    // MEGA's PHP stream copy() can report completion before a remote upload is
    // committed (the upload happens on stream close). Use an explicit checked
    // download/upload instead, and verify the destination in a refreshed tree.
    if (strpos($path, 'mega://') === 0 && strpos($dest, 'mega://') === 0) {
        return fm_mega_copy_checked($path, $dest);
    }
    return fm_copy($path, $dest, $upd);
}


/**
 * Copy a MEGA file using explicit download and upload, with post-upload verification.
 * Never report success for a missing destination or silently overwrite a file.
 */
function fm_mega_copy_checked($source, $destination)
{
    return fm_mega_copy_tree_checked($source, $destination);
}

/**
 * Copy MEGA files or complete folder trees. Snapshot the source before writing,
 * create folders top-down and verify every remote file and directory.
 * Never overwrite an existing destination.
 */
function fm_mega_copy_tree_checked($source, $destination)
{
    if (!class_exists('MegaApi') || !class_exists('MegaFS')) return false;
    $src = MegaFS::remote($source);
    $dst = MegaFS::remote($destination);
    if ($src === false || $dst === false || $src === '' || $dst === '') return false;
    if ($dst === $src || strpos($dst . '/', $src . '/') === 0) return false;
    try {
        MegaApi::load();
        $srcHandle = MegaApi::find($src);
        $parentPath = dirname($dst);
        $parentHandle = MegaApi::find($parentPath === '.' ? '' : $parentPath);
        if ($srcHandle === null || $parentHandle === null ||
            MegaApi::$nodes[$parentHandle]['t'] === 0 || MegaApi::find($dst) !== null) return false;

        $snapshot = [];
        $walk = function ($handle, $relative, $depth) use (&$walk, &$snapshot) {
            if ($depth > 32 || count($snapshot) >= 5000) throw new Exception('MEGA folder copy limit exceeded');
            $node = MegaApi::$nodes[$handle];
            $snapshot[] = ['handle' => $handle, 'relative' => $relative,
                'type' => (int)$node['t'], 'size' => (int)$node['s']];
            if ($node['t'] !== 0) {
                foreach ((MegaApi::$kids[$handle] ?? []) as $name => $childHandle) {
                    $walk($childHandle, $relative === '' ? $name : $relative . '/' . $name, $depth + 1);
                }
            }
        };
        $walk($srcHandle, '', 0);
        $rootName = basename($dst);
        foreach ($snapshot as $entry) {
            $target = $dst . ($entry['relative'] === '' ? '' : '/' . $entry['relative']);
            $dir = dirname($target);
            MegaApi::load();
            $ph = MegaApi::find($dir === '.' ? '' : $dir);
            if ($ph === null || MegaApi::find($target) !== null) return false;
            $name = basename($target);
            if ($entry['type'] !== 0) {
                if (!MegaApi::mkdir($ph, $name)) return false;
            } else {
                $tmp = tempnam(sys_get_temp_dir(), 'megacopy_');
                if ($tmp === false) return false;
                try {
                    if (!MegaApi::download($entry['handle'], $tmp) ||
                        filesize($tmp) !== $entry['size'] ||
                        !MegaApi::upload($tmp, $ph, $name)) return false;
                } finally {
                    @unlink($tmp);
                }
            }
            MegaApi::load();
            $created = MegaApi::find($target);
            if ($created === null ||
                (int)MegaApi::$nodes[$created]['t'] !== $entry['type'] ||
                ($entry['type'] === 0 && (int)MegaApi::$nodes[$created]['s'] !== $entry['size'])) return false;
        }
        return true;
    } catch (Throwable $e) {
        error_log('MEGA recursive copy failed: ' . $e->getMessage());
        return false;
    }
}

/** Move file or folder and verify the final location using fresh MEGA metadata. */
function fm_mega_destination_exists($destination)
{
    if (strpos($destination, 'mega://') !== 0) return file_exists($destination);
    try {
        MegaApi::load();
        $remote = MegaFS::remote($destination);
        return $remote !== false && MegaApi::find($remote) !== null;
    } catch (Throwable $e) {
        error_log('MEGA destination lookup: ' . $e->getMessage());
        // A lookup failure is not evidence of a name conflict.
        return false;
    }
}

function fm_mega_move_checked($source, $destination)
{
    if (strpos($source, 'mega://') !== 0 || strpos($destination, 'mega://') !== 0) {
        return fm_rename($source, $destination) === true;
    }
    $src = MegaFS::remote($source);
    $dst = MegaFS::remote($destination);
    if ($src === false || $dst === false || $src === '' || $dst === '' ||
        $src === $dst || strpos($dst . '/', $src . '/') === 0) return false;
    try {
        MegaApi::load();
        $handle = MegaApi::find($src);
        $parent = dirname($dst);
        $ph = MegaApi::find($parent === '.' ? '' : $parent);
        if ($handle === null || $ph === null || MegaApi::find($dst) !== null ||
            MegaApi::$nodes[$ph]['t'] === 0) return false;
        $kind = (int)MegaApi::$nodes[$handle]['t'];
        if (!MegaApi::move($handle, $ph, basename($dst))) return false;
        MegaApi::load();
        $found = MegaApi::find($dst);
        return $found === $handle && MegaApi::find($src) === null &&
            (int)MegaApi::$nodes[$found]['t'] === $kind;
    } catch (Throwable $e) {
        error_log('MEGA move failed: ' . $e->getMessage());
        return false;
    }
}

/**
 * Safely create folder
 * @param string $dir
 * @param bool $force
 * @return bool
 */
function fm_mkdir($dir, $force)
{
    if (file_exists($dir)) {
        if (is_dir($dir)) {
            return $dir;
        } elseif (!$force) {
            return false;
        }
        unlink($dir);
    }
    return mkdir($dir, 0777, true);
}

/**
 * Safely copy file
 * @param string $f1
 * @param string $f2
 * @param bool $upd Indicates if file should be updated with new content
 * @return bool
 */
function fm_copy($f1, $f2, $upd)
{
    $time1 = filemtime($f1);
    if (file_exists($f2)) {
        $time2 = filemtime($f2);
        if ($time2 >= $time1 && $upd) {
            return false;
        }
    }
    $ok = copy($f1, $f2);
    if ($ok) {
        touch($f2, $time1);
    }
    return $ok;
}

/**
 * Get mime type
 * @param string $file_path
 * @return mixed|string
 */
function fm_get_mime_type($file_path)
{
    if (strpos($file_path, 'mega://') === 0) { // avoid downloading the file just to sniff its type
        $m = fm_get_file_mimes(strtolower(pathinfo($file_path, PATHINFO_EXTENSION)));
        return is_array($m) ? $m[0] : ($m ?: 'application/octet-stream');
    }
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $file_path);
        if (\PHP_VERSION_ID < 80000) {
            finfo_close($finfo);
        }
        return $mime;
    } elseif (function_exists('mime_content_type')) {
        return mime_content_type($file_path);
    } elseif (!stristr(ini_get('disable_functions'), 'shell_exec')) {
        $file = escapeshellarg($file_path);
        $mime = shell_exec('file -bi ' . $file);
        return $mime;
    } else {
        return '--';
    }
}

/**
 * HTTP Redirect
 * @param string $url
 * @param int $code
 */
function fm_redirect($url, $code = 302)
{
    header('Location: ' . $url, true, $code);
    exit;
}

/**
 * Path traversal prevention and clean the url
 * It replaces (consecutive) occurrences of / and \\ with whatever is in DIRECTORY_SEPARATOR, and processes /. and /.. fine.
 * @param $path
 * @return string
 */
function get_absolute_path($path)
{
    $path = str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $path);
    $parts = array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
    $absolutes = array();
    foreach ($parts as $part) {
        if ('.' == $part) continue;
        if ('..' == $part) {
            array_pop($absolutes);
        } else {
            $absolutes[] = $part;
        }
    }
    return implode(DIRECTORY_SEPARATOR, $absolutes);
}

/**
 * Clean path
 * @param string $path
 * @return string
 */
function fm_clean_path($path, $trim = true)
{
    $path = $trim ? trim($path) : $path;
    $path = trim($path, '\\/');
    $path = str_replace(array('../', '..\\'), '', $path);
    $path =  get_absolute_path($path);
    if ($path == '..') {
        $path = '';
    }
    return str_replace('\\', '/', $path);
}

/**
 * Get parent path
 * @param string $path
 * @return bool|string
 */
function fm_get_parent_path($path)
{
    $path = fm_clean_path($path);
    if ($path != '') {
        $array = explode('/', $path);
        if (count($array) > 1) {
            $array = array_slice($array, 0, -1);
            return implode('/', $array);
        }
        return '';
    }
    return false;
}

function fm_get_display_path($file_path)
{
    global $path_display_mode, $root_path, $root_url;
    switch ($path_display_mode) {
        case 'relative':
            return array(
                'label' => lng('Path'),
                'path' => fm_enc(fm_convert_win(str_replace($root_path, '', $file_path)))
            );
        case 'host':
            $relative_path = str_replace($root_path, '', $file_path);
            return array(
                'label' => lng('Host Path'),
                'path' => fm_enc(fm_convert_win('/' . $root_url . '/' . ltrim(str_replace('\\', '/', $relative_path), '/')))
            );
        case 'full':
        default:
            return array(
                'label' => lng('Full Path'),
                'path' => fm_enc(fm_convert_win($file_path))
            );
    }
}

/**
 * Check file is in exclude list
 * @param string $name The name of the file/folder
 * @param string $path The full path of the file/folder
 * @return bool
 */
function fm_is_exclude_items($name, $path)
{
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (isset($exclude_items) and sizeof($exclude_items)) {
        unset($exclude_items);
    }

    $exclude_items = FM_EXCLUDE_ITEMS;
    if (version_compare(PHP_VERSION, '7.0.0', '<')) {
        $exclude_items = unserialize($exclude_items);
    }
    if (!in_array($name, $exclude_items) && !in_array("*.$ext", $exclude_items) && !in_array($path, $exclude_items)) {
        return true;
    }
    return false;
}

/**
 * get language translations from json file
 * @param int $tr
 * @return array
 */
function fm_get_translations($tr)
{
    global $lang_list;
    static $languages = null;
    if ($languages === null) {
        $content = @file_get_contents(__DIR__ . '/translation.json');
        $decoded = $content !== false ? json_decode($content, true) : null;
        $languages = is_array($decoded) && isset($decoded['language']) && is_array($decoded['language']) ? $decoded['language'] : array();
    }
    $withTranslations = (bool)$tr;
    foreach ($languages as $entry) {
        if (!is_array($entry) || !isset($entry['code'], $entry['name'], $entry['translation']) ||
            !is_string($entry['code']) || !is_string($entry['name']) || !is_array($entry['translation'])) continue;
        $lang_list[$entry['code']] = $entry['name'];
        if ($withTranslations) $tr[$entry['code']] = $entry['translation'];
    }
    return $tr;
}

/**
 * @param string $file
 * Recover all file sizes larger than > 2GB.
 * Works on php 32bits and 64bits and supports linux
 * @return int|string
 */
function fm_get_size($file)
{
    static $iswin = null;
    static $isdarwin = null;
    static $exec_works = null;

    // Set static variables once
    if ($iswin === null) {
        $iswin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $isdarwin = strtoupper(PHP_OS) === 'DARWIN';
        $exec_works = function_exists('exec') && !ini_get('safe_mode') && @exec('echo EXEC') === 'EXEC';
    }

    // Attempt shell command if exec is available
    if ($exec_works) {
        $arg = escapeshellarg($file);
        $cmd = $iswin ? "for %F in (\"$file\") do @echo %~zF" : ($isdarwin ? "stat -f%z $arg" : "stat -c%s $arg");
        @exec($cmd, $output);

        if (!empty($output) && ctype_digit($size = trim(implode("\n", $output)))) {
            return $size;
        }
    }

    // Attempt Windows COM interface for Windows systems
    if ($iswin && class_exists('COM')) {
        try {
            $fsobj = new COM('Scripting.FileSystemObject');
            $f = $fsobj->GetFile(realpath($file));
            if (ctype_digit($size = $f->Size)) {
                return $size;
            }
        } catch (Exception $e) {
            // COM failed, fallback to filesize
        }
    }

    // Default to PHP's filesize function
    return filesize($file);
}


/**
 * Get nice filesize
 * @param int $size
 * @return string
 */
function fm_get_filesize($size)
{
    $size = (float) $size;
    $units = array('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB');
    $power = ($size > 0) ? floor(log($size, 1024)) : 0;
    $power = ($power > (count($units) - 1)) ? (count($units) - 1) : $power;
    return sprintf('%s %s', round($size / pow(1024, $power), 2), $units[$power]);
}

/**
 * Get info about zip archive
 * @param string $path
 * @return array|bool
 */
function fm_get_zip_info($path, $ext)
{
    // ZIP/Phar libraries need a real seekable local file, not mega://.
    // Download to a bounded temporary file and always remove it afterwards.
    $local = $path;
    $temp = false;
    if (strpos($path, 'mega://') === 0) {
        $size = @filesize($path);
        if ($size === false || $size > 64 * 1024 * 1024) return false;
        $temp = @tempnam(sys_get_temp_dir(), 'mega_arc_');
        if ($temp === false) return false;
        $src = @fopen($path, 'rb');
        $dst = @fopen($temp, 'wb');
        if (!$src || !$dst) {
            if ($src) fclose($src);
            if ($dst) fclose($dst);
            @unlink($temp);
            return false;
        }
        $copied = @stream_copy_to_stream($src, $dst, 64 * 1024 * 1024 + 1);
        fclose($src);
        fclose($dst);
        if ($copied === false || $copied > 64 * 1024 * 1024 || $copied !== $size) {
            @unlink($temp);
            return false;
        }
        $local = $temp;
    }
    $files = false;
    try {
        if ($ext === 'zip' && class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            if ($zip->open($local) === true) {
                $files = array();
                for ($i = 0; $i < min($zip->numFiles,1000); $i++) {
                    $info = $zip->statIndex($i);
                    if (!$info) continue;
                    $name = $info['name'];
                    $files[] = array(
                        'name' => $name,
                        'filesize' => (int)$info['size'],
                        'compressed_size' => (int)$info['comp_size'],
                        'folder' => substr($name, -1) === '/'
                    );
                }
                $zip->close();
            }
        } elseif ($ext === 'tar' && class_exists('PharData')) {
            // PharData requires a .tar extension on the temporary filename.
            $tarpath = $local;
            if ($temp !== false) {
                $tarpath = $temp . '.tar';
                if (!@rename($temp, $tarpath)) throw new Exception('Cannot stage TAR');
                $temp = $tarpath;
            }
            $archive = new PharData($tarpath);
            $files = array();
            foreach (new RecursiveIteratorIterator($archive) as $entry) {
                if(count($files)>=1000)break;
                $name = str_replace('phar://' . $tarpath . '/', '', $entry->getPathname());
                $files[] = array(
                    'name' => $name,
                    'filesize' => (int)$entry->getSize(),
                    'compressed_size' => (int)$entry->getSize(),
                    'folder' => $entry->isDir()
                );
            }
        }
    } catch (Throwable $e) {
        $files = false;
        error_log('MEGA archive preview failed: ' . $e->getMessage());
    }
    if ($temp !== false) @unlink($temp);
    return $files;
}

/**
 * Encode html entities
 * @param string $text
 * @return string
 */
function fm_enc($text)
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}

/**
 * Prevent XSS attacks
 * @param string $text
 * @return string
 */
function fm_isvalid_filename($text)
{
    return (strpbrk($text, '/?%*:|"<>' . chr(0)) === FALSE) ? true : false;
}

/**
 * Save message in session
 * @param string $msg
 * @param string $status
 */
function fm_set_msg($msg, $status = 'ok')
{
    $_SESSION[FM_SESSION_ID]['message'] = $msg;
    $_SESSION[FM_SESSION_ID]['status'] = $status;
}

/**
 * Check if string is in UTF-8
 * @param string $string
 * @return int
 */
function fm_is_utf8($string)
{
    return preg_match('//u', $string);
}

/**
 * Convert file name to UTF-8 in Windows
 * @param string $filename
 * @return string
 */
function fm_convert_win($filename)
{
    if (FM_IS_WIN && function_exists('iconv')) {
        $filename = iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $filename);
    }
    return $filename;
}

/**
 * @param $obj
 * @return array
 */
function fm_object_to_array($obj)
{
    if (!is_object($obj) && !is_array($obj)) {
        return $obj;
    }
    if (is_object($obj)) {
        $obj = get_object_vars($obj);
    }
    return array_map('fm_object_to_array', $obj);
}

/**
 * Get CSS classname for file
 * @param string $path
 * @return string
 */
function fm_get_file_icon_class($path)
{
    // get extension
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

    switch ($ext) {
        case 'ico':
        case 'gif':
        case 'jpg':
        case 'jpeg':
        case 'jpc':
        case 'jp2':
        case 'jpx':
        case 'xbm':
        case 'wbmp':
        case 'png':
        case 'bmp':
        case 'tif':
        case 'tiff':
        case 'webp':
        case 'avif':
        case 'svg':
            $img = 'fa fa-picture-o';
            break;
        case 'passwd':
        case 'ftpquota':
        case 'sql':
        case 'js':
        case 'ts':
        case 'jsx':
        case 'tsx':
        case 'hbs':
        case 'json':
        case 'sh':
        case 'config':
        case 'twig':
        case 'tpl':
        case 'md':
        case 'gitignore':
        case 'c':
        case 'cpp':
        case 'h':
        case 'hpp':
        case 'cs':
        case 'py':
        case 'rs':
        case 'map':
        case 'lock':
        case 'dtd':
        case 'ps1':
            $img = 'fa fa-file-code-o';
            break;
        case 'txt':
        case 'ini':
        case 'conf':
        case 'log':
        case 'htaccess':
        case 'yaml':
        case 'yml':
        case 'toml':
        case 'tmp':
        case 'top':
        case 'bot':
        case 'dat':
        case 'bak':
        case 'htpasswd':
        case 'pl':
            $img = 'fa fa-file-text-o';
            break;
        case 'css':
        case 'less':
        case 'sass':
        case 'scss':
            $img = 'fa fa-css3';
            break;
        case 'bz2':
        case 'tbz2':
        case 'tbz':
        case 'zip':
        case 'rar':
        case 'gz':
        case 'tgz':
        case 'tar':
        case '7z':
        case 'xz':
        case 'txz':
        case 'zst':
        case 'tzst':
            $img = 'fa fa-file-archive-o';
            break;
        case 'php':
        case 'php4':
        case 'php5':
        case 'phps':
        case 'phtml':
            $img = 'fa fa-code';
            break;
        case 'htm':
        case 'html':
        case 'shtml':
        case 'xhtml':
            $img = 'fa fa-html5';
            break;
        case 'xml':
        case 'xsl':
            $img = 'fa fa-file-excel-o';
            break;
        case 'wav':
        case 'mp3':
        case 'mp2':
        case 'm4a':
        case 'aac':
        case 'ogg':
        case 'oga':
        case 'wma':
        case 'mka':
        case 'flac':
        case 'ac3':
        case 'tds':
            $img = 'fa fa-music';
            break;
        case 'm3u':
        case 'm3u8':
        case 'pls':
        case 'cue':
        case 'xspf':
            $img = 'fa fa-headphones';
            break;
        case 'avi':
        case 'mpg':
        case 'mpeg':
        case 'mp4':
        case 'm4v':
        case 'flv':
        case 'f4v':
        case 'ogm':
        case 'ogv':
        case 'mov':
        case 'mkv':
        case '3gp':
        case 'asf':
        case 'wmv':
        case 'webm':
            $img = 'fa fa-file-video-o';
            break;
        case 'eml':
        case 'msg':
            $img = 'fa fa-envelope-o';
            break;
        case 'xls':
        case 'xlsx':
        case 'xlsm':
        case 'ods':
            $img = 'fa fa-file-excel-o';
            break;
        case 'csv':
            $img = 'fa fa-file-text-o';
            break;
        case 'bak':
        case 'swp':
            $img = 'fa fa-clipboard';
            break;
        case 'doc':
        case 'docx':
        case 'odt':
            $img = 'fa fa-file-word-o';
            break;
        case 'ppt':
        case 'pptx':
            $img = 'fa fa-file-powerpoint-o';
            break;
        case 'ttf':
        case 'ttc':
        case 'otf':
        case 'woff':
        case 'woff2':
        case 'eot':
        case 'fon':
            $img = 'fa fa-font';
            break;
        case 'pdf':
            $img = 'fa fa-file-pdf-o';
            break;
        case 'psd':
        case 'ai':
        case 'eps':
        case 'fla':
        case 'swf':
            $img = 'fa fa-file-image-o';
            break;
        case 'exe':
        case 'msi':
            $img = 'fa fa-file-o';
            break;
        case 'bat':
            $img = 'fa fa-terminal';
            break;
        default:
            $img = 'fa fa-info-circle';
    }

    return $img;
}

/**
 * Get image files extensions
 * @return array
 */
function fm_get_image_exts()
{
    return array('ico', 'gif', 'jpg', 'jpeg', 'jpc', 'jp2', 'jpx', 'xbm', 'wbmp', 'png', 'bmp', 'tif', 'tiff', 'psd', 'svg', 'webp', 'avif');
}

/**
 * Get video files extensions
 * @return array
 */
function fm_get_video_exts()
{
    return array('avi', 'webm', 'wmv', 'mp4', 'm4v', 'ogm', 'ogv', 'mov', 'mkv');
}

/**
 * Get audio files extensions
 * @return array
 */
function fm_get_audio_exts()
{
    return array('wav', 'mp3', 'ogg', 'm4a');
}

/**
 * Get text file extensions
 * @return array
 */
function fm_get_text_exts()
{
    return array(
        'txt',
        'css',
        'ini',
        'conf',
        'log',
        'htaccess',
        'passwd',
        'ftpquota',
        'sql',
        'js',
        'ts',
        'jsx',
        'tsx',
        'mjs',
        'json',
        'sh',
        'config',
        'php',
        'php4',
        'php5',
        'phps',
        'phtml',
        'htm',
        'html',
        'shtml',
        'xhtml',
        'xml',
        'xsl',
        'm3u',
        'm3u8',
        'pls',
        'cue',
        'bash',
        'vue',
        'eml',
        'msg',
        'csv',
        'bat',
        'twig',
        'tpl',
        'md',
        'gitignore',
        'less',
        'sass',
        'scss',
        'c',
        'cpp',
        'h',
        'hpp',
        'cs',
        'py',
        'go',
        'zsh',
        'swift',
        'map',
        'lock',
        'dtd',
        'svg',
        'asp',
        'aspx',
        'asx',
        'asmx',
        'ashx',
        'jsp',
        'jspx',
        'cgi',
        'dockerfile',
        'ruby',
        'yml',
        'yaml',
        'toml',
        'vhost',
        'scpt',
        'applescript',
        'csx',
        'cshtml',
        'c++',
        'coffee',
        'cfm',
        'rb',
        'graphql',
        'mustache',
        'jinja',
        'http',
        'handlebars',
        'java',
        'es',
        'es6',
        'markdown',
        'wiki',
        'tmp',
        'top',
        'bot',
        'dat',
        'bak',
        'htpasswd',
        'pl',
        'ps1'
    );
}

/**
 * Get mime types of text files
 * @return array
 */
function fm_get_text_mimes()
{
    return array(
        'application/xml',
        'application/javascript',
        'application/x-javascript',
        'image/svg+xml',
        'message/rfc822',
        'application/json',
    );
}

/**
 * Get file names of text files w/o extensions
 * @return array
 */
function fm_get_text_names()
{
    return array(
        'license',
        'readme',
        'authors',
        'contributors',
        'changelog',
    );
}

/**
 * Get online docs viewer supported files extensions
 * @return array
 */
function fm_get_onlineViewer_exts()
{
    return array('doc', 'docx', 'xls', 'xlsx', 'pdf', 'ppt', 'pptx', 'ai', 'psd', 'dxf', 'xps', 'rar', 'odt', 'ods');
}

/**
 * It returns the mime type of a file based on its extension.
 * @param extension The file extension of the file you want to get the mime type for.
 * @return string|string[] The mime type of the file.
 */
function fm_get_file_mimes($extension)
{
    $fileTypes['swf'] = 'application/x-shockwave-flash';
    $fileTypes['pdf'] = 'application/pdf';
    $fileTypes['exe'] = 'application/octet-stream';
    $fileTypes['zip'] = 'application/zip';
    $fileTypes['doc'] = 'application/msword';
    $fileTypes['xls'] = 'application/vnd.ms-excel';
    $fileTypes['ppt'] = 'application/vnd.ms-powerpoint';
    $fileTypes['gif'] = 'image/gif';
    $fileTypes['png'] = 'image/png';
    $fileTypes['jpeg'] = 'image/jpg';
    $fileTypes['jpg'] = 'image/jpg';
    $fileTypes['webp'] = 'image/webp';
    $fileTypes['avif'] = 'image/avif';
    $fileTypes['rar'] = 'application/rar';

    $fileTypes['ra'] = 'audio/x-pn-realaudio';
    $fileTypes['ram'] = 'audio/x-pn-realaudio';
    $fileTypes['ogg'] = 'audio/x-pn-realaudio';

    $fileTypes['wav'] = 'video/x-msvideo';
    $fileTypes['wmv'] = 'video/x-msvideo';
    $fileTypes['avi'] = 'video/x-msvideo';
    $fileTypes['asf'] = 'video/x-msvideo';
    $fileTypes['divx'] = 'video/x-msvideo';

    $fileTypes['mp3'] = 'audio/mpeg';
    $fileTypes['mp4'] = 'video/mp4';
    $fileTypes['mpeg'] = 'video/mpeg';
    $fileTypes['mpg'] = 'video/mpeg';
    $fileTypes['mpe'] = 'video/mpeg';
    $fileTypes['mov'] = 'video/quicktime';
    $fileTypes['swf'] = 'video/quicktime';
    $fileTypes['3gp'] = 'video/quicktime';
    $fileTypes['m4a'] = 'video/quicktime';
    $fileTypes['aac'] = 'video/quicktime';
    $fileTypes['m3u'] = 'video/quicktime';

    $fileTypes['php'] = ['application/x-php'];
    $fileTypes['html'] = ['text/html'];
    $fileTypes['txt'] = ['text/plain'];
    //Unknown mime-types should be 'application/octet-stream'
    if (empty($fileTypes[$extension])) {
        $fileTypes[$extension] = ['application/octet-stream'];
    }
    return $fileTypes[$extension];
}

/**
 * This function scans the files and folder recursively, and return matching files
 * @param string $dir
 * @param string $filter
 * @return array|null
 */
function scan($dir = '', $filter = '')
{
    $path = FM_ROOT_PATH . '/' . $dir;
    if ($path) {
        $ite = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));
        $rii = new RegexIterator($ite, "/(" . $filter . ")/i");

        $files = array();
        foreach ($rii as $file) {
            if (!$file->isDir()) {
                $fileName = $file->getFilename();
                $location = str_replace(FM_ROOT_PATH, '', $file->getPath());
                $files[] = array(
                    "name" => $fileName,
                    "type" => "file",
                    "path" => $location,
                );
            }
        }
        return $files;
    }
}

/**
 * Parameters: downloadFile(File Location, File Name,
 * max speed, is streaming
 * If streaming - videos will show as videos, images as images
 * instead of download prompt
 * https://stackoverflow.com/a/13821992/1164642
 */
function fm_download_file($fileLocation, $fileName, $chunkSize  = 1024)
{
    if (connection_status() != 0)
        return (false);
    $extension = pathinfo($fileName, PATHINFO_EXTENSION);

    $contentType = fm_get_file_mimes($extension);

    if (is_array($contentType)) {
        $contentType = implode(' ', $contentType);
    }

    $size = filesize($fileLocation);

    if ($size == 0) {
        fm_set_msg(lng('Zero byte file! Aborting download'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));

        return (false);
    }

    @ini_set('magic_quotes_runtime', 0);
    $fp = fopen("$fileLocation", "rb");

    if ($fp === false) {
        fm_set_msg(lng('Cannot open file! Aborting download'), 'error');
        $FM_PATH = FM_PATH;
        fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
        return (false);
    }

    // headers
    header('Content-Description: File Transfer');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Pragma: public');
    header("Content-Transfer-Encoding: binary");
    header("Content-Type: $contentType");

    $contentDisposition = 'attachment';

    if (strstr($_SERVER['HTTP_USER_AGENT'], "MSIE")) {
        $fileName = preg_replace('/\./', '%2e', $fileName, substr_count($fileName, '.') - 1);
        header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
    } else {
        header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
    }

    header("Accept-Ranges: bytes");
    $range = 0;

    if (isset($_SERVER['HTTP_RANGE'])) {
        list($a, $range) = explode("=", $_SERVER['HTTP_RANGE']);
        str_replace($range, "-", $range);
        $size2 = $size - 1;
        $new_length = $size - $range;
        header("HTTP/1.1 206 Partial Content");
        header("Content-Length: $new_length");
        header("Content-Range: bytes $range$size2/$size");
    } else {
        $size2 = $size - 1;
        header("Content-Range: bytes 0-$size2/$size");
        header("Content-Length: " . $size);
    }
    while (ob_get_level()) ob_end_clean();
    if (strpos($fileLocation, 'mega://') === 0) {
        fpassthru($fp); // reuse the already-downloaded stream
    } else {
        $fileLocation = realpath($fileLocation);
        readfile($fileLocation);
    }

    fclose($fp);

    return ((connection_status() == 0) and !connection_aborted());
}

/**
 * Class to work with zip files (using ZipArchive)
 */
class FM_Zipper
{
    private $zip;

    public function __construct()
    {
        $this->zip = new ZipArchive();
    }

    /**
     * Create archive with name $filename and files $files (RELATIVE PATHS!)
     * @param string $filename
     * @param array|string $files
     * @return bool
     */
    public function create($filename, $files)
    {
        $res = $this->zip->open($filename, ZipArchive::CREATE);
        if ($res !== true) {
            return false;
        }
        if (is_array($files)) {
            foreach ($files as $f) {
                $f = fm_clean_path($f);
                if (!$this->addFileOrDir($f)) {
                    $this->zip->close();
                    return false;
                }
            }
            $this->zip->close();
            return true;
        } else {
            if ($this->addFileOrDir($files)) {
                $this->zip->close();
                return true;
            }
            return false;
        }
    }

    /**
     * Extract archive $filename to folder $path (RELATIVE OR ABSOLUTE PATHS)
     * @param string $filename
     * @param string $path
     * @return bool
     */
    public function unzip($filename, $path)
    {
        $res = $this->zip->open($filename);
        if ($res !== true) {
            return false;
        }
        if ($this->zip->extractTo($path)) {
            $this->zip->close();
            return true;
        }
        return false;
    }

    /**
     * Add file/folder to archive
     * @param string $filename
     * @return bool
     */
    private function addFileOrDir($filename)
    {
        if (is_file($filename)) {
            return $this->zip->addFile($filename);
        } elseif (is_dir($filename)) {
            return $this->addDir($filename);
        }
        return false;
    }

    /**
     * Add folder recursively
     * @param string $path
     * @return bool
     */
    private function addDir($path)
    {
        if (!$this->zip->addEmptyDir($path)) {
            return false;
        }
        $objects = scandir($path);
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (is_dir($path . '/' . $file)) {
                        if (!$this->addDir($path . '/' . $file)) {
                            return false;
                        }
                    } elseif (is_file($path . '/' . $file)) {
                        if (!$this->zip->addFile($path . '/' . $file)) {
                            return false;
                        }
                    }
                }
            }
            return true;
        }
        return false;
    }
}

/**
 * Class to work with Tar files (using PharData)
 */
class FM_Zipper_Tar
{
    private $tar;

    public function __construct()
    {
        $this->tar = null;
    }

    /**
     * Create archive with name $filename and files $files (RELATIVE PATHS!)
     * @param string $filename
     * @param array|string $files
     * @return bool
     */
    public function create($filename, $files)
    {
        $this->tar = new PharData($filename);
        if (is_array($files)) {
            foreach ($files as $f) {
                $f = fm_clean_path($f);
                if (!$this->addFileOrDir($f)) {
                    return false;
                }
            }
            return true;
        } else {
            if ($this->addFileOrDir($files)) {
                return true;
            }
            return false;
        }
    }

    /**
     * Extract archive $filename to folder $path (RELATIVE OR ABSOLUTE PATHS)
     * @param string $filename
     * @param string $path
     * @return bool
     */
    public function unzip($filename, $path)
    {
        $res = $this->tar->open($filename);
        if ($res !== true) {
            return false;
        }
        if ($this->tar->extractTo($path)) {
            return true;
        }
        return false;
    }

    /**
     * Add file/folder to archive
     * @param string $filename
     * @return bool
     */
    private function addFileOrDir($filename)
    {
        if (is_file($filename)) {
            try {
                $this->tar->addFile($filename);
                return true;
            } catch (Exception $e) {
                return false;
            }
        } elseif (is_dir($filename)) {
            return $this->addDir($filename);
        }
        return false;
    }

    /**
     * Add folder recursively
     * @param string $path
     * @return bool
     */
    private function addDir($path)
    {
        $objects = scandir($path);
        if (is_array($objects)) {
            foreach ($objects as $file) {
                if ($file != '.' && $file != '..') {
                    if (is_dir($path . '/' . $file)) {
                        if (!$this->addDir($path . '/' . $file)) {
                            return false;
                        }
                    } elseif (is_file($path . '/' . $file)) {
                        try {
                            $this->tar->addFile($path . '/' . $file);
                        } catch (Exception $e) {
                            return false;
                        }
                    }
                }
            }
            return true;
        }
        return false;
    }
}

/**
 * Save Configuration
 */
class FM_Config
{
    var $data;

    function __construct()
    {
        global $root_path, $root_url, $CONFIG;
        $fm_url = $root_url . $_SERVER["PHP_SELF"];
        $this->data = array(
            'lang' => 'en',
            'error_reporting' => true,
            'show_hidden' => true
        );
        $data = false;
        if (strlen($CONFIG)) {
            $data = fm_object_to_array(json_decode($CONFIG));
        } else {
            $msg = lng("AppName").'<br>Error: Cannot load configuration';
            if (substr($fm_url, -1) == '/') {
                $fm_url = rtrim($fm_url, '/');
                $msg .= '<br>';
                $msg .= '<br>Seems like you have a trailing slash on the URL.';
                $msg .= '<br>Try this link: <a href="' . $fm_url . '">' . $fm_url . '</a>';
            }
            die($msg);
        }
        if (is_array($data) && count($data)) $this->data = $data;
        else $this->save();
    }

    function save()
    {
        global $config_file;
        $fm_file = is_readable($config_file) ? $config_file : __FILE__;
        $var_name = '$CONFIG';
        $var_value = var_export(json_encode($this->data), true);
        $config_string = "<?php" . chr(13) . chr(10) . "//Default Configuration" . chr(13) . chr(10) . "$var_name = $var_value;" . chr(13) . chr(10);
        if (is_writable($fm_file)) {
            $lines = file($fm_file);
            if ($fh = @fopen($fm_file, "w")) {
                @fputs($fh, $config_string, strlen($config_string));
                for ($x = 3; $x < count($lines); $x++) {
                    @fputs($fh, $lines[$x], strlen($lines[$x]));
                }
                @fclose($fh);
            }
        }
    }
}

//--- Templates Functions ---

/**
 * Show nav block
 * @param string $path
 */
function fm_show_nav_path($path)
{
    global $lang, $sticky_navbar, $editFile;
    $isStickyNavBar = $sticky_navbar ? 'fixed-top' : '';
?>
    <nav class="navbar navbar-expand-lg mb-4 main-nav <?php echo $isStickyNavBar ?> bg-body-tertiary" data-bs-theme="<?php echo FM_THEME; ?>">
        <div class="fm-title-quota">
            <a class="navbar-brand"> <?php echo lng('AppTitle') ?> </a>
            <?php
            // Cache quota briefly to avoid an API call on every navigation.
            $quotaLabel = 'Quota unavailable';
            if (class_exists('MegaApi') && !empty(MegaApi::$sid)) {
                if (!isset($_SESSION['mega_quota_cache']) ||
                    !is_array($_SESSION['mega_quota_cache']) ||
                    time() - (int)($_SESSION['mega_quota_cache']['time'] ?? 0) > 120) {
                    try {
                        $quotaData = MegaApi::quota();
                        $_SESSION['mega_quota_cache'] = ['time' => time(), 'data' => $quotaData];
                    } catch (Throwable $e) {
                        $_SESSION['mega_quota_cache'] = ['time' => time(), 'data' => null];
                    }
                }
                $quotaData = $_SESSION['mega_quota_cache']['data'];
                if (is_array($quotaData) && isset($quotaData['used'], $quotaData['total']) &&
                    $quotaData['total'] > 0) {
                    $quotaLabel = sprintf('%.1f / %.1f GiB',
                        $quotaData['used'] / 1073741824, $quotaData['total'] / 1073741824);
                }
            }
            ?>
            <span class="fm-quota" title="MEGA storage used / total"><?php echo htmlspecialchars($quotaLabel, ENT_QUOTES, 'UTF-8'); ?></span>
        </div>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="<?php echo lng('Toggle navigation') ?>">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="fm-always-visible-path">
            <?php
            $path = fm_clean_path($path);
            $root_url = "<a href='?p='><i class='fa fa-home' aria-hidden='true' title='" . FM_ROOT_PATH . "'></i></a>";
            $sep = '<i class="bread-crumb"> / </i>';
            if ($path != '') {
                $exploded = explode('/', $path);
                $count = count($exploded);
                $array = array();
                $parent = '';
                for ($i = 0; $i < $count; $i++) {
                    $parent = trim($parent . '/' . $exploded[$i], '/');
                    $parent_enc = urlencode($parent);
                    $array[] = "<a href='?p={$parent_enc}'>" . fm_enc(fm_convert_win($exploded[$i])) . "</a>";
                }
                $root_url .= $sep . implode($sep, $array);
            }
            $desktopUp = '';
            if (FM_PATH !== '') {
                $upPath = dirname(trim(FM_PATH, '/'));
                if ($upPath === '.' || $upPath === '/') $upPath = '';
                $desktopUp = ' <a class="mega-desktop-parent" href="?p=' . rawurlencode($upPath) . '" title="Up to parent folder" aria-label="Up to parent folder"><i class="fa fa-level-up" aria-hidden="true"></i></a>';
            }
            echo '<div class="fm-path-links">' . $root_url . $desktopUp . $editFile . '</div>';
            ?>

        </div>
        <div class="collapse navbar-collapse" id="navbarSupportedContent">

            <div class="col-xs-6 col-sm-7">
                <ul class="navbar-nav justify-content-end" data-bs-theme="<?php echo FM_THEME; ?>">
                    <?php if (!FM_READONLY): ?>
                        <li class="nav-item">
                            <a title="<?php echo lng('Upload') ?>" class="nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload"><i class="fa fa-cloud-upload" aria-hidden="true"></i> <?php echo lng('Upload') ?></a>
                        </li>
                        <li class="nav-item">
                            <a title="<?php echo lng('NewItem') ?>" class="nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;new_item=1"><i class="fa fa-plus-square"></i> <?php echo lng('NewItem') ?></a>
                        </li>
                    <?php endif; ?>
                    <li class="nav-item"><a class="nav-link" href="?<?php echo FM_STORAGE_TYPE === 'mega' ? 'mega_tools=1' : 'local_tools=1'; ?>&amp;p=<?php echo rawurlencode(FM_PATH); ?>"><i class="fa fa-search" aria-hidden="true"></i> <?php echo lng('Search'); ?></a></li>
                    <?php if (FM_STORAGE_TYPE === 'mega'): ?><li class="nav-item"><a class="nav-link" href="?mega_rubbish=1&amp;p="><i class="fa fa-trash-o" aria-hidden="true"></i> <?php echo lng('Rubbish Bin'); ?></a></li><?php endif; ?>
                    <?php if (FM_STORAGE_TYPE === 'mega'): ?><li class="nav-item"><a class="nav-link" href="?mega_shared_links=1&amp;p=<?php echo rawurlencode(FM_PATH); ?>"><i class="fa fa-link" aria-hidden="true"></i> <?php echo lng('Shared Links'); ?></a></li><?php endif; ?>
                    <?php if (FM_USE_AUTH): ?>
                        <li class="nav-item avatar dropdown">
                            <a class="nav-link dropdown-toggle" id="navbarDropdownMenuLink-5" data-bs-toggle="dropdown" aria-expanded="false">
                                <i class="fa fa-user-circle"></i>
                            </a>

                            <div class="dropdown-menu dropdown-menu-end text-small shadow" aria-labelledby="navbarDropdownMenuLink-5" data-bs-theme="<?php echo FM_THEME; ?>">
                                <?php if (!FM_READONLY): ?>
                                    <a title="<?php echo lng('Settings') ?>" class="dropdown-item nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;settings=1"><i class="fa fa-cog" aria-hidden="true"></i> <?php echo lng('Settings') ?></a>
                                <?php endif ?>
                                <a title="<?php echo lng('Help') ?>" class="dropdown-item nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;help=2"><i class="fa fa-exclamation-circle" aria-hidden="true"></i> <?php echo lng('Help') ?></a>
                                <a title="<?php echo lng('Logout') ?>" class="dropdown-item nav-link" href="?logout=1"><i class="fa fa-sign-out" aria-hidden="true"></i> <?php echo lng('Logout') ?></a>
                            </div>
                        </li>
                    <?php else: ?>
                        <?php if (!FM_READONLY): ?>
                            <li class="nav-item">
                                <a title="<?php echo lng('Settings') ?>" class="dropdown-item nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;settings=1"><i class="fa fa-cog" aria-hidden="true"></i> <?php echo lng('Settings') ?></a>
                            </li>
                        <?php endif; ?>
                        <li class="nav-item">
 <a title="<?php echo lng('Logout') ?>" class="nav-link" href="<?php echo FM_STORAGE_TYPE === 'mega' ? '?mega_logout=1' : '?logout=1'; ?>"><i class="fa fa-sign-out" aria-hidden="true"></i> <?php echo lng('Logout') ?></a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>
    <!-- Desktop compact header: reuse the existing bulk-operation handlers. -->
    <style id="mega-v73-desktop-compact">
    @media <?php echo fm_desktop_media_query(); ?> {
      html body .main-nav {display:grid!important;grid-template-columns:minmax(180px,1fr) auto!important;grid-template-rows:auto auto!important;align-items:center!important;column-gap:12px!important;row-gap:1px!important;padding:3px 8px 5px!important;margin-bottom:12px!important;min-height:68px!important}
      html body .main-nav>.fm-title-quota{grid-column:1!important;grid-row:1!important;order:unset!important;align-self:center!important;flex-wrap:nowrap!important;gap:10px!important}
      html body .main-nav>.fm-title-quota .navbar-brand{font-size:20px!important;font-weight:600!important;white-space:nowrap!important;margin:0!important;padding:0!important}
      html body .main-nav>.fm-always-visible-path{grid-column:1!important;grid-row:2!important;order:unset!important;flex-basis:auto!important;flex-grow:0!important;width:100%!important;padding:0!important;min-width:0!important;align-self:center!important}
      html body .main-nav>#navbarSupportedContent{grid-column:2!important;grid-row:1!important;order:unset!important;display:flex!important;flex-grow:0!important;flex-basis:auto!important;align-self:center!important;justify-self:end!important;min-width:0!important}
      html body .main-nav>#navbarSupportedContent .navbar-nav{display:flex!important;flex-direction:row!important;align-items:center!important;gap:14px!important;flex-wrap:nowrap!important}
      html body .main-nav>#navbarSupportedContent .nav-link{padding:2px 0!important;white-space:nowrap!important}
      html body .main-nav>#navbarSupportedContent .nav-item{display:flex!important;align-items:center!important;gap:14px!important}
      html body .main-nav .mega-desktop-bulk{grid-column:2!important;grid-row:2!important;justify-self:end!important;align-self:center!important;display:flex;align-items:center;gap:0;min-height:29px}
      html body .main-nav .mega-desktop-bulk[hidden]{display:none!important}
      html body .main-nav .mega-desktop-bulk button{border:0;border-left:1px solid var(--bs-border-color,#d6dce2);background:transparent;color:var(--bs-body-color,#333);padding:2px 13px;font-size:13px;display:inline-flex;align-items:center;gap:7px;white-space:nowrap;min-height:27px}
      html body .main-nav .mega-desktop-bulk button:first-child{border-left:0}
      html body .main-nav .mega-desktop-bulk button i{font-size:16px;color:#347cbb}
      html body .main-nav .mega-desktop-bulk button.mega-desktop-delete,html body .main-nav .mega-desktop-bulk button.mega-desktop-delete i{color:#d3434d}
      html body .main-nav .mega-desktop-bulk button:hover{background:var(--bs-secondary-bg,#e8edf2)}
      html body .mega-actions{display:none!important}
      html body .mega-view-controls{display:none!important}
      html body #wrapper>form.pt-3{padding-top:0!important}
      html body .main-nav .mega-desktop-bulk .mega-desktop-count{font-size:12px;color:var(--bs-secondary-color,#777);padding-right:8px;white-space:nowrap}
    }
    @media <?php echo fm_desktop_media_query(); ?> {
      html body #main-table tbody tr.fm-parent-folder-row{display:none!important}
      html body .fm-path-links{display:flex!important;align-items:center!important;gap:4px!important}
      html body .fm-path-links .mega-desktop-parent{display:inline-flex!important;align-items:center!important;justify-content:center!important;margin-left:9px!important;font-size:19px!important;color:var(--bs-link-color,#1670b8)!important;text-decoration:none!important}
      html body .main-nav .mega-desktop-bulk button:disabled{opacity:.45;cursor:default;background:transparent!important}
      html body .main-nav .mega-desktop-bulk{visibility:visible!important;min-height:28px!important}
      html body .main-nav{grid-template-rows:minmax(23px,auto) minmax(28px,auto)!important}
    }
    @media <?php echo fm_desktop_media_query(); ?> and (max-width:1100px){html body .main-nav>#navbarSupportedContent .navbar-nav{gap:8px!important}html body .main-nav .mega-desktop-bulk button{padding:2px 8px!important}}
    </style>
    <style id="mega-v75-desktop-right-align">
    @media <?php echo fm_desktop_media_query(); ?>{
      /* v75: override Bootstrap col-sm-7 (58.333%) on the desktop nav wrapper.
         Both header action rows now terminate at the same right edge. */
      html body .main-nav>#navbarSupportedContent{width:max-content!important;max-width:none!important;margin-left:auto!important;margin-right:0!important;padding-right:0!important;justify-content:flex-end!important}
      html body .main-nav>#navbarSupportedContent>.col-xs-6.col-sm-7{width:max-content!important;max-width:none!important;flex:0 0 auto!important;margin:0!important;padding:0!important}
      html body .main-nav>#navbarSupportedContent .navbar-nav{width:max-content!important;margin-left:auto!important;margin-right:0!important;justify-content:flex-end!important}
    }
    </style>
    <script id="mega-v73-desktop-compact-script">
    (function(){
      function init(){
        var nav=document.querySelector('.main-nav'),counter=document.getElementById('mega-selected-count'),table=document.getElementById('main-table');
        if(!nav||!table||nav.querySelector('.mega-desktop-bulk'))return;
        var bar=document.createElement('div');bar.className='mega-desktop-bulk';bar.hidden=false;
        var count=document.createElement('span');count.className='mega-desktop-count';bar.appendChild(count);
        var labels=<?php echo json_encode(array_map(function($key){return html_entity_decode(lng($key),ENT_QUOTES,'UTF-8');},['delete'=>'Delete','zip'=>'Zip','tar'=>'Tar','copy'=>'Copy','selected'=>'{count} selected']),JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_UNESCAPED_UNICODE); ?>;
        [['delete',labels.delete,'fa-trash-o','mega-desktop-delete'],['zip',labels.zip,'fa-file-archive-o',''],['tar',labels.tar,'fa-file-archive-o',''],['copy',labels.copy,'fa-files-o','']].forEach(function(a){
          var b=document.createElement('button');b.type='button';b.className=a[3];
          var icon=document.createElement('i');icon.className='fa '+a[2];icon.setAttribute('aria-hidden','true');b.appendChild(icon);
          b.appendChild(document.createTextNode(a[1]));
          b.addEventListener('click',function(){
            if(a[0]==='copy'){var input=document.getElementById('a-copy');if(input)input.click();}
            else if(typeof megaConfirmBulk==='function')megaConfirmBulk(a[0]);
          });bar.appendChild(b);
        });
        nav.appendChild(bar);
        function update(){var checked=table.querySelectorAll('tbody input[name="file[]"]:checked').length;bar.hidden=false;count.textContent=checked ? labels.selected.replace('{count}',String(checked)) : '';Array.prototype.forEach.call(bar.querySelectorAll('button'),function(button){button.disabled=checked===0;});}
        table.addEventListener('change',function(e){if(e.target.matches('input[type="checkbox"]'))update()});
        var selectAll=document.getElementById('mega-select-toggle');if(selectAll)selectAll.addEventListener('click',function(){setTimeout(update,0)});
        if(counter){var observer=new MutationObserver(update);observer.observe(counter,{childList:true,characterData:true,subtree:true});}update();
      }
      if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
    })();
    </script>
    <!-- Mobile-only compact header and contextual hamburger menu. -->
    <div class="mega-mobile-header-spacer" aria-hidden="true"></div>
    <div class="mega-mobile-header" aria-label="Current folder and actions">
      <?php $mobileParent = (($d=dirname(trim(FM_PATH, '/'))) === '.' || $d === '/') ? '' : $d; ?>
      <div class="mega-mobile-heading"><div class="mega-mobile-heading-line"><strong><?php echo htmlspecialchars(lng('AppTitle'), ENT_QUOTES, 'UTF-8'); ?></strong><?php if (isset($_SESSION['mega_quota_cache']['data']) && is_array($_SESSION['mega_quota_cache']['data'])) { $mq = $_SESSION['mega_quota_cache']['data']; if (!empty($mq['total'])) { ?><span class="mega-mobile-quota"><?php echo htmlspecialchars(sprintf('%.1f / %.1f GiB', $mq['used']/1073741824, $mq['total']/1073741824), ENT_QUOTES, 'UTF-8'); ?></span><?php } } ?></div><div class="mega-mobile-crumbs"><div class="mega-mobile-crumb-links"><a href="?p=" aria-label="Storage root"><i class="fa fa-home" aria-hidden="true"></i></a><?php $crumbPath = ''; foreach (explode('/', trim(FM_PATH, '/')) as $crumbPart) { if ($crumbPart === '') continue; $crumbPath .= ($crumbPath === '' ? '' : '/') . $crumbPart; ?><span class="mega-crumb-separator">/</span><a href="?p=<?php echo urlencode($crumbPath); ?>" title="<?php echo htmlspecialchars($crumbPath, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($crumbPart, ENT_QUOTES, 'UTF-8'); ?></a><?php } ?></div><?php if (FM_PATH !== ''): ?><a class="mega-mobile-parent" href="?p=<?php echo urlencode($mobileParent); ?>" aria-label="Up to parent folder" title="Up to parent folder"><i class="fa fa-level-up"></i></a><?php endif; ?></div></div>
      <button type="button" class="mega-mobile-menu-trigger" aria-expanded="false" aria-controls="mega-mobile-menu" aria-label="File manager menu"><i class="fa fa-bars"></i></button>
      <div class="mega-mobile-menu" id="mega-mobile-menu" hidden>
        <div class="mega-mobile-selected-actions" hidden>
          <div class="mega-mobile-selection-label"><?php echo lng('Selected count placeholder'); ?></div>
          <button type="button" data-bulk="copy"><i class="fa fa-files-o"></i> <?php echo lng('Copy/Move'); ?></button>
          <button type="button" data-bulk="delete"><i class="fa fa-trash-o"></i> <?php echo lng('Delete'); ?></button>
          <button type="button" data-bulk="zip"><i class="fa fa-file-archive-o"></i> <?php echo lng('Create ZIP'); ?></button>
          <button type="button" data-bulk="tar"><i class="fa fa-file-archive-o"></i> <?php echo lng('Create TAR'); ?></button>
          <hr>
        </div>
        <?php if (!FM_READONLY): ?>
        <a href="?p=<?php echo urlencode(FM_PATH); ?>&amp;new_item=1"><i class="fa fa-plus-square-o"></i> <?php echo lng('NewItem'); ?></a>
        <a href="?p=<?php echo urlencode(FM_PATH); ?>&amp;upload"><i class="fa fa-cloud-upload"></i> <?php echo lng('Upload'); ?></a>
        <?php endif; ?>
        <a href="?<?php echo FM_STORAGE_TYPE === 'mega' ? 'mega_tools=1' : 'local_tools=1'; ?>&amp;p=<?php echo rawurlencode(FM_PATH); ?>"><i class="fa fa-search"></i> <?php echo lng('Search'); ?></a>
        <?php if (FM_STORAGE_TYPE === 'mega'): ?><a href="?mega_rubbish=1&amp;p="><i class="fa fa-trash-o" aria-hidden="true"></i> <?php echo lng('Rubbish Bin'); ?></a><?php endif; ?>
        <?php if (FM_STORAGE_TYPE === 'mega'): ?><a href="?mega_shared_links=1&amp;p=<?php echo rawurlencode(FM_PATH); ?>"><i class="fa fa-link" aria-hidden="true"></i> <?php echo lng('Shared Links'); ?></a><?php endif; ?>
        <?php if (!FM_READONLY): ?><a href="?p=<?php echo urlencode(FM_PATH); ?>&amp;settings=1"><i class="fa fa-cog"></i> <?php echo lng('Settings'); ?></a><?php endif; ?>
        <a href="<?php echo FM_STORAGE_TYPE === 'mega' ? '?mega_logout=1' : '?logout=1'; ?>"><i class="fa fa-sign-out"></i> <?php echo lng('Logout'); ?></a>
      </div>
    </div>
    <script>
    (function(){
      var trigger=document.querySelector('.mega-mobile-menu-trigger'),panel=document.getElementById('mega-mobile-menu');
      if(!trigger||!panel)return;
      function close(){panel.hidden=true;trigger.setAttribute('aria-expanded','false')}
      trigger.addEventListener('click',function(e){e.stopPropagation();var opening=panel.hidden;panel.hidden=!opening;trigger.setAttribute('aria-expanded',String(opening));});
      document.addEventListener('click',function(e){if(!panel.hidden&&!panel.contains(e.target)&&!trigger.contains(e.target))close()});
      document.addEventListener('keydown',function(e){if(e.key==='Escape')close()});
      panel.addEventListener('click',function(e){var button=e.target.closest('[data-bulk]');if(!button)return;var op=button.getAttribute('data-bulk');close();if(op==='copy'){var copy=document.getElementById('a-copy');if(copy)copy.click();}else if(typeof megaConfirmBulk==='function')megaConfirmBulk(op);});
      window.megaMobileUpdateMenu=function(count){var selected=panel.querySelector('.mega-mobile-selected-actions');if(selected){selected.hidden=count===0;selected.querySelector('.mega-mobile-selection-label').textContent=count+' '+<?php echo json_encode(html_entity_decode(lng('selected'), ENT_QUOTES, 'UTF-8'), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG); ?>;}};
    })();
    </script>
<?php
}

/**
 * Show alert message from session
 */
function fm_show_message()
{
    if (!isset($_SESSION[FM_SESSION_ID]['message'])) return;
    $status = isset($_SESSION[FM_SESSION_ID]['status']) ? $_SESSION[FM_SESSION_ID]['status'] : 'ok';
    $type = ($status === 'error' || $status === 'alert') ? 'error' : (($status === 'ok') ? 'success' : 'info');
    $message = $_SESSION[FM_SESSION_ID]['message'];
    $GLOBALS['fm_has_inline_conflict'] = true;
    // Messages generated by existing handlers may contain trusted formatting (<b>).
    echo '<div class="mega-inline-notice mega-inline-notice--' . $type . '" role="' . ($type === 'error' ? 'alert' : 'status') . '">' . $message . '</div>';
    unset($_SESSION[FM_SESSION_ID]['message'], $_SESSION[FM_SESSION_ID]['status']);
}

/**
 * Show page header in Login Form
 */
function fm_show_header_login()
{
    header("Content-Type: text/html; charset=utf-8");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
    header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
    header("Pragma: no-cache");

    global $favicon_path;
?>
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="<?php echo (FM_THEME == "dark") ? 'dark' : 'light' ?>">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <meta name="description" content="Web based File Manager in PHP, Manage your files efficiently and easily with Tiny File Manager">
        <meta name="author" content="CCP Programmers">
        <meta name="robots" content="noindex, nofollow">
        <meta name="googlebot" content="noindex">
        <?php if ($favicon_path) {
            echo '<link rel="icon" href="' . fm_enc($favicon_path) . '" type="image/png">';
        } ?>
        <title><?php echo fm_enc(APP_TITLE) ?></title>
        <?php print_external('pre-jsdelivr'); ?>
        <?php print_external('css-bootstrap'); ?>
        <style>
            body.fm-login-page {
                background-color: #f7f9fb;
                font-size: 14px;
                background-color: #f7f9fb;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 304 304' width='304' height='304'%3E%3Cpath fill='%23e2e9f1' fill-opacity='0.4' d='M44.1 224a5 5 0 1 1 0 2H0v-2h44.1zm160 48a5 5 0 1 1 0 2H82v-2h122.1zm57.8-46a5 5 0 1 1 0-2H304v2h-42.1zm0 16a5 5 0 1 1 0-2H304v2h-42.1zm6.2-114a5 5 0 1 1 0 2h-86.2a5 5 0 1 1 0-2h86.2zm-256-48a5 5 0 1 1 0 2H0v-2h12.1zm185.8 34a5 5 0 1 1 0-2h86.2a5 5 0 1 1 0 2h-86.2zM258 12.1a5 5 0 1 1-2 0V0h2v12.1zm-64 208a5 5 0 1 1-2 0v-54.2a5 5 0 1 1 2 0v54.2zm48-198.2V80h62v2h-64V21.9a5 5 0 1 1 2 0zm16 16V64h46v2h-48V37.9a5 5 0 1 1 2 0zm-128 96V208h16v12.1a5 5 0 1 1-2 0V210h-16v-76.1a5 5 0 1 1 2 0zm-5.9-21.9a5 5 0 1 1 0 2H114v48H85.9a5 5 0 1 1 0-2H112v-48h12.1zm-6.2 130a5 5 0 1 1 0-2H176v-74.1a5 5 0 1 1 2 0V242h-60.1zm-16-64a5 5 0 1 1 0-2H114v48h10.1a5 5 0 1 1 0 2H112v-48h-10.1zM66 284.1a5 5 0 1 1-2 0V274H50v30h-2v-32h18v12.1zM236.1 176a5 5 0 1 1 0 2H226v94h48v32h-2v-30h-48v-98h12.1zm25.8-30a5 5 0 1 1 0-2H274v44.1a5 5 0 1 1-2 0V146h-10.1zm-64 96a5 5 0 1 1 0-2H208v-80h16v-14h-42.1a5 5 0 1 1 0-2H226v18h-16v80h-12.1zm86.2-210a5 5 0 1 1 0 2H272V0h2v32h10.1zM98 101.9V146H53.9a5 5 0 1 1 0-2H96v-42.1a5 5 0 1 1 2 0zM53.9 34a5 5 0 1 1 0-2H80V0h2v34H53.9zm60.1 3.9V66H82v64H69.9a5 5 0 1 1 0-2H80V64h32V37.9a5 5 0 1 1 2 0zM101.9 82a5 5 0 1 1 0-2H128V37.9a5 5 0 1 1 2 0V82h-28.1zm16-64a5 5 0 1 1 0-2H146v44.1a5 5 0 1 1-2 0V18h-26.1zm102.2 270a5 5 0 1 1 0 2H98v14h-2v-16h124.1zM242 149.9V160h16v34h-16v62h48v48h-2v-46h-48v-66h16v-30h-16v-12.1a5 5 0 1 1 2 0zM53.9 18a5 5 0 1 1 0-2H64V2H48V0h18v18H53.9zm112 32a5 5 0 1 1 0-2H192V0h50v2h-48v48h-28.1zm-48-48a5 5 0 0 1-9.8-2h2.07a3 3 0 1 0 5.66 0H178v34h-18V21.9a5 5 0 1 1 2 0V32h14V2h-58.1zm0 96a5 5 0 1 1 0-2H137l32-32h39V21.9a5 5 0 1 1 2 0V66h-40.17l-32 32H117.9zm28.1 90.1a5 5 0 1 1-2 0v-76.51L175.59 80H224V21.9a5 5 0 1 1 2 0V82h-49.59L146 112.41v75.69zm16 32a5 5 0 1 1-2 0v-99.51L184.59 96H300.1a5 5 0 0 1 3.9-3.9v2.07a3 3 0 0 0 0 5.66v2.07a5 5 0 0 1-3.9-3.9H185.41L162 121.41v98.69zm-144-64a5 5 0 1 1-2 0v-3.51l48-48V48h32V0h2v50H66v55.41l-48 48v2.69zM50 53.9v43.51l-48 48V208h26.1a5 5 0 1 1 0 2H0v-65.41l48-48V53.9a5 5 0 1 1 2 0zm-16 16V89.41l-34 34v-2.82l32-32V69.9a5 5 0 1 1 2 0zM12.1 32a5 5 0 1 1 0 2H9.41L0 43.41V40.6L8.59 32h3.51zm265.8 18a5 5 0 1 1 0-2h18.69l7.41-7.41v2.82L297.41 50H277.9zm-16 160a5 5 0 1 1 0-2H288v-71.41l16-16v2.82l-14 14V210h-28.1zm-208 32a5 5 0 1 1 0-2H64v-22.59L40.59 194H21.9a5 5 0 1 1 0-2H41.41L66 216.59V242H53.9zm150.2 14a5 5 0 1 1 0 2H96v-56.6L56.6 162H37.9a5 5 0 1 1 0-2h19.5L98 200.6V256h106.1zm-150.2 2a5 5 0 1 1 0-2H80v-46.59L48.59 178H21.9a5 5 0 1 1 0-2H49.41L82 208.59V258H53.9zM34 39.8v1.61L9.41 66H0v-2h8.59L32 40.59V0h2v39.8zM2 300.1a5 5 0 0 1 3.9 3.9H3.83A3 3 0 0 0 0 302.17V256h18v48h-2v-46H2v42.1zM34 241v63h-2v-62H0v-2h34v1zM17 18H0v-2h16V0h2v18h-1zm273-2h14v2h-16V0h2v16zm-32 273v15h-2v-14h-14v14h-2v-16h18v1zM0 92.1A5.02 5.02 0 0 1 6 97a5 5 0 0 1-6 4.9v-2.07a3 3 0 1 0 0-5.66V92.1zM80 272h2v32h-2v-32zm37.9 32h-2.07a3 3 0 0 0-5.66 0h-2.07a5 5 0 0 1 9.8 0zM5.9 0A5.02 5.02 0 0 1 0 5.9V3.83A3 3 0 0 0 3.83 0H5.9zm294.2 0h2.07A3 3 0 0 0 304 3.83V5.9a5 5 0 0 1-3.9-5.9zm3.9 300.1v2.07a3 3 0 0 0-1.83 1.83h-2.07a5 5 0 0 1 3.9-3.9zM97 100a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-48 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 48a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 96a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-144a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-96 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm96 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-32 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM49 36a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-32 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM33 68a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-48a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 240a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm80-176a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 48a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm112 176a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-16 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM17 180a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm0-32a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM17 84a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm32 64a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm16-16a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'%3E%3C/path%3E%3C/svg%3E");
            }

            .fm-login-page .brand {
                width: 121px;
                overflow: hidden;
                margin: 0 auto;
                position: relative;
                z-index: 1
            }

            .fm-login-page .brand img {
                width: 100%
            }

            .fm-login-page .card-wrapper {
                width: 360px;
            }

            .fm-login-page .card {
                border-color: transparent;
                box-shadow: 0 4px 8px rgba(0, 0, 0, .05)
            }

            .fm-login-page .card-title {
                margin-bottom: 1.5rem;
                font-size: 24px;
                font-weight: 400;
            }

            .fm-login-page .form-control {
                border-width: 2.3px
            }

            .fm-login-page .form-group label {
                width: 100%
            }

            .fm-login-page .btn.btn-block {
                padding: 12px 10px
            }

            /* Match the file manager's clean Bootstrap action buttons. */
            .fm-login-page .fm-login-submit {
                min-height: 44px; border-radius: 8px; font-size: 16px;
                font-weight: 500; margin-top: 8px; padding: 10px 16px;
            }
            .fm-login-page .fm-login-password-wrap { position: relative; }
            .fm-login-page .fm-login-password-wrap .form-control { padding-right: 52px; }
            .fm-login-page .fm-password-toggle {
                position: absolute; right: 4px; top: 50%; transform: translateY(-50%);
                display: flex; align-items: center; justify-content: center;
                width: 44px; height: 42px; border: 0; background: transparent;
                color: var(--bs-secondary-color, #6c757d); border-radius: 6px;
                cursor: pointer; touch-action: manipulation;
            }
            .fm-login-page .fm-password-toggle:focus-visible { outline: 2px solid #0d6efd; outline-offset: -3px; }
            [data-bs-theme="dark"] body.fm-login-page { background-color: #171a1d; }
            .fm-login-page .footer {
                margin: 20px 0;
                color: #888;
                text-align: center
            }

            @media screen and (max-width:425px) {
                .fm-login-page .card-wrapper {
                    width: 90%;
                    margin: 0 auto;
                    margin-top: 10%;
                }
            }

            @media screen and (max-width:320px) {
                .fm-login-page .card.fat {
                    padding: 0
                }

                .fm-login-page .card.fat .card-body {
                    padding: 15px
                }
            }

            .message {
                padding: 4px 7px;
                border: 1px solid #ddd;
                background-color: #fff
            }

            .message.ok {
                border-color: green;
                color: green
            }

            .message.error {
                border-color: red;
                color: red
            }

            .message.alert {
                border-color: orange;
                color: orange
            }

            body.fm-login-page.theme-dark {
                background-color: #2f2a2a;
            }

            .theme-dark svg g,
            .theme-dark svg path {
                fill: #ffffff;
            }

            .theme-dark .form-control {
                color: #fff;
                background-color: #403e3e;
            }

            .h-100vh {
                min-height: 100vh;
            }
        </style>
    <style>.inline-actions .mega-row-download{display:inline-block;margin:0;padding:0;vertical-align:middle}.inline-actions .mega-download-action{display:inline-flex;align-items:center;justify-content:center;background:#3988b8;color:#fff;border:0;border-radius:3px;width:22px;height:21px;padding:0;cursor:pointer;font-size:14px;line-height:1;vertical-align:middle}.inline-actions .mega-download-action:hover{background:#286d99}.inline-actions .mega-download-action:focus-visible{outline:2px solid #0d6efd;outline-offset:2px}</style>
<style id="mega-ui-consistency-2026">
/* Centralized dark-mode UI tokens. No changes to file previews or document contents. */
body.theme-dark, html[data-bs-theme="dark"] body {
  --mega-ui-text:#f1f5f9;
  --mega-ui-muted:#cbd5e1;
  --mega-ui-surface:#242b31;
  --mega-ui-raised:#303a44;
  --mega-ui-hover:#3c4855;
  --mega-ui-border:#657382;
  --mega-ui-focus:#e2e8f0;
}
/* Consistent row actions; preserve colored destructive/success buttons outside row actions. */
body.theme-dark .inline-actions > a > i,
body.theme-dark .inline-actions .mega-download-action,
body.theme-dark .inline-actions button.mega-download-action {
  background:var(--mega-ui-raised)!important;
  border-color:var(--mega-ui-border)!important;
  color:var(--mega-ui-text)!important;
}
body.theme-dark .inline-actions > a:hover > i,
body.theme-dark .inline-actions .mega-download-action:hover {
  background:var(--mega-ui-hover)!important;
  color:#fff!important;
}
body.theme-dark .inline-actions .mega-download-action i {color:var(--mega-ui-text)!important;background:transparent!important}
/* Consistent folder navigation, breadcrumbs, parent row, and selection controls. */
body.theme-dark #main-table .filename a,
body.theme-dark #main-table .filename a i,
body.theme-dark #main-table .go-back,
body.theme-dark .fm-path-links a,
body.theme-dark .fm-path-links a i,
body.theme-dark #navbarSupportedContent .nav-link,
body.theme-dark #navbarSupportedContent .nav-link i {color:var(--mega-ui-text)!important}
body.theme-dark #main-table .custom-control-label::before {border-color:var(--mega-ui-muted)!important}
body.theme-dark #main-table .custom-control-input:disabled ~ .custom-control-label::before {opacity:.45!important}
/* Copy/Move destination picker: matching folder labels, boundaries and focus. */
body.theme-dark #mega-folder-picker #mega-folder-entries > button {
  color:var(--mega-ui-text)!important;
  border:1px solid var(--mega-ui-border)!important;
  background:var(--mega-ui-surface)!important;
}
body.theme-dark #mega-folder-picker #mega-folder-entries > button:hover,
body.theme-dark #mega-folder-picker #mega-folder-entries > button:focus-visible {
  border-color:var(--mega-ui-focus)!important;
  background:var(--mega-ui-hover)!important;
  color:#fff!important;
}
/* Neutral secondary controls and cancel/back actions in dialogs. */
body.theme-dark .modal .btn-secondary,
body.theme-dark .modal .btn-outline-secondary,
body.theme-dark .modal .btn-cancel,
body.theme-dark #mega-folder-picker .btn-secondary {
  color:var(--mega-ui-text)!important;
  background:var(--mega-ui-raised)!important;
  border-color:var(--mega-ui-border)!important;
}
body.theme-dark .modal .btn-secondary:hover,
body.theme-dark .modal .btn-outline-secondary:hover,
body.theme-dark .modal .btn-cancel:hover {
  color:#fff!important;
  background:var(--mega-ui-hover)!important;
}
body.theme-dark .modal-content,
body.theme-dark .modal-header,
body.theme-dark .modal-footer {border-color:var(--mega-ui-border)!important}
body.theme-dark .modal .form-control,
body.theme-dark .modal .custom-select {color:var(--mega-ui-text)!important;border-color:var(--mega-ui-border)!important}
body.theme-dark .modal .form-control:focus,
body.theme-dark #mega-folder-picker #mega-folder-entries > button:focus-visible {
  outline:2px solid var(--mega-ui-focus)!important;
  outline-offset:1px;
}
/* Prevent toolbar icons from shrinking inconsistently on narrow screens. */
body.theme-dark .inline-actions .mega-download-action {flex-shrink:0}
@media<?php echo fm_layout_media_query(); ?> {
  body.theme-dark .inline-actions {white-space:nowrap}
  body.theme-dark .modal-dialog {max-width:calc(100vw - 16px);margin:8px auto}
  body.theme-dark .modal-content {max-width:100%}
}

/* Consistency v2: all secondary controls, states, and accessible focus. */
body.theme-dark #mega-folder-picker .btn-outline-secondary,
body.theme-dark #mega-folder-picker #mega-folder-root,
body.theme-dark #mega-folder-picker #mega-folder-up,
body.theme-dark .modal .btn-light {
 color:var(--mega-ui-text)!important;background:var(--mega-ui-raised)!important;border-color:var(--mega-ui-border)!important;
}
body.theme-dark #mega-folder-picker button:disabled,
body.theme-dark .modal button:disabled,
body.theme-dark .inline-actions button:disabled {opacity:.5!important;cursor:not-allowed!important}
body.theme-dark .inline-actions > a:focus-visible,
body.theme-dark .inline-actions button:focus-visible,
body.theme-dark #mega-folder-picker button:focus-visible,
body.theme-dark .modal button:focus-visible {outline:2px solid var(--mega-ui-focus)!important;outline-offset:2px!important}
body.theme-dark #main-table .custom-control-input:focus ~ .custom-control-label::before {box-shadow:0 0 0 2px var(--mega-ui-focus)!important}
body.theme-dark .modal .text-muted,
body.theme-dark #mega-folder-picker .text-muted {color:var(--mega-ui-muted)!important}
@media<?php echo fm_layout_media_query(); ?>{body.theme-dark .modal-footer{display:flex;flex-wrap:wrap;gap:6px}body.theme-dark .modal-footer .btn{max-width:100%}}
</style>



<style id="mega-mobile-v50-header">
@media<?php echo fm_layout_media_query(); ?>{
 body .mega-mobile-header{position:sticky!important;top:0!important;z-index:1050!important;background:var(--bs-body-bg,#fff)!important;isolation:isolate;box-shadow:0 1px 3px #00000012}
 body .mega-mobile-crumbs{min-width:0!important;overflow:hidden!important}
 body .mega-mobile-crumb-links{display:flex;align-items:center;gap:5px;flex:0 1 auto;min-width:0;overflow-x:auto;white-space:nowrap;scrollbar-width:none;overscroll-behavior-x:contain}
 body .mega-mobile-crumb-links::-webkit-scrollbar{display:none}
 body .mega-mobile-crumb-links a{color:var(--bs-link-color,#1670b8);text-decoration:none;white-space:nowrap;flex:0 0 auto}
 body .mega-mobile-crumb-links a:last-child{font-weight:500}
 body .mega-crumb-separator{color:var(--bs-secondary-color,#777);flex:0 0 auto;margin-inline:3px}
 body .mega-mobile-menu:not([hidden]){position:absolute;top:calc(100% - 3px)!important;z-index:1100!important}
}
</style>

<style id="mega-mobile-v51-fixed-header">
.mega-mobile-header-spacer{display:none}
@media<?php echo fm_layout_media_query(); ?>{
 body .mega-mobile-header-spacer{display:block!important;height:66px!important;min-height:66px!important}
 body .mega-mobile-header{position:fixed!important;top:0!important;left:0!important;right:0!important;width:100%!important;box-sizing:border-box!important;z-index:1060!important;margin:0!important;padding:6px 12px!important;min-height:66px!important;background:var(--bs-body-bg,#fff)!important;box-shadow:0 1px 3px #00000016!important}
 body .mega-mobile-heading{margin-left:0!important;padding-left:0!important}
 body .mega-mobile-heading-line strong{font-size:16px!important}
 body .mega-mobile-menu:not([hidden]){z-index:1070!important}
 body .mega-view-controls #mega-select-toggle{color:var(--bs-body-color,#202832)!important;opacity:1!important;visibility:visible!important;text-shadow:none!important;background:transparent!important;-webkit-text-fill-color:currentColor!important;min-width:90px!important;text-align:left!important;font-weight:500!important}
 body.theme-dark .mega-view-controls #mega-select-toggle{color:#e8edf4!important}
}
</style>
<style id="mega-mobile-v55-final-fixes">
@media screen and <?php echo fm_layout_media_query(); ?>{
 /* Align selection label with the file list checkbox column. */
 html body .mega-view-controls{padding-left:15px!important;padding-right:10px!important;justify-content:space-between!important}
 html body .mega-view-controls #mega-select-toggle{margin-left:0!important;margin-right:auto!important;padding:3px 0!important;min-width:0!important;flex:0 0 auto!important;text-align:left!important}
 /* Sorting arrow stays visible and black in all interaction states. */
 html body .mega-view-controls #mega-sort-direction,
 html body .mega-view-controls #mega-sort-direction:hover,
 html body .mega-view-controls #mega-sort-direction:focus,
 html body .mega-view-controls #mega-sort-direction:active,
 html body .mega-view-controls #mega-sort-direction:disabled,
 html body .mega-view-controls #mega-sort-direction.active{
  color:var(--bs-body-color,#212529)!important;-webkit-text-fill-color:currentColor!important;opacity:1!important;visibility:visible!important;
  background:transparent!important;text-shadow:none!important;box-shadow:none!important;
  min-width:38px!important;flex:0 0 38px!important;font-weight:700!important;
 }
 /* Whole statistics row, not just its badges, is white. */
 html body #main-table tfoot,html body #main-table tfoot tr,
 html body #main-table tfoot td{background:#fff!important;background-color:#fff!important}
 html body .mega-preview-actions .mega-preview-cancel{order:-1!important}
 html body .mega-preview-cancel-desktop{display:none!important}
}
@media screen and <?php echo fm_desktop_media_query(); ?>{.mega-preview-cancel-mobile{display:none!important}}
</style>

<style id="mega-mobile-v61-unified-two-actions-and-statistics">
@media<?php echo fm_layout_media_query(); ?>{
  /* Keep the entire statistics strip white, without horizontal rules. */
  html body.mega-mobile-list #main-table tfoot,
  html body.mega-mobile-list #main-table tfoot tr,
  html body.mega-mobile-list #main-table tfoot td{
    background:#fff!important;background-color:#fff!important;
    border:0!important;border-top:0!important;border-bottom:0!important;
    box-shadow:none!important;outline:0!important;
  }
  html body.mega-mobile-list #main-table tfoot tr::before{
    background:#fff!important;top:0!important;bottom:0!important;
    border:0!important;box-shadow:none!important;
  }
  html body.mega-mobile-list #main-table tfoot tr::after,
  html body.mega-mobile-list #main-table tfoot td::before,
  html body.mega-mobile-list #main-table tfoot td::after{border:0!important;box-shadow:none!important;}
  html body.mega-mobile-list #main-table tfoot td{padding-top:5px!important;padding-bottom:5px!important;}
  html body .mega-two-action-row{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:10px!important;width:100%!important;}
  html body .mega-two-action-row>.btn{display:flex!important;align-items:center!important;justify-content:center!important;width:100%!important;min-width:0!important;margin:0!important;white-space:nowrap!important;min-height:46px!important;}
  html body .mega-two-action-row>.btn:last-child{background:#0d6efd!important;border-color:#0d6efd!important;color:#fff!important;}
}
</style>
<style id="mega-mobile-v62-footer-final-override">
@media<?php echo fm_layout_media_query(); ?>{
 html body.mega-mobile-list #main-table tbody tr:last-child{border-bottom:0!important}
 html body.mega-mobile-list #main-table tfoot tr,
 html body.mega-mobile-list #main-table tfoot td{--bs-table-border-color:transparent!important;box-shadow:none!important;border:0!important;outline:0!important}
}
</style>

</head>

    <body class="fm-login-page <?php echo (FM_THEME == "dark") ? 'theme-dark' : ''; ?>">
        <div id="wrapper" class="container-fluid">

        <?php
    }

    /**
     * Show page footer in Login Form
     */
    function fm_show_footer_login()
    {
        ?>
        </div>
        <?php print_external('js-jquery'); ?>
        <?php print_external('js-bootstrap'); ?>
    <script>
            /* Match the content offset to the real fixed header height, including
               wrapped breadcrumbs and the expanded mobile navigation. */
            (function () {
                function updateFixedNavHeight() {
                    var nav = document.querySelector('.main-nav.fixed-top');
                    if (!nav) return;
                    var height = Math.ceil(nav.getBoundingClientRect().height);
                    if (height > 0) document.documentElement.style.setProperty('--fm-nav-height', height + 'px');
                }
                document.addEventListener('DOMContentLoaded', function () {
                    updateFixedNavHeight();
                    var nav = document.querySelector('.main-nav.fixed-top');
                    if (nav && window.ResizeObserver) {
                        new ResizeObserver(updateFixedNavHeight).observe(nav);
                    }
                    window.addEventListener('resize', updateFixedNavHeight);
                    if (nav) nav.addEventListener('transitionend', updateFixedNavHeight);
                });
            })();
</script>


<script>
/* Common notification renderer; textContent prevents HTML injection from API errors. */
window.megaNotify = function(type, message, container) {
    var parent = container || document.querySelector('.mega-notification-area') || document.querySelector('main') || document.body;
    var note = document.createElement('div');
    note.className = 'mega-inline-notice mega-inline-notice--' + (['error','success','warning','info'].indexOf(type) >= 0 ? type : 'info');
    note.setAttribute('role', type === 'error' ? 'alert' : 'status');
    note.textContent = String(message);
    parent.appendChild(note);
    if (window.megaNoticeSchedule) window.megaNoticeSchedule(note);
    return note;
};
window.megaShowNotice = window.megaNotify;
</script>
<script>
/* One shared auto-dismiss controller for all inline operation results. */
(function () {
    'use strict';
    window.MEGA_NOTICE_DURATION_MS = 5000;
    var delay = window.MEGA_NOTICE_DURATION_MS;
    var timers = typeof WeakMap !== 'undefined' ? new WeakMap() : null;
    function schedule(note) {
        if (!note || !note.classList || !note.classList.contains('mega-inline-notice')) return;
        if (timers && timers.has(note)) clearTimeout(timers.get(note));
        if (note.hidden || note.style.display === 'none') return;
        var timer = setTimeout(function () {
            note.hidden = true;
            note.style.display = 'none';
            if (timers) timers.delete(note);
        }, delay);
        if (timers) timers.set(note, timer);
    }
    window.megaNoticeSchedule = schedule;
    function scan(root) {
        if (!root || root.nodeType !== 1) return;
        if (root.matches && root.matches('.mega-inline-notice')) schedule(root);
        if (root.querySelectorAll) {
            var notes = root.querySelectorAll('.mega-inline-notice');
            for (var i = 0; i < notes.length; i++) schedule(notes[i]);
        }
    }
    function start() {
        scan(document.body);
        if (typeof MutationObserver === 'undefined') return;
        var observer = new MutationObserver(function (records) {
            for (var i = 0; i < records.length; i++) {
                var record = records[i];
                if (record.type === 'childList') {
                    for (var j = 0; j < record.addedNodes.length; j++) scan(record.addedNodes[j]);
                    if (record.target && record.target.closest) {
                        var parent = record.target.closest('.mega-inline-notice');
                        if (parent) schedule(parent);
                    }
                } else if (record.type === 'characterData' && record.target.parentElement) {
                    var note = record.target.parentElement.closest('.mega-inline-notice');
                    if (note) schedule(note);
                }
            }
        });
        observer.observe(document.body, {childList:true, subtree:true, characterData:true});
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
}());
</script>
<script>
/* Custom localized validation for the New Item form. Native validation bubbles
   are localized by the browser UI, not the website's language preference. */
(function(){
 var msg = <?php echo json_encode(html_entity_decode(lng('Please fill out this field.'), ENT_QUOTES, 'UTF-8'), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG); ?>;
 var form=document.getElementById('mega-new-item-form');
 if(!form)return;
 var field=document.getElementById('newfilename');
 if(!field)return;
 var note=document.createElement('div');
 note.setAttribute('role','alert');
 note.style.cssText='display:none;color:#b42318;margin-top:8px;font-size:.95rem';
 note.textContent=msg;
 field.insertAdjacentElement('afterend',note);
 form.addEventListener('submit',function(e){
   if(!field.value.trim()){
     e.preventDefault();e.stopImmediatePropagation();
     note.style.display='block';field.setAttribute('aria-invalid','true');field.focus();
   }
 },true);
 field.addEventListener('input',function(){note.style.display='none';field.removeAttribute('aria-invalid');});
})();
</script>

</body>

    </html>

<?php
    }

    /**
     * Show Header after login
     */
    function fm_show_header()
    {
        header("Content-Type: text/html; charset=utf-8");
        header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
        header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
        header("Pragma: no-cache");

        global $sticky_navbar, $favicon_path;
        $isStickyNavBar = $sticky_navbar ? 'navbar-fixed' : 'navbar-normal';
?>
    <!DOCTYPE html>
    <html data-bs-theme="<?php echo FM_THEME; ?>">

    <head>
        <script>
        window.FM_STORAGE_TYPE = <?php echo json_encode(FM_STORAGE_TYPE); ?>;
        window.megaPrefsCookieName = <?php echo json_encode($GLOBALS['mega_pref_cookie']); ?>;
        window.megaPrefsStorageKey = <?php echo json_encode($GLOBALS['mega_pref_storage']); ?>;
        window.megaPrefsCookiePath = <?php echo json_encode(rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/') . '/'); ?>;
        // Restore browser preferences if cookies were cleared independently.
        (function () {
            try {
                var stored = localStorage.getItem(window.megaPrefsStorageKey);
                if (stored && !document.cookie.split('; ').some(function (part) { return part.indexOf(window.megaPrefsCookieName + '=') === 0; })) {
                    var p = JSON.parse(stored);
                    if (p && (p.theme === 'light' || p.theme === 'dark') && typeof p.show_hidden === 'boolean') {
                        document.documentElement.setAttribute('data-bs-theme', p.theme);
                        document.cookie = window.megaPrefsCookieName + '=' + encodeURIComponent(JSON.stringify(p)) +
                            '; path=' + window.megaPrefsCookiePath + '; max-age=31536000; SameSite=Lax' +
                            (location.protocol === 'https:' ? '; Secure' : '');
                        if (!sessionStorage.getItem('mega_prefs_restored')) {
                            sessionStorage.setItem('mega_prefs_restored', '1');
                            location.reload();
                        }
                    }
                } else sessionStorage.removeItem('mega_prefs_restored');
            } catch (e) { /* Browser storage can be disabled. */ }
        }());
        </script>
        <meta charset="utf-8">
        <meta name="viewport" content="<?php echo (FM_VIEW_MODE === 'desktop' || (FM_VIEW_MODE === 'auto' && FM_AUTO_DESKTOP)) ? 'width=1280' : 'width=device-width, initial-scale=1, shrink-to-fit=no'; ?>">
        <meta name="description" content="Web based File Manager in PHP, Manage your files efficiently and easily with Tiny File Manager">
        <meta name="author" content="CCP Programmers">
        <meta name="robots" content="noindex, nofollow">
        <meta name="googlebot" content="noindex">
        <?php if ($favicon_path) {
            echo '<link rel="icon" href="' . fm_enc($favicon_path) . '" type="image/png">';
        } ?>
        <title><?php echo fm_enc(APP_TITLE) ?> | <?php echo (isset($_GET['view']) ? $_GET['view'] : ((isset($_GET['edit'])) ? $_GET['edit'] : "H3K")); ?></title>
        <?php print_external('pre-jsdelivr'); ?>
        <?php print_external('pre-cloudflare'); ?>
        <?php print_external('css-bootstrap'); ?>
        <?php print_external('css-font-awesome'); ?>
        <?php if (FM_USE_HIGHLIGHTJS && isset($_GET['view'])): ?>
            <?php print_external('css-highlightjs'); ?>
        <?php endif; ?>
        <script type="text/javascript">
            window.csrf = '<?php echo $_SESSION['token']; ?>';
        </script>
        <style>
            html {
                -moz-osx-font-smoothing: grayscale;
                -webkit-font-smoothing: antialiased;
                text-rendering: optimizeLegibility;
                height: 100%;
                scroll-behavior: smooth;
            }

            *,
            *::before,
            *::after {
                box-sizing: border-box;
            }

            body {
                font-size: 15px;
                color: #222;
                background: #F7F7F7;
            }

            /* Reserve the actual height of the fixed navigation on every page.
               The navigation height changes on mobile and when its menu opens. */
            body.navbar-fixed {
                margin-top: 0;
                padding-top: calc(var(--fm-nav-height, 120px) + 8px);
            }
            body.navbar-fixed #wrapper > .path,
            body.navbar-fixed #wrapper > .col-md-8,
            body.navbar-fixed #wrapper > .container,
            body.navbar-fixed #wrapper > .container-fluid,
            body.navbar-fixed #wrapper > form,
            body.navbar-fixed #wrapper > .fm-page-content {
                margin-top: 0 !important;
            }

            a,
            a:hover,
            a:visited,
            a:focus {
                text-decoration: none !important;
            }

            .filename,
            td,
            th {
                white-space: nowrap
            }

            .navbar-brand {
                font-weight: bold;
            }

            .nav-item.avatar a {
                cursor: pointer;
                text-transform: capitalize;
            }

            .nav-item.avatar a>i {
                font-size: 15px;
            }

            .nav-item.avatar .dropdown-menu a {
                font-size: 13px;
            }

            #search-addon {
                font-size: 12px;
                border-right-width: 0;
            }

            .brl-0 {
                background: transparent;
                border-left: 0;
                border-top-left-radius: 0;
                border-bottom-left-radius: 0;
            }

            .brr-0 {
                border-top-right-radius: 0;
                border-bottom-right-radius: 0;
            }

            .bread-crumb {
                color: #cccccc;
                font-style: normal;
            }

            #main-table {
                transition: transform .25s cubic-bezier(0.4, 0.5, 0, 1), width 0s .25s;
            }

            #main-table .filename a {
                color: #222222;
            }

            .table td,
            .table th {
                vertical-align: middle !important;
            }

            .table .custom-checkbox-td .custom-control.custom-checkbox,
            .table .custom-checkbox-header .custom-control.custom-checkbox {
                min-width: 18px;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .table-sm td,
            .table-sm th {
                padding: .4rem;
            }

            .table-bordered td,
            .table-bordered th {
                border: 1px solid #f1f1f1;
            }

            .hidden {
                display: none
            }

            pre.with-hljs {
                padding: 0;
                overflow: hidden;
            }

            pre.with-hljs code {
                margin: 0;
                border: 0;
                overflow: scroll;
            }

            code.maxheight,
            pre.maxheight {
                max-height: 512px
            }

            .fa.fa-caret-right {
                font-size: 1.2em;
                margin: 0 4px;
                vertical-align: middle;
                color: #ececec
            }

            .fa.fa-home {
                font-size: 1.3em;
                vertical-align: bottom
            }

            .path {
                margin-bottom: 10px
            }

            form.dropzone {
                min-height: 200px;
                border: 2px dashed #007bff;
                line-height: 6rem;
            }

            .right {
                text-align: right
            }

            .center,
            .close,
            .login-form,
            .preview-img-container {
                text-align: center
            }

            .message {
                padding: 4px 7px;
                border: 1px solid #ddd;
                background-color: #fff
            }

            .message.ok {
                border-color: green;
                color: green
            }

            .message.error {
                border-color: red;
                color: red
            }

            .message.alert {
                border-color: orange;
                color: orange
            }

            .preview-img {
                max-width: 100%;
                max-height: 80vh;
                background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAKklEQVR42mL5//8/Azbw+PFjrOJMDCSCUQ3EABZc4S0rKzsaSvTTABBgAMyfCMsY4B9iAAAAAElFTkSuQmCC);
                cursor: zoom-in
            }

            input#preview-img-zoomCheck[type=checkbox] {
                display: none
            }

            input#preview-img-zoomCheck[type=checkbox]:checked~label>img {
                max-width: none;
                max-height: none;
                cursor: zoom-out
            }

            .inline-actions>a>i {
                font-size: 1em;
                margin-left: 5px;
                background: #3785c1;
                color: #fff;
                padding: 3px 4px;
                border-radius: 3px;
            }

            .preview-video {
                position: relative;
                max-width: 100%;
                height: 0;
                padding-bottom: 62.5%;
                margin-bottom: 10px
            }

            .preview-video video {
                position: absolute;
                width: 100%;
                height: 100%;
                left: 0;
                top: 0;
                background: #000
            }

            .compact-table {
                border: 0;
                width: auto
            }

            .compact-table td,
            .compact-table th {
                width: 100px;
                border: 0;
                text-align: center
            }

            .compact-table tr:hover td {
                background-color: #fff
            }

            .filename {
                max-width: 420px;
                overflow: hidden;
                text-overflow: ellipsis
            }

            .break-word {
                word-wrap: break-word;
                margin-left: 30px
            }

            .break-word.float-left a {
                color: #7d7d7d
            }

            .break-word+.float-right {
                padding-right: 30px;
                position: relative
            }

            .break-word+.float-right>a {
                color: #7d7d7d;
                font-size: 1.2em;
                margin-right: 4px
            }

            #editor {
                position: absolute;
                right: 15px;
                top: 100px;
                bottom: 15px;
                left: 15px
            }

            @media (max-width:481px) {
                #editor {
                    top: 150px;
                }
            }

            #normal-editor {
                border-radius: 3px;
                border-width: 2px;
                padding: 10px;
                outline: none;
            }

            .btn-2 {
                padding: 4px 10px;
                font-size: small;
            }

            li.file:before,
            li.folder:before {
                font: normal normal normal 14px/1 FontAwesome;
                content: "\f016";
                margin-right: 5px
            }

            li.folder:before {
                content: "\f114"
            }

            i.fa.fa-folder-o {
                color: #0157b3
            }

            i.fa.fa-picture-o {
                color: #26b99a
            }

            i.fa.fa-file-archive-o {
                color: #da7d7d
            }

            .btn-2 i.fa.fa-file-archive-o {
                color: inherit
            }

            i.fa.fa-css3 {
                color: #f36fa0
            }

            i.fa.fa-file-code-o {
                color: #007bff
            }

            i.fa.fa-code {
                color: #cc4b4c
            }

            i.fa.fa-file-text-o {
                color: #0096e6
            }

            i.fa.fa-html5 {
                color: #d75e72
            }

            i.fa.fa-file-excel-o {
                color: #09c55d
            }

            i.fa.fa-file-powerpoint-o {
                color: #f6712e
            }

            i.go-back {
                font-size: 1.2em;
                color: #007bff;
            }

            .main-nav {
                padding: 0.2rem 1rem;
                box-shadow: 0 4px 5px 0 rgba(0, 0, 0, .14), 0 1px 10px 0 rgba(0, 0, 0, .12), 0 2px 4px -1px rgba(0, 0, 0, .2)
            }

            .dataTables_filter {
                display: none;
            }

            table.dataTable thead .sorting {
                cursor: pointer;
                background-repeat: no-repeat;
                background-position: center right;
                background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAQAAADYWf5HAAAAkElEQVQoz7XQMQ5AQBCF4dWQSJxC5wwax1Cq1e7BAdxD5SL+Tq/QCM1oNiJidwox0355mXnG/DrEtIQ6azioNZQxI0ykPhTQIwhCR+BmBYtlK7kLJYwWCcJA9M4qdrZrd8pPjZWPtOqdRQy320YSV17OatFC4euts6z39GYMKRPCTKY9UnPQ6P+GtMRfGtPnBCiqhAeJPmkqAAAAAElFTkSuQmCC');
            }

            table.dataTable thead .sorting_asc {
                cursor: pointer;
                background-repeat: no-repeat;
                background-position: center right;
                background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAYAAAByUDbMAAAAZ0lEQVQ4y2NgGLKgquEuFxBPAGI2ahhWCsS/gDibUoO0gPgxEP8H4ttArEyuQYxAPBdqEAxPBImTY5gjEL9DM+wTENuQahAvEO9DMwiGdwAxOymGJQLxTyD+jgWDxCMZRsEoGAVoAADeemwtPcZI2wAAAABJRU5ErkJggg==');
            }

            table.dataTable thead .sorting_desc {
                cursor: pointer;
                background-repeat: no-repeat;
                background-position: center right;
                background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAYAAAByUDbMAAAAZUlEQVQ4y2NgGAWjYBSggaqGu5FA/BOIv2PBIPFEUgxjB+IdQPwfC94HxLykus4GiD+hGfQOiB3J8SojEE9EM2wuSJzcsFMG4ttQgx4DsRalkZENxL+AuJQaMcsGxBOAmGvopk8AVz1sLZgg0bsAAAAASUVORK5CYII=');
            }

            table.dataTable thead tr:first-child th.custom-checkbox-header:first-child {
                background-image: none;
            }

            .footer-action li {
                margin-bottom: 10px;
            }

            .app-v-title {
                font-size: 24px;
                font-weight: 300;
                letter-spacing: -.5px;
                text-transform: uppercase;
            }

            hr.custom-hr {
                border-top: 1px dashed #8c8b8b;
                border-bottom: 1px dashed #fff;
            }

            #snackbar {
                visibility: hidden;
                min-width: 250px;
                margin-left: -125px;
                background-color: #333;
                color: #fff;
                text-align: center;
                border-radius: 2px;
                padding: 16px;
                position: fixed;
                z-index: 1;
                left: 50%;
                bottom: 30px;
                font-size: 17px;
            }

            #snackbar.show {
                visibility: visible;
                -webkit-animation: fadein 0.5s, fadeout 0.5s 2.5s;
                animation: fadein 0.5s, fadeout 0.5s 2.5s;
            }

            @-webkit-keyframes fadein {
                from {
                    bottom: 0;
                    opacity: 0;
                }

                to {
                    bottom: 30px;
                    opacity: 1;
                }
            }

            @keyframes fadein {
                from {
                    bottom: 0;
                    opacity: 0;
                }

                to {
                    bottom: 30px;
                    opacity: 1;
                }
            }

            @-webkit-keyframes fadeout {
                from {
                    bottom: 30px;
                    opacity: 1;
                }

                to {
                    bottom: 0;
                    opacity: 0;
                }
            }

            @keyframes fadeout {
                from {
                    bottom: 30px;
                    opacity: 1;
                }

                to {
                    bottom: 0;
                    opacity: 0;
                }
            }

            :is(#main-table,#mega-trash-table) span.badge {
                border-bottom: 2px solid #f8f9fa
            }

            :is(#main-table,#mega-trash-table) span.badge:nth-child(1) {
                border-color: #df4227
            }

            :is(#main-table,#mega-trash-table) span.badge:nth-child(2) {
                border-color: #f8b600
            }


            /* Single compact gap after the fixed header; no duplicated page margins. */
            body.navbar-fixed #wrapper > .path,
            body.navbar-fixed #wrapper > .col-md-8,
            body.navbar-fixed #wrapper > .container,
            body.navbar-fixed #wrapper > .container-fluid,
            body.navbar-fixed #wrapper > form,
            body.navbar-fixed #wrapper > .fm-page-content {
                margin-top: 0 !important;
            }
            .fm-file-list { margin-top: 0; }
            .fm-page-content { padding-left: 12px; padding-right: 12px; }
            .fm-new-item-card { max-width: 760px; margin: 0 auto; }
            /* Upload header: Back stays in its own row, never overlaps Dropzone. */
            .fm-upload-destination { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; min-height:44px; margin-bottom:18px; }
            .fm-upload-destination .fm-upload-back { order:2; margin-left:auto; flex-shrink:0; float:none !important; }
            #fileUploader { clear:both; margin-top:0; }
            /* URL form: full-width input, centered action. */
            .fm-url-upload-form { display:flex; flex-direction:column; align-items:stretch; gap:16px; width:100%; max-width:100%; }
            .fm-url-upload-form .fm-url-input { display:block; width:100% !important; max-width:100%; box-sizing:border-box; }
            .fm-url-upload-form .fm-url-submit { align-self:center; width:min(100%, 260px); margin:0 !important; }
            .fm-url-upload-form .lds-facebook { align-self:center; }
            .fm-upload-back { border-radius: 9px; padding: 8px 14px; font-weight: 500; }
            .fm-upload-back:hover { background: var(--bs-secondary-bg); }
            /* v53: one shared two-column action layout across file, URL and search pages. */
            .fm-unified-actions { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; width:100%; margin-top:14px; }
            .fm-unified-actions .fm-unified-button { display:flex; align-items:center; justify-content:center; gap:8px; width:100% !important; min-width:0 !important; max-width:none !important; min-height:44px; margin:0 !important; padding:9px 12px; border-radius:9px; font-weight:500; text-align:center; box-sizing:border-box; }
            .fm-file-upload-actions { grid-template-columns:minmax(0,1fr); }
            /* v54: label and path stay adjacent; no flex space-between. */
            .fm-upload-destination { display:flex; align-items:baseline; justify-content:flex-start; flex-wrap:wrap; column-gap:4px; row-gap:2px; min-height:0; margin-bottom:14px; }
            .fm-upload-destination strong { flex:0 0 auto; }
            .fm-destination-value { min-width:0; overflow-wrap:anywhere; }
            .fm-new-item-destination { margin-bottom:16px; }
            /* Bootstrap .hidden must also hide the file-only cancel row. */
            .fm-file-upload-actions.hidden { display:none !important; }
            .fm-url-upload-form .fm-url-actions { align-self:stretch; }
            .fm-url-upload-form .fm-url-submit { align-self:auto; }
            .mega-search-form .mega-search-actions { flex:0 0 100%; }
            @media (max-width:520px) { .mega-search-form .mega-search-actions .fm-unified-button { width:100% !important; } }
            /* Fixed visual order: title, toggle, breadcrumbs, expanded menu. */
            .main-nav > .fm-title-quota { order: 1; }
            .main-nav > .navbar-toggler { order: 2; margin-left:auto; }
            .main-nav > .fm-always-visible-path { order: 3; }
            .main-nav > #navbarSupportedContent { order: 4; flex-basis:100%; }
            .fm-title-quota { display:flex; align-items:center; gap:8px; min-width:0; flex-wrap:wrap; }
            .fm-title-quota .navbar-brand { margin-right:0; }
            .fm-quota { font-size:12px; color:var(--bs-secondary-color,#666); white-space:nowrap; }
            @media (max-width: 575px) { .fm-title-quota .navbar-brand { font-size:1.2rem; } .fm-quota { font-size:11px; } }
            /* Keep MEGA breadcrumbs visible outside the mobile collapse menu. */
            .fm-always-visible-path {
                flex-basis: 100%;
                order: 3;
                min-width: 0;
                padding: 6px 0 2px;
                overflow-x: auto;
                white-space: nowrap;
                scrollbar-width: thin;
            }
            .fm-path-links { display: inline-block; }
            .fm-path-links a { display: inline-block; }
            @media <?php echo fm_desktop_media_query(); ?> {
                .fm-always-visible-path { order: 3; flex-basis: auto; flex-grow: 1; padding: 0 12px; }
                #navbarSupportedContent { flex-grow: 0; flex-basis:auto; }
            }

            :is(#main-table,#mega-trash-table) span.badge:nth-child(3) {
                border-color: #00bd60
            }

            :is(#main-table,#mega-trash-table) span.badge:nth-child(4) {
                border-color: #4581ff
            }

            :is(#main-table,#mega-trash-table) span.badge:nth-child(5) {
                border-color: #ac68fc
            }

            :is(#main-table,#mega-trash-table) span.badge:nth-child(6) {
                border-color: #45c3d2
            }

            @media only screen and (min-device-width:768px) and (max-device-width:1024px) and (orientation:landscape) and (-webkit-min-device-pixel-ratio:2) {
                .navbar-collapse .col-xs-6 {
                    padding: 0;
                }
            }

            .btn.active.focus,
            .btn.active:focus,
            .btn.focus,
            .btn.focus:active,
            .btn:active:focus,
            .btn:focus {
                outline: 0 !important;
                outline-offset: 0 !important;
                background-image: none !important;
                -webkit-box-shadow: none !important;
                box-shadow: none !important
            }

            .lds-facebook {
                display: none;
                position: relative;
                width: 64px;
                height: 64px
            }

            .lds-facebook div,
            .lds-facebook.show-me {
                display: inline-block
            }

            .lds-facebook div {
                position: absolute;
                left: 6px;
                width: 13px;
                background: #007bff;
                animation: lds-facebook 1.2s cubic-bezier(0, .5, .5, 1) infinite
            }

            .lds-facebook div:nth-child(1) {
                left: 6px;
                animation-delay: -.24s
            }

            .lds-facebook div:nth-child(2) {
                left: 26px;
                animation-delay: -.12s
            }

            .lds-facebook div:nth-child(3) {
                left: 45px;
                animation-delay: 0s
            }

            @keyframes lds-facebook {
                0% {
                    top: 6px;
                    height: 51px
                }

                100%,
                50% {
                    top: 19px;
                    height: 26px
                }
            }

            ul#search-wrapper {
                padding-left: 0;
                border: 1px solid #ecececcc;
            }

            ul#search-wrapper li {
                list-style: none;
                padding: 5px;
                border-bottom: 1px solid #ecececcc;
            }

            ul#search-wrapper li:nth-child(odd) {
                background: #f9f9f9cc;
            }

            .c-preview-img {
                max-width: 300px;
            }

            .border-radius-0 {
                border-radius: 0;
            }

            .float-right {
                float: right;
            }

            .table-hover>tbody>tr:hover>td:first-child {
                border-left: 1px solid #1b77fd;
            }

            #main-table tr.even {
                background-color: #F8F9Fa;
            }

            .filename>a>i {
                margin-right: 3px;
            }

            .fs-7 {
                font-size: 14px;
            }
        
/* Search uses the shared header/nav/breadcrumb; only content styling is local. */

/* v109: one centered Close action at every viewport size. */
html body .mega-search-page .mega-rubbish-close {
  display:flex!important; justify-content:center!important; width:100%;
}
html body .mega-search-page .mega-rubbish-close > .fm-unified-button {
  flex:0 1 240px; width:100%!important; max-width:240px!important;
}
.mega-search-page{margin:0 auto 24px;padding-left:12px;padding-right:12px}
.mega-search-card{max-width:760px;margin:0 auto;border-radius:var(--bs-card-border-radius,6px);box-shadow:none}
.mega-search-card .card-body{padding:var(--bs-card-spacer-y,1rem) var(--bs-card-spacer-x,1rem)}
.mega-search-card .card-header{font-size:1rem;font-weight:400;line-height:1.5}.mega-search-card .card-header .fa{margin-right:4px}
.mega-search-scope{font-size:.95rem;overflow-wrap:anywhere}
.mega-search-form{display:flex;gap:10px;flex-wrap:wrap}
.mega-search-options{display:flex;align-items:center;gap:18px;flex-basis:100%;flex-wrap:wrap}
.mega-search-option{display:inline-flex;align-items:center;gap:7px;cursor:pointer;white-space:nowrap}
.mega-search-option input{width:17px;height:17px;accent-color:#2176bf}
.mega-search-form .form-control{min-width:0;flex:1;border-radius:9px;padding:12px}
.mega-search-form .btn{min-width:120px;border-radius:9px}
.mega-search-results{display:grid;gap:10px}
.mega-search-result{display:flex;align-items:center;gap:12px;padding:12px;border:1px solid var(--bs-border-color,#e2e6eb);border-radius:12px;min-width:0}
.mega-search-file-icon{flex:0 0 38px;height:38px;display:flex;align-items:center;justify-content:center;border-radius:10px;background:rgba(33,118,191,.1);color:#2176bf;font-size:21px}
.mega-search-detail{flex:1;min-width:0}.mega-search-filename{font-weight:600;overflow-wrap:anywhere}.mega-search-folder{font-size:.875rem;margin-top:3px;overflow-wrap:anywhere}
.mega-search-size{font-size:.875rem;color:var(--bs-secondary-color,#697482);white-space:nowrap}
.mega-search-empty{padding:24px;border:1px dashed var(--bs-border-color,#cbd5df);border-radius:12px;text-align:center}
@media(max-width:520px){.mega-search-page{padding:0 12px}.mega-search-card .card-body{padding:16px}.mega-search-form{flex-direction:column}.mega-search-form .btn{width:100%}.mega-search-result{align-items:flex-start}}
</style>
        <?php
        if (FM_THEME == "dark"): ?>
            <style>
                :root {
                    --bs-bg-opacity: 1;
                    --bg-color: #f3daa6;
                    --bs-dark-rgb: 28, 36, 41 !important;
                    --bs-bg-opacity: 1;
                }

                body.theme-dark {
                    background-image: linear-gradient(90deg, #1c2429, #263238);
                    color: #CFD8DC;
                }

                .list-group .list-group-item {
                    background: #343a40;
                }

                .theme-dark .navbar-nav i,
                .navbar-nav .dropdown-toggle,
                .break-word {
                    color: #CFD8DC;
                }

                a,
                a:hover,
                a:visited,
                a:active,
                #main-table .filename a,
                i.fa.fa-folder-o,
                i.go-back {
                    color: var(--bg-color);
                }

                ul#search-wrapper li:nth-child(odd) {
                    background: #212a2f;
                }

                .theme-dark .btn-outline-primary {
                    color: #b8e59c;
                    border-color: #b8e59c;
                }

                .theme-dark .btn-outline-primary:hover,
                .theme-dark .btn-outline-primary:active {
                    background-color: #2d4121;
                }

                .theme-dark input.form-control {
                    background-color: #101518;
                    color: #CFD8DC;
                }

                .theme-dark .dropzone {
                    background: transparent;
                }

                .theme-dark .inline-actions>a>i {
                    background: #79755e;
                }

                .theme-dark .text-white {
                    color: #CFD8DC !important;
                }

                .theme-dark .table-bordered td,
                .table-bordered th {
                    border-color: #343434;
                }

                .theme-dark .table-bordered td .custom-control-input,
                .theme-dark .table-bordered th .custom-control-input {
                    opacity: 0.678;
                }

                .message {
                    background-color: #212529;
                }

                form.dropzone {
                    border-color: #79755e;
                }
            </style>
        <?php endif; ?>
    <style>.inline-actions .mega-row-download{display:inline-block;margin:0;padding:0;vertical-align:middle}.inline-actions .mega-download-action{display:inline-flex;align-items:center;justify-content:center;background:#3988b8;color:#fff;border:0;border-radius:3px;width:22px;height:21px;padding:0;cursor:pointer;font-size:14px;line-height:1;vertical-align:middle}.inline-actions .mega-download-action:hover{background:#286d99}.inline-actions .mega-download-action:focus-visible{outline:2px solid #0d6efd;outline-offset:2px}</style>

<style id="mega-v90-two-layouts">
/* Exactly two responsive modes: mobile <=991px, desktop >=992px. */
@media <?php echo fm_layout_media_query(); ?> {
  html body .main-nav .mega-desktop-bulk {display:none!important;}
  html body .fm-path-links .mega-desktop-parent {display:none!important;}
  html body .mega-actions {display:none!important;}
  html body .mega-view-controls {display:flex!important;}
  html body.mega-mobile-list #main-table tbody tr.fm-parent-folder-row {display:none!important;}
}
@media <?php echo fm_desktop_media_query(); ?> {
  html body .mega-view-controls {display:none!important;}
  html body .mega-actions {display:none!important;}
}
</style>
<style id="mega-v89-desktop-download-spacing">
/* Match the 5px left spacing used by the adjacent file action icons. */
@media <?php echo fm_desktop_media_query(); ?> {
  #main-table td.inline-actions > .mega-download-direct { margin-left:5px !important; }
}
</style>
<style id="mega-dark-download-action-neutral">
/* Match the neutral dark-theme action buttons; preserve light theme styling. */
body.theme-dark .inline-actions .mega-download-action,
html[data-bs-theme="dark"] .inline-actions .mega-download-action {
    background: #79755e !important;
    color: #fff !important;
    border: 1px solid #79755e !important;
}
body.theme-dark .inline-actions .mega-download-action:hover,
html[data-bs-theme="dark"] .inline-actions .mega-download-action:hover {
    background: #68654f !important;
    border-color: #68654f !important;
}
body.theme-dark .inline-actions .mega-download-action i,
html[data-bs-theme="dark"] .inline-actions .mega-download-action i {color:#fff !important;}
</style>
<style id="mega-dark-neutral-navigation-v1">

/* Dark theme: neutral white navigation, breadcrumbs, folder labels and icons.
   Keep destructive actions, status indicators, and syntax highlighting meaningful. */
body.theme-dark #navbarSupportedContent .navbar-nav .nav-link,
body.theme-dark #navbarSupportedContent .navbar-nav .nav-link:visited,
body.theme-dark #navbarSupportedContent .navbar-nav .nav-link:hover,
body.theme-dark #navbarSupportedContent .navbar-nav .nav-link .fa,
body.theme-dark .fm-always-visible-path .fm-path-links a,
body.theme-dark .fm-always-visible-path .fm-path-links a:visited,
body.theme-dark .fm-always-visible-path .fm-path-links a:hover,
body.theme-dark .fm-always-visible-path .fm-path-links a .fa,
body.theme-dark .fm-always-visible-path .fm-path-links .bread-crumb,
body.theme-dark #main-table .filename a,
body.theme-dark #main-table .filename a:visited,
body.theme-dark #main-table .filename a:hover,
body.theme-dark #main-table .filename a .fa-folder-o,
body.theme-dark #main-table .filename .fa-folder-o,
body.theme-dark #main-table .filename .fa-folder,
body.theme-dark #main-table .filename .icon-link_folder,
body.theme-dark .mega-search-file-icon .fa-folder-o,
body.theme-dark .mega-search-folder a,
body.theme-dark .mega-search-card a.btn-outline-secondary,
body.theme-dark .mega-search-card a.btn-outline-secondary .fa,
body.theme-dark .mega-preview-actions .btn:not(.mega-danger) .fa,
body.theme-dark .mega-preview-actions .btn:not(.mega-danger) i.fa-arrow-circle-left,
body.theme-dark .modal-footer .btn-secondary,
body.theme-dark .modal-footer .btn-secondary .fa,
body.theme-dark .modal-footer .btn-outline-secondary,
body.theme-dark .modal-footer .btn-outline-secondary .fa {
    color: #f1f5f9 !important;
}
body.theme-dark #navbarSupportedContent .navbar-nav .nav-link:hover,
body.theme-dark .fm-always-visible-path .fm-path-links a:hover,
body.theme-dark #main-table .filename a:hover {
    color: #ffffff !important;
}
</style>
<style id="mega-dark-white-neutral-v2">

/* White neutral links and icons in dark mode; preserve colored status actions. */
body.theme-dark .main-nav .fm-always-visible-path a,
body.theme-dark .main-nav .fm-always-visible-path a i,
body.theme-dark .main-nav .fm-always-visible-path .bread-crumb,
body.theme-dark .main-nav #navbarSupportedContent a.nav-link,
body.theme-dark .main-nav #navbarSupportedContent a.nav-link i,
body.theme-dark a.btn-outline-secondary,
body.theme-dark a.btn-outline-secondary i,
body.theme-dark button.btn-outline-secondary,
body.theme-dark button.btn-outline-secondary i,
body.theme-dark .btn-cancel,
body.theme-dark .btn-cancel i,
body.theme-dark a.text-danger:has(.fa-times-circle-o),
body.theme-dark a.text-danger:has(.fa-times-circle-o) i,
body.theme-dark a[href] > .fa-arrow-left,
body.theme-dark #main-table .filename a,
body.theme-dark #main-table .filename a i.fa-folder-o,
body.theme-dark #main-table .filename a i.fa-folder,
body.theme-dark .fm-path-links a,
body.theme-dark .fm-path-links a i {
  color:#f1f5f9!important;
}
body.theme-dark a.btn-outline-secondary,
body.theme-dark button.btn-outline-secondary {
  background:#37414b!important;
  border-color:#596674!important;
}
body.theme-dark a.btn-outline-secondary:hover,
body.theme-dark button.btn-outline-secondary:hover {
  background:#465362!important;
}
</style>
<script id="mega-remove-stray-escaped-newline">
/* Remove only orphaned literal backslash-n text nodes from page chrome.
   Never touch source previews, editors, filenames or user content. */
document.addEventListener('DOMContentLoaded', function () {
    var root = document.body;
    if (!root || !document.createTreeWalker) return;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    var toRemove = [];
    while (walker.nextNode()) {
        var node = walker.currentNode;
        if (node.nodeValue.trim() !== '\\n') continue;
        var el = node.parentElement;
        if (!el || el.closest('pre,code,textarea,script,style,[contenteditable],.CodeMirror,.ace_editor,.mega-preview-content,.preview-text')) continue;
        // Only stray layout text, not text inside named UI components.
        if (el.matches('body,main,header,nav,section,div,.container,.container-fluid,.row')) {
            toRemove.push(node);
        }
    }
    toRemove.forEach(function (node) { node.parentNode.removeChild(node); });
});
</script>
<style id="mega-dark-checkbox-parent-white">

/* Dark theme: parent-folder entry and selection checkbox outlines. */
body.theme-dark #main-table td[data-sort] > a,
body.theme-dark #main-table td[data-sort] > a:visited,
body.theme-dark #main-table td[data-sort] > a > i.go-back,
body.theme-dark #main-table i.fa-chevron-circle-left.go-back,
body.theme-dark #main-table td[data-sort] > a:hover {color:#f1f5f9!important}
body.theme-dark #main-table .custom-checkbox .custom-control-label::before,
body.theme-dark #main-table .custom-checkbox .custom-control-label:before,
body.theme-dark #main-table .custom-checkbox-header .custom-control-label::before {
  background-color:transparent!important;
  border:1.5px solid #f1f5f9!important;
  box-shadow:none!important;
}
body.theme-dark #main-table .custom-checkbox .custom-control-input:checked ~ .custom-control-label::before,
body.theme-dark #main-table .custom-checkbox .custom-control-input:checked ~ .custom-control-label:before {
  background-color:#527faf!important;
  border-color:#f1f5f9!important;
}
body.theme-dark #main-table .custom-checkbox .custom-control-input:focus ~ .custom-control-label::before {
  box-shadow:0 0 0 .2rem rgba(241,245,249,.22)!important;
}
</style>
<style id="mega-dark-folder-picker-neutral">

/* Copy/Move destination picker: neutral folder rows in dark theme only. */
body.theme-dark #mega-folder-picker #mega-folder-entries > button,
html[data-bs-theme="dark"] #mega-folder-picker #mega-folder-entries > button {
    color: #f1f5f9 !important;
    border-color: #cbd5e1 !important;
    background-color: #242b31 !important;
}
body.theme-dark #mega-folder-picker #mega-folder-entries > button:hover,
body.theme-dark #mega-folder-picker #mega-folder-entries > button:focus,
html[data-bs-theme="dark"] #mega-folder-picker #mega-folder-entries > button:hover,
html[data-bs-theme="dark"] #mega-folder-picker #mega-folder-entries > button:focus {
    color: #ffffff !important;
    border-color: #ffffff !important;
    background-color: #35414c !important;
}
</style>

<style id="mega-mobile-unified-v41">
/* One shared responsive design system for all server-rendered screens. */
@media <?php echo fm_layout_media_query(); ?> {
  body {
    --mega-mobile-radius:14px;
    --mega-mobile-gap:12px;
    --mega-mobile-surface:var(--bs-body-bg,#fff);
    --mega-mobile-border:var(--bs-border-color,#d5dce4);
    --mega-mobile-text:var(--bs-body-color,#202832);
    overflow-x:hidden;
  }
  body.theme-dark {
    --mega-mobile-surface:#242c34;
    --mega-mobile-border:#475562;
    --mega-mobile-text:#e8edf4;
  }
  body #wrapper.container-fluid{padding-left:12px!important;padding-right:12px!important;max-width:100vw}
  body .path,body .path>.card,body .path .card-body,body .mega-preview-content{min-width:0;max-width:100%;box-sizing:border-box}
  body .path>.card,body .path .card{
    border-radius:var(--mega-mobile-radius)!important;
    overflow:visible;
  }
  body .path .card-header{padding:12px 14px}
  body .path .card-body{padding:14px!important}
  body .path .card-header h6{font-size:1.05rem;font-weight:650;margin:0}
  body .path .form-control,body .path .form-select,
  body .modal .form-control,body .modal .form-select{
    min-height:44px;max-width:100%;font-size:16px;
    color:var(--mega-mobile-text);background-color:var(--mega-mobile-surface);
    border-color:var(--mega-mobile-border);border-radius:9px
  }
  body .path input[type=file],body .path input[type=url],body .path input[type=text],
  body .path textarea{max-width:100%;box-sizing:border-box}
  body .path .btn,body .modal .btn{min-height:44px;border-radius:9px;touch-action:manipulation}
  body .path .btn-sm,body .modal .btn-sm{min-height:40px}
  body .path .break-word,body .path p,body .path .card-body,
  body .modal .modal-body{overflow-wrap:anywhere}
  body .path .d-flex{min-width:0}
  body .modal-dialog{max-width:calc(100vw - 24px)!important;margin:12px auto!important}
  body .modal-content{max-width:100%;border-radius:16px;overflow:hidden}
  body .modal-body{max-height:calc(100dvh - 160px);overflow-y:auto;overscroll-behavior:contain}
  body .modal-footer{gap:8px}
  body .modal-footer .btn{flex:1 1 auto}
  body .mega-view-controls{display:flex;gap:8px;flex-wrap:wrap;padding:10px!important}
  body .mega-view-controls #mega-mobile-sort{flex:1 1 100px;min-width:85px;max-width:none}
  body .mega-view-controls #mega-sort-direction{flex:0 0 44px}
  body .mega-view-controls #mega-select-toggle{flex:0 0 auto}
  body.mega-mobile-list #main-table tbody tr{
    background:var(--mega-mobile-surface)!important;
    border-color:var(--mega-mobile-border)!important;
    box-shadow:0 1px 2px rgba(0,0,0,.035);
    padding:12px 10px!important;min-height:72px!important;
  }
  body.mega-mobile-list #main-table tbody tr>td[data-sort] .filename a{
    max-width:100%;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;
  }
  body.mega-mobile-list #main-table .mega-row-more{min-height:44px;min-width:44px}
  body.mega-mobile-list .mega-row-actions-menu{
    background:var(--mega-mobile-surface)!important;
    color:var(--mega-mobile-text)!important;
    border:1px solid var(--mega-mobile-border)!important;
    box-shadow:0 8px 24px rgba(0,0,0,.17)!important;
    border-radius:12px!important;
  }
  body.mega-mobile-list .mega-row-actions-menu>a,
  body.mega-mobile-list .mega-row-actions-menu>button{min-height:44px!important}
  body #mega-copy-form{display:flex;flex-direction:column;gap:12px}
  body #mega-copy-form>p{margin:0!important;line-height:1.65}
  body #mega-copy-form #inp_copy_to{display:block!important;width:100%!important;max-width:100%!important;margin-top:8px}
  body #mega-copy-form #mega-folder-picker{
    margin:0!important;padding:14px!important;max-height:none!important;
    background:var(--mega-mobile-surface)!important;
    border-color:var(--mega-mobile-border)!important;border-radius:12px!important
  }
  body #mega-folder-picker #mega-folder-entries{display:flex;flex-direction:column;gap:8px}
  body #mega-folder-picker #mega-folder-entries>button{
    display:flex!important;align-items:center!important;text-align:left!important;
    width:100%!important;min-height:48px!important;
    padding:11px 13px!important;border-radius:10px!important;
    color:var(--mega-mobile-text)!important;
    background:var(--mega-mobile-surface)!important;
    border:1px solid var(--mega-mobile-border)!important;
    white-space:normal!important;overflow-wrap:anywhere
  }
  body #mega-folder-location{display:block;overflow-wrap:anywhere;margin:8px 0}
  body #mega-copy-form>div[role=group]{
    position:sticky;bottom:0;z-index:12;display:grid!important;
    grid-template-columns:1fr 1fr;gap:8px!important;
    padding:12px 0;background:var(--mega-mobile-surface);
  }
  body #mega-copy-form>div[role=group] .btn{width:100%;margin:0;min-height:48px}
  body #mega-copy-form>div[role=group] .btn:first-of-type{grid-column:1 / -1}
  body .mega-editor-actions{gap:8px}
  body .mega-editor-actions .btn{min-height:46px}
  body .mega-preview-content .btn{min-height:40px}
  body .mega-preview-content iframe,body .mega-preview-content img,
  body .mega-preview-content video{max-width:100%}
  body .mega-inline-notice{max-width:100%;overflow-wrap:anywhere}
  body .mega-action-grid.operations{padding-bottom:env(safe-area-inset-bottom,0px)}
  body .mega-action-grid.operations .mega-action{min-height:52px}
  body .mega-preview-content table{max-width:100%}
  body .fm-file-list{max-width:100%}
  body :focus-visible{outline:2px solid #3189ed;outline-offset:2px}
}
@media (prefers-reduced-motion:reduce){
  .mega-row-actions-menu,.mega-inline-notice{transition:none!important;animation:none!important}
}
</style>


<style id="mega-copy-v44-compact-fix">
@media <?php echo fm_layout_media_query(); ?>{
  body #mega-copy-form > div[role="group"]{display:none!important;position:static!important}
  body #mega-copy-form > p.break-word{display:none!important}
  body #mega-copy-form{gap:0!important}
  body #mega-copy-form .mega-copy-v43{gap:9px!important}
  body #mega-copy-form .mega-copy-v43-source{padding:12px 14px!important;gap:10px!important}
  body #mega-copy-form .mega-copy-v43-heading{margin:0!important}
  body #mega-copy-form .mega-copy-v43-crumbs{min-height:32px!important}
  body #mega-copy-form #mega-folder-picker{padding:0!important;margin:0!important;max-height:none!important}
  body #mega-copy-form #mega-folder-status{padding:7px 12px!important;min-height:0!important}
  body #mega-copy-form #mega-folder-entries{max-height:36dvh!important}
  body #mega-copy-form #mega-folder-entries>button{min-height:51px!important;padding:9px 36px 9px 14px!important}
  body #mega-copy-form .mega-copy-v43-target{padding:11px 14px!important;gap:4px!important}
  body #mega-copy-form .mega-copy-v43-advanced summary{padding:5px 0!important}
  body #mega-copy-form .mega-copy-v43-submit{min-height:48px!important}
  body #mega-copy-form .mega-copy-v43-cancel{min-height:44px!important}
  body #mega-copy-form .mega-copy-v43-mode label{min-height:42px!important}
}
</style>
<style id="mega-mobile-compact-v48">
.mega-mobile-header,.mega-mobile-menu{display:none}
@media<?php echo fm_layout_media_query(); ?>{
 body{padding-bottom:0!important}
 body #wrapper.container-fluid{padding:0 8px!important}
 body .main-nav{display:none!important}
 body .mega-mobile-header{display:flex;position:relative;align-items:center;gap:10px;height:54px;padding:4px 6px;margin:0 0 5px;background:var(--bs-body-bg,#fff);border-bottom:1px solid var(--bs-border-color,#d5dce4);z-index:1020}
 body .mega-mobile-back,body .mega-mobile-menu-trigger{display:flex;align-items:center;justify-content:center;flex:0 0 38px;height:40px;background:transparent;border:0;color:var(--bs-body-color,#222);text-decoration:none;font-size:19px}
 body .mega-mobile-heading{flex:1;min-width:0;display:flex;flex-direction:column;gap:1px;line-height:1.2}
 body .mega-mobile-heading strong{font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 body .mega-mobile-heading small{font-size:11px;opacity:.7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 body .mega-mobile-menu:not([hidden]){display:flex;position:absolute;right:4px;top:49px;width:220px;max-height:calc(100dvh - 65px);overflow-y:auto;flex-direction:column;padding:5px;background:var(--bs-body-bg,#fff);border:1px solid var(--bs-border-color,#d5dce4);border-radius:9px;box-shadow:0 8px 26px #0003;z-index:1100}
 body .mega-mobile-menu a,body .mega-mobile-menu button{display:flex;align-items:center;gap:10px;width:100%;min-height:39px;padding:8px 10px;border:0;border-radius:5px;background:transparent;text-align:left;text-decoration:none;color:var(--bs-body-color,#222);font-size:13px}
 body .mega-mobile-menu i{width:17px;text-align:center}
 body .mega-mobile-menu a:active,body .mega-mobile-menu button:active{background:var(--bs-secondary-bg,#e7ebf0)}
 body .mega-mobile-menu .mega-mobile-selection-label{padding:6px 10px;font-weight:600;font-size:12px}
 body .mega-mobile-menu hr{margin:4px 6px;border-color:var(--bs-border-color,#ddd)}
 body #wrapper>form.pt-3{padding-top:3px!important}
 body .mega-view-controls{display:flex!important;align-items:center!important;flex-wrap:nowrap!important;gap:5px!important;padding:4px 5px!important;margin:0 0 5px!important;border:0!important;border-bottom:1px solid var(--bs-border-color,#ddd)!important;border-radius:0!important;box-shadow:none!important}
 body .mega-view-controls label[for="mega-mobile-sort"]{font-size:11px!important}
 body .mega-view-controls #mega-mobile-sort{flex:1 1 auto!important;min-width:60px!important;max-width:none!important;width:auto!important;min-height:33px!important;padding:3px 20px 3px 6px!important;font-size:12px!important}
 body .mega-view-controls #mega-sort-direction{flex:0 0 34px!important;width:34px!important;min-height:33px!important;padding:3px!important}
 body .mega-view-controls #mega-select-toggle{flex:0 0 auto!important;min-height:33px!important;padding:3px 6px!important;font-size:11px!important}
 body.mega-mobile-list #main-table tbody tr{display:flex!important;align-items:center!important;gap:6px!important;min-height:52px!important;margin:0!important;padding:5px 4px!important;border:0!important;border-bottom:1px solid var(--bs-border-color,#e2e6e9)!important;border-radius:0!important;box-shadow:none!important;background:transparent!important}
 body.mega-mobile-list #main-table tbody tr>td[data-sort] .filename,body.mega-mobile-list #main-table tbody tr>td[data-sort] .filename a{white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;max-width:100%!important}
 body.mega-mobile-list .mega-file-meta{margin-top:1px!important;font-size:11px!important;line-height:1.2!important}
 body.mega-mobile-list #main-table tbody tr>td.inline-actions{flex:0 0 34px!important;min-width:34px!important}
 body.mega-mobile-list .mega-row-more{width:34px!important;min-width:34px!important;height:38px!important;min-height:38px!important;padding:3px!important;border:0!important;background:transparent!important;box-shadow:none!important}
 body.mega-mobile-list .mega-actions{display:none!important}
 body.mega-mobile-list:has(.mega-actions.mega-has-selection) .fm-file-list{padding-bottom:0!important}
 body.theme-dark .mega-mobile-header,body.theme-dark .mega-mobile-menu{background:#242c34;color:#e8edf4;border-color:#475562}
 body.theme-dark .mega-mobile-back,body.theme-dark .mega-mobile-menu-trigger,body.theme-dark .mega-mobile-menu a,body.theme-dark .mega-mobile-menu button{color:#e8edf4}
}
</style>
<style id="mega-mobile-v49-layout-fix">
@media<?php echo fm_layout_media_query(); ?>{
  html body.navbar-fixed,html body{padding-top:0!important;margin-top:0!important}
  body #wrapper.container-fluid{padding:0 8px!important;margin-top:0!important}
  body .main-nav{display:none!important}
  body .mega-mobile-header{height:auto!important;min-height:58px!important;padding:5px 7px!important;margin:0 0 2px!important;gap:7px!important}
  body .mega-mobile-heading{min-width:0!important;gap:3px!important}
  body .mega-mobile-heading-line{display:flex;align-items:baseline;gap:9px;min-width:0}
  body .mega-mobile-heading-line strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:16px!important}
  body .mega-mobile-quota{white-space:nowrap;font-size:10px;color:var(--bs-secondary-color,#777)}
  body .mega-mobile-crumbs{display:flex;align-items:center;gap:7px;min-width:0;font-size:11px;color:var(--bs-secondary-color,#777)}
  body .mega-mobile-crumbs>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  body .mega-mobile-parent{display:flex;align-items:center;justify-content:center;flex:0 0 28px;height:27px;font-size:18px;color:var(--bs-link-color,#1670b8)}
  body.mega-mobile-list #main-table tbody tr.fm-parent-folder-row{display:none!important}
  body .mega-view-controls{height:41px!important;min-height:41px!important;padding:2px 3px!important;gap:5px!important;justify-content:flex-end!important}
  body .mega-view-controls #mega-select-toggle{order:0!important;margin-right:auto!important;border:0!important;background:transparent!important;font-size:12px!important;padding:3px 4px!important}
  body .mega-view-controls label[for="mega-mobile-sort"]{display:none!important}
  body .mega-view-controls #mega-mobile-sort{order:1!important;flex:0 1 110px!important;width:110px!important;min-width:72px!important;border:0!important;background-color:transparent!important;font-size:12px!important}
  body .mega-view-controls #mega-sort-direction{order:2!important;border:0!important;background:transparent!important;font-size:18px!important}
  body.mega-mobile-list #main-table tbody tr{min-height:53px!important}
}
</style>

<style id="mega-mobile-v52-sticky-and-select">
/* Main application head: v51 accidentally injected its fixed-header CSS into the login head. */
.mega-mobile-header-spacer{display:none}
@media screen and <?php echo fm_layout_media_query(); ?>{
 html body .mega-mobile-header-spacer{display:block!important;height:66px!important;min-height:66px!important;flex:none!important}
 html body .mega-mobile-header{display:flex!important;position:fixed!important;top:0!important;left:0!important;right:0!important;width:100%!important;height:66px!important;min-height:66px!important;max-height:66px!important;box-sizing:border-box!important;z-index:1060!important;margin:0!important;padding:6px 12px!important;background:var(--bs-body-bg,#fff)!important;box-shadow:0 1px 3px #00000020!important;transform:none!important}
 html body .mega-mobile-heading{margin-left:0!important;padding-left:0!important}
 html body .mega-mobile-menu:not([hidden]){z-index:1070!important}
 html body .mega-view-controls #mega-select-toggle,
 html body .mega-view-controls #mega-select-toggle:hover,
 html body .mega-view-controls #mega-select-toggle:focus,
 html body .mega-view-controls #mega-select-toggle:active,
 html body .mega-view-controls #mega-select-toggle:disabled,
 html body .mega-view-controls #mega-select-toggle.active{
  color:#222831!important;-webkit-text-fill-color:#222831!important;opacity:1!important;
  visibility:visible!important;text-shadow:none!important;background:transparent!important;
  font-weight:600!important;min-width:100px!important;white-space:nowrap!important;
  box-shadow:none!important;border-color:transparent!important;
 }
 html body.theme-dark .mega-view-controls #mega-select-toggle,
 html body.theme-dark .mega-view-controls #mega-select-toggle:hover,
 html body.theme-dark .mega-view-controls #mega-select-toggle:focus,
 html body.theme-dark .mega-view-controls #mega-select-toggle:active,
 html body.theme-dark .mega-view-controls #mega-select-toggle:disabled{color:#e8edf4!important;-webkit-text-fill-color:#e8edf4!important}
}
</style>
<style id="mega-mobile-v57-sort-alignment">
@media screen and <?php echo fm_layout_media_query(); ?>{
 /* Keep selection control at the same left edge as file checkboxes. */
 html body .mega-view-controls{position:relative!important;display:flex!important;align-items:center!important;justify-content:flex-end!important;padding-left:14px!important;padding-right:8px!important;gap:6px!important}
 html body .mega-view-controls #mega-select-toggle{position:absolute!important;left:14px!important;top:50%!important;transform:translateY(-50%)!important;margin:0!important;padding:4px 0!important;width:auto!important;min-width:0!important;max-width:none!important;flex:none!important;text-align:left!important;white-space:nowrap!important;z-index:1!important}
 html body .mega-view-controls #mega-mobile-sort{margin-left:auto!important;flex:0 1 105px!important;max-width:105px!important;min-width:70px!important}
 /* Sorting arrow is always solid black, regardless of theme or button state. */
 html body .mega-view-controls #mega-sort-direction,
 html body .mega-view-controls #mega-sort-direction:hover,
 html body .mega-view-controls #mega-sort-direction:focus,
 html body .mega-view-controls #mega-sort-direction:focus-visible,
 html body .mega-view-controls #mega-sort-direction:active,
 html body .mega-view-controls #mega-sort-direction:disabled,
 html body .mega-view-controls #mega-sort-direction.active,
 html body.theme-dark .mega-view-controls #mega-sort-direction{
 color:var(--bs-body-color,#212529)!important;-webkit-text-fill-color:currentColor!important;opacity:1!important;visibility:visible!important;
 background:transparent!important;border-color:transparent!important;box-shadow:none!important;text-shadow:none!important;
 font-weight:700!important;filter:none!important;pointer-events:auto!important;
 }
}
</style>
<style id="mega-v67-theme-consistency">
/* Sorting arrow must follow the selected theme, including hover/focus/active. */
@media<?php echo fm_layout_media_query(); ?>{
 html body .mega-view-controls #mega-sort-direction,
 html body .mega-view-controls #mega-sort-direction:hover,
 html body .mega-view-controls #mega-sort-direction:focus,
 html body .mega-view-controls #mega-sort-direction:focus-visible,
 html body .mega-view-controls #mega-sort-direction:active,
 html body .mega-view-controls #mega-sort-direction:disabled,
 html body .mega-view-controls #mega-sort-direction.active{
   color:var(--bs-body-color,#212529)!important;
   -webkit-text-fill-color:currentColor!important;
   opacity:1!important;visibility:visible!important;
   background:transparent!important;text-shadow:none!important;
 }
 html[data-bs-theme="dark"] body .mega-view-controls #mega-sort-direction,
 html body.theme-dark .mega-view-controls #mega-sort-direction,
 html[data-bs-theme="dark"] body .mega-view-controls #mega-sort-direction:is(:hover,:focus,:active,:disabled),
 html body.theme-dark .mega-view-controls #mega-sort-direction:is(:hover,:focus,:active,:disabled){
   color:#e8edf4!important;-webkit-text-fill-color:#e8edf4!important;
 }
}
</style>
<style id="mega-v64-full-width-two-actions">
@media <?php echo fm_layout_media_query(); ?> {
  html body .mega-two-action-row {
    display:grid!important;
    grid-template-columns:repeat(2,minmax(0,1fr))!important;
    gap:12px!important;
    width:100%!important;
    max-width:none!important;
    margin-left:0!important;
    margin-right:0!important;
    padding-left:0!important;
    padding-right:0!important;
    flex:initial!important;
  }
  html body .mega-two-action-row > .btn {
    display:flex!important;
    width:100%!important;
    min-width:0!important;
    margin:0!important;
    align-items:center!important;
    justify-content:center!important;
    white-space:nowrap!important;
    min-height:46px!important;
  }
  html body .mega-two-action-row > .btn:last-child {
    background-color:#0d6efd!important;
    border-color:#0d6efd!important;
    color:#fff!important;
  }
  html body .mega-settings-panel .mega-two-action-row {
    flex:0 0 100%!important;
    max-width:100%!important;
  }
}
</style>



<style id="mega-v85-cancel-icon-consistency">
/* Match the Upload Files Cancel control on every page and viewport. */
a:has(> i.fa-times):not(.text-danger) > i.fa-times,
button[data-bs-dismiss="modal"] > i.fa-times {
  display:inline-block;
  margin-right:4px;
  vertical-align:baseline;
}
</style>
<style id="mega-v84-desktop-preview-editor-center">
/* Desktop only: center all file-preview action buttons and both editor toolbars.
   Preserve mobile action grids and existing button sizes/behavior. */
@media screen and <?php echo fm_desktop_media_query(); ?> {
  html body .mega-preview-actions {
    display: flex !important;
    flex-wrap: wrap !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 9px !important;
    width: 100% !important;
  }
  html body .mega-preview-actions > a,
  html body .mega-preview-actions > form {
    flex: 0 0 auto !important;
    width: auto !important;
    max-width: none !important;
    margin: 0 !important;
  }
  html body .mega-preview-actions > form > .btn {
    width: auto !important;
  }
  html body .mega-editor-shell .mega-editor-actions {
    display: flex !important;
    flex-wrap: wrap !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 9px !important;
    width: 100% !important;
  }
  html body .mega-editor-shell .mega-editor-actions .mega-editor-save {
    margin-left: 0 !important;
    margin-right: 0 !important;
  }
  html body .mega-editor-shell .mega-editor-tools {
    justify-content: center !important;
  }
  html body .mega-editor-shell .mega-editor-tools .js-ace-toolbar {
    justify-content: center !important;
  }
}
</style>


<style id="mega-v78-desktop-upload-tab-visibility">
/* Desktop only: the inactive Upload Files action row must not be
   resurrected by the v77 display:flex!important desktop layout rule. */
@media screen and <?php echo fm_desktop_media_query(); ?> {
  html body .fm-upload-wrapper .fm-file-upload-actions.fm-unified-actions.hidden {
    display: none !important;
  }
}
</style>


<style id="mega-v95-button-icon-spacing">
/* A single icon-to-caption gap in both responsive layouts. */
button.mega-icon-label-gap > i.mega-caption-icon,
a.btn.mega-icon-label-gap > i.mega-caption-icon,
input[type="button"].mega-icon-label-gap > i.mega-caption-icon,
.swal2-actions button.mega-icon-label-gap > i.mega-caption-icon,
.swal-button.mega-icon-label-gap > i.mega-caption-icon {
    margin-left: 0 !important;
    margin-right: 6px !important;
}
button.mega-icon-label-gap > svg.mega-caption-icon,
a.btn.mega-icon-label-gap > svg.mega-caption-icon,
.swal2-actions button.mega-icon-label-gap > svg.mega-caption-icon {
    margin-left: 0 !important;
    margin-right: 6px !important;
}
/* A few button captions wrap their icon in a span. */
.mega-icon-label-gap > .mega-caption-icon { vertical-align: middle; }
</style>

<style id="mega-v117-desktop-form-consistency">
@media screen and <?php echo fm_desktop_media_query(); ?> {
  html body #wrapper .fm-form-panel {
    box-sizing:border-box!important;
    width:100%!important;max-width:800px!important;
    margin-left:auto!important;margin-right:auto!important;
  }
  html body #wrapper > .mega-settings-panel,
  html body #wrapper > .fm-form-panel-shell,
  html body #wrapper .fm-upload-page-path {
    box-sizing:border-box!important;
    width:calc(100% - 24px)!important;max-width:800px!important;
    padding-left:0!important;padding-right:0!important;
    flex:0 0 auto!important;margin-left:auto!important;margin-right:auto!important;
  }
  html body #wrapper .mega-search-page .mega-search-actions,
  html body #wrapper .mega-settings-panel .mega-two-action-row,
  html body #wrapper .fm-new-item-card .mega-two-action-row,
  html body #wrapper .fm-upload-wrapper .fm-file-upload-actions:not(.hidden),
  html body #wrapper .fm-upload-wrapper .fm-url-actions {
    display:flex!important;flex-direction:row!important;flex-wrap:wrap!important;
    align-items:center!important;justify-content:center!important;
    gap:12px!important;width:100%!important;max-width:100%!important;
    flex-basis:100%!important;margin-left:0!important;margin-right:0!important;padding-left:0!important;padding-right:0!important;
  }
  html body #wrapper .mega-search-page .mega-search-actions > .fm-unified-button,
  html body #wrapper .mega-settings-panel .mega-two-action-row > .btn,
  html body #wrapper .fm-new-item-card .mega-two-action-row > .btn,
  html body #wrapper .fm-upload-wrapper .fm-file-upload-actions > .fm-unified-button,
  html body #wrapper .fm-upload-wrapper .fm-url-actions > .fm-unified-button {
    display:inline-flex!important;align-items:center!important;justify-content:center!important;
    flex:0 0 auto!important;width:auto!important;min-width:120px!important;max-width:none!important;
    min-height:44px!important;box-sizing:border-box!important;margin:0!important;
    white-space:nowrap!important;overflow-wrap:normal!important;word-break:normal!important;
  }
}
</style>

<style id="mega-v116-desktop-header-consistency">
/* Override Bootstrap's viewport-only collapse when Desktop is selected or
   detected. The table, header and controls share the same layout decision. */
@media screen and <?php echo fm_desktop_media_query(); ?> {
  html body .main-nav > .navbar-toggler {display:none!important;}
  html body .main-nav > #navbarSupportedContent {
    display:flex!important;height:auto!important;visibility:visible!important;
    overflow:visible!important;flex-basis:auto!important;
  }
  html body .main-nav #navbarSupportedContent .navbar-nav {flex-direction:row!important;}
  html body .main-nav .navbar-nav .dropdown-menu {position:absolute;}
  html body #main-table .mega-file-meta {display:none!important;}
  html body #mega-view-controls {display:none!important;}
}
</style>

<style id="mega-v119-share-dialogs">
#megaStopSharingDialog .modal-content{height:auto;min-height:var(--mega-operation-dialog-height);}
@media <?php echo fm_layout_media_query(); ?> {
 html body #wrapper .mega-search-page .mega-search-actions{display:flex!important;flex-wrap:wrap!important;justify-content:center!important;justify-content:safe center!important;gap:12px!important;overflow-x:auto;}
 html body #wrapper .mega-search-page .mega-search-actions > .fm-unified-button{flex:0 0 auto!important;width:auto!important;min-width:120px!important;max-width:none!important;white-space:nowrap!important;overflow-wrap:normal!important;word-break:normal!important;}
}
</style>

<style id="mega-v123-plain-row-action-icons">
/* File-list actions: plain icons, including hover, in both themes. */
html body #main-table td.inline-actions > a > i,
html body #main-table td.inline-actions > .mega-download-direct,
html body #main-table td.inline-actions > .mega-download-direct > i,
html body #main-table td.inline-actions > form.mega-row-download .mega-download-action,
html body #main-table td.inline-actions > form.mega-row-download .mega-download-action > i {
  background:transparent!important;
  background-image:none!important;
  border-color:transparent!important;
  box-shadow:none!important;
  color:var(--bs-link-color,#3785c1)!important;
}
html body #main-table td.inline-actions > a:focus-visible,
html body #main-table td.inline-actions > .mega-download-direct:focus-visible {
  outline:2px solid var(--bs-link-color,#3785c1);outline-offset:2px;
}
</style>

<style id="mega-v131-mobile-actions-and-confirmation">
.modal.modal-alert.confirmDialog .modal-content,
#megaBulkConfirm .modal-content {height:auto!important;min-height:var(--mega-operation-dialog-height,140px);max-height:calc(100dvh - 24px);}
.modal.modal-alert.confirmDialog .modal-body,
#megaBulkConfirm .modal-body {min-width:0!important;}
.modal .fm-confirm-filename,
#megaBulkConfirmDetail {display:block!important;flex-shrink:0;width:100%;max-width:100%;min-width:0;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;overflow-wrap:normal!important;word-break:normal!important;}
body.mega-mobile-list #main-table .mega-row-actions-menu {z-index:1040!important;overscroll-behavior:contain;}
html body.modal-open #main-table td.inline-actions > .mega-row-actions-menu.mega-open {display:none!important;}
</style>
<style id="fm-common-breadcrumb-metrics">
html body .fm-path-links,html body .mega-mobile-crumb-links{
  display:flex!important;align-items:center!important;gap:4px!important;line-height:1.3!important;
}
html body .fm-path-links{font-size:14px!important}
html body .fm-path-links>a,html body .mega-mobile-crumb-links>a{
  display:inline-flex!important;align-items:center!important;font-size:inherit!important;
  line-height:inherit!important;font-weight:400!important;vertical-align:middle!important;
}
html body .fm-path-links .fa-home,html body .fm-path-links .fm-rubbish-crumb-icon,
html body .mega-mobile-crumb-links .fa-home,html body .mega-mobile-crumb-links .fm-rubbish-crumb-icon{
  font-size:1.15em!important;line-height:1!important;width:1em;text-align:center;vertical-align:middle!important;
}
html body .fm-path-links .bread-crumb,html body .mega-mobile-crumb-links .mega-crumb-separator{
  display:inline-flex;align-items:center;font-style:normal;font-size:inherit;line-height:inherit;
  color:var(--bs-secondary-color,#777);
}
html body .fm-path-links .mega-desktop-parent{font-size:inherit!important;margin-left:9px!important;line-height:1!important}
html body .fm-path-links .mega-desktop-parent .fa{font-size:1.15em!important;line-height:1!important}
@media<?php echo fm_layout_media_query(); ?>{
 html body .mega-mobile-crumb-links{font-size:11px!important}
 html body .mega-mobile-crumbs .mega-mobile-parent{font-size:12.65px!important;line-height:1!important}
}
</style>
</head>

    <body class="<?php echo (FM_THEME == "dark") ? 'theme-dark' : ''; ?> <?php echo $isStickyNavBar; ?>">
        <div id="wrapper" class="container-fluid">
            <!-- Advance Search Modal -->
            <div class="modal fade" id="searchModal" tabindex="-1" role="dialog" aria-labelledby="searchModalLabel" aria-hidden="true" data-bs-theme="<?php echo FM_THEME; ?>">
                <div class="modal-dialog modal-lg" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title col-10" id="searchModalLabel">
                                <div class="input-group mb-3">
                                    <input type="text" class="form-control" placeholder="<?php echo lng('Search') ?> <?php echo lng('a files') ?>" aria-label="<?php echo lng('Search') ?>" aria-describedby="search-addon3" id="advanced-search" autofocus required>
                                    <span class="input-group-text" id="search-addon3"><i class="fa fa-search"></i></span>
                                </div>
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?php echo lng('Close') ?>"></button>
                        </div>
                        <div class="modal-body">
                            <form action="" method="post">
                                <div class="lds-facebook">
                                    <div></div>
                                    <div></div>
                                    <div></div>
                                </div>
                                <ul id="search-wrapper">
                                    <p class="m-2"><?php echo lng('Search file in folder and subfolders...') ?></p>
                                </ul>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <!--Rename Modal -->
            <div class="modal modal-alert" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" role="dialog" id="renameDialog" data-bs-theme="<?php echo FM_THEME; ?>">
                <div class="modal-dialog" role="document">
                    <form class="modal-content rounded-3 shadow" method="post" autocomplete="off">
                        <div class="modal-body p-4 text-center">
                            <h5 class="mb-2"><?php echo lng('Are you sure to rename?') ?></h5>
                            <p class="mb-1">
                                <input type="text" name="rename_to" id="js-rename-to" class="form-control" placeholder="<?php echo lng('Enter new file name') ?>" required>
                                <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                                <input type="hidden" name="rename_from" id="js-rename-from">
                            </p>
                        </div>
                        <div class="modal-footer flex-nowrap p-0">
                            <button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel') ?></button>
                            <button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0"><i class="fa fa-check" aria-hidden="true"></i> <strong><?php echo lng('Okay'); ?></strong></button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Confirm Modal -->
            <script type="text/html" id="js-tpl-confirm">
                <div class="modal modal-alert confirmDialog" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" role="dialog" id="confirmDialog-<%this.id%>" data-bs-theme="<?php echo FM_THEME; ?>">
                    <div class="modal-dialog" role="document">
                        <form class="modal-content rounded-3 shadow" method="post" autocomplete="off" action="<%this.action%>">
                            <div class="modal-body p-4 text-center">
                                <h5 class="mb-2"><%this.confirmMessage%></h5>
                                <p class="mb-1 fm-confirm-filename"><%this.content%></p>
                            </div>
                            <div class="modal-footer flex-nowrap p-0">
                                <button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel') ?></button>
                                <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
                                <button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0" data-bs-dismiss="modal"><i class="fa fa-check" aria-hidden="true"></i> <strong><?php echo lng('Okay'); ?></strong></button>
                            </div>
                        </form>
                    </div>
                </div>
            </script>
        <?php
    }

    /**
     * Show page footer after login
     */
    function fm_show_footer()
    {
        global $ext_language, $lang;
        ?>
        </div>
        <?php print_external('js-jquery'); ?>
        <?php print_external('js-bootstrap'); ?>
        <?php print_external('js-jquery-datatables'); ?>
        <?php if (FM_USE_HIGHLIGHTJS && isset($_GET['view'])): ?>
            <?php print_external('js-highlightjs'); ?>
            <script>
                hljs.highlightAll();
                var isHighlightingEnabled = true;
            </script>
        <?php endif; ?>
        <script>
            function template(html, options) {
                var re = /<\%([^\%>]+)?\%>/g,
                    reExp = /(^( )?(if|for|else|switch|case|break|{|}))(.*)?/g,
                    code = 'var r=[];\n',
                    cursor = 0,
                    match;
                var add = function(line, js) {
                    js ? (code += line.match(reExp) ? line + '\n' : 'r.push(' + line + ');\n') : (code += line != '' ? 'r.push("' + line.replace(/"/g, '\\"') + '");\n' : '');
                    return add
                }
                while (match = re.exec(html)) {
                    add(html.slice(cursor, match.index))(match[1], !0);
                    cursor = match.index + match[0].length
                }
                add(html.substr(cursor, html.length - cursor));
                code += 'return r.join("");';
                return new Function(code.replace(/[\r\t\n]/g, '')).apply(options)
            }

            function rename(e, t) {
                if (t) {
                    $("#js-rename-from").val(t);
                    $("#js-rename-to").val(t);
                    $("#renameDialog").modal('show');
                }
            }

            function change_checkboxes(e, t) {
                for (var n = e.length - 1; n >= 0; n--) e[n].checked = "boolean" == typeof t ? t : !e[n].checked
            }

            function get_checkboxes() {
                for (var e = document.getElementsByName("file[]"), t = [], n = e.length - 1; n >= 0; n--)(e[n].type = "checkbox") && t.push(e[n]);
                return t
            }

            function select_all() {
                change_checkboxes(get_checkboxes(), !0); mega_update_selection()
            }

            function unselect_all() {
                change_checkboxes(get_checkboxes(), !1); mega_update_selection()
            }

            function invert_all() {
                change_checkboxes(get_checkboxes()); mega_update_selection()
            }

            function checkbox_toggle() {
                var e = get_checkboxes();
                e.push(this), change_checkboxes(e); mega_update_selection()
            }

            function mega_toggle_all_selection() {
                var boxes = get_checkboxes();
                var allSelected = boxes.length > 0 && boxes.every(function(box) { return box.checked; });
                change_checkboxes(boxes, !allSelected);
                mega_update_selection();
                // Update card selection highlight even when changed programmatically.
                boxes.forEach(function(box) {
                    var row = box.closest('tr');
                    if (row) row.classList.toggle('mega-selected-row', box.checked);
                });
            }

            function mega_update_selection() {
                var boxes = get_checkboxes(), count = 0;
                for (var i = 0; i < boxes.length; i++) if (boxes[i].checked) count++;
                var bulkPanel = document.querySelector('.mega-actions');
                if (bulkPanel) {
                    bulkPanel.classList.toggle('mega-has-selection', count > 0);
                    bulkPanel.setAttribute('aria-hidden', count ? 'false' : 'true');
                }
                if (window.megaMobileUpdateMenu) window.megaMobileUpdateMenu(count);
                var label = document.getElementById('mega-selected-count');
                if (label) label.textContent = count + ' selected';
                var toggle = document.getElementById('mega-select-toggle');
                if (toggle) {
                    var allChecked = boxes.length > 0 && count === boxes.length;
                    var toggleText = allChecked ? <?php echo json_encode(lng('UnSelectAll')); ?> : <?php echo json_encode(lng('SelectAll')); ?>;
                    toggle.textContent = toggleText;
                    toggle.title = toggleText;
                    toggle.setAttribute('aria-label', toggleText);
                }
                var headerToggle = document.getElementById('js-select-all-items');
                if (headerToggle) {
                    headerToggle.checked = boxes.length > 0 && count === boxes.length;
                    headerToggle.indeterminate = count > 0 && count < boxes.length;
                }
                boxes.forEach(function(box) {
                    var row = box.closest('tr');
                    if (row) row.classList.toggle('mega-selected-row', box.checked);
                });
                var actions = document.querySelectorAll('.mega-needs-selection');
                for (var j = 0; j < actions.length; j++) {
                    actions[j].disabled = count === 0;
                    actions[j].classList.toggle('disabled', count === 0);
                }
            }
            document.addEventListener('change', function(event) {
                if (event.target && (event.target.name === 'file[]' || event.target.id === 'js-select-all-items')) mega_update_selection();
            });
            document.addEventListener('DOMContentLoaded', mega_update_selection);

            // Shared editor operation lifecycle: always close the processing UI
            // before rendering the result. Never infer success from HTTP 200 alone.
            function megaEditorFinishOperation(message, type) {
                if (window.megaOperationManager) window.megaOperationManager.end();
                else if (window.megaHideWorking) window.megaHideWorking();
                if (message) megaEditorResult(message, type || 'info');
            }
            function megaEditorResponseIsSuccess(response, operation) {
                var value = String(response == null ? '' : response).trim();
                if (operation === 'save') return value === '1' || value === 'true' || value === 'OK' || value === 'ok' || value === 'success';
                if (operation === 'backup') return /^Backup .+ created\s*$/i.test(value);
                return false;
            }
            // Create file backup with .bck
            var megaEditorBackupPending = false;
            function backup(e, t) {
                if (megaEditorBackupPending) return false;
                megaEditorBackupPending = true;
                if (window.megaOperationManager) window.megaOperationManager.begin('backup');
                var request = new XMLHttpRequest();
                var payload = "path=" + e + "&file=" + t + "&token=" + encodeURIComponent(window.csrf) + "&type=backup&ajax=true";
                function finish() {
                    megaEditorBackupPending = false;
                    megaEditorFinishOperation();
                }
                request.open('POST', '', true);
                request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                request.onload = function() {
                    finish();
                    if (request.status >= 200 && request.status < 300 && megaEditorResponseIsSuccess(request.responseText, 'backup')) megaEditorResult(<?php echo json_encode(lng('Backup completed')); ?>, 'success');
                    else megaEditorResult(<?php echo json_encode(lng('Backup failed')); ?> + ' (HTTP ' + request.status + ')', 'error');
                };
                request.onerror = function() { finish(); megaEditorResult(<?php echo json_encode(lng('Backup failed: network error')); ?>, 'error'); };
                request.ontimeout = function() { finish(); megaEditorResult(<?php echo json_encode(lng('Backup failed') . ': ' . lng('Request timed out')); ?>, 'error'); };
                request.onabort = finish;
                request.timeout = 120000;
                try { request.send(payload); } catch (err) { finish(); megaEditorResult(<?php echo json_encode(lng('Backup failed')); ?>, 'error'); }
                return false;
            }

            document.addEventListener('DOMContentLoaded', function() {
                var result = document.getElementById('megaEditorResult');
                var toolbar = document.querySelector('.mega-editor-toolbar, .mega-editor-header, .mega-editor-shell, .mega-editor-card');
                if (result && toolbar && toolbar.parentNode) toolbar.parentNode.insertBefore(result, toolbar);
            });
            // Shared inline operation-result component, matching fm_show_message() notices.
            // Always use textContent for server responses (never inject server HTML).
            function megaEditorResult(message, type) {
                // Reuse a single visible result host immediately below the editor
                // action buttons, rather than adding a notice after the full editor.
                var host = document.getElementById('megaEditorResult');
                if (!host) {
                    host = document.createElement('div');
                    host.id = 'megaEditorResult';
                    var actions = document.querySelector('.mega-editor-actions');
                    if (actions && actions.parentNode) actions.parentNode.insertBefore(host, actions.nextSibling);
                    else document.body.appendChild(host);
                }
                var kind = (type === 'error' || type === 'warning' || type === 'info') ? type : 'success';
                host.className = 'mega-inline-notice mega-inline-notice--' + kind;
                host.setAttribute('role', kind === 'error' ? 'alert' : 'status');
                host.setAttribute('aria-live', kind === 'error' ? 'assertive' : 'polite');
                host.textContent = String(message || <?php echo json_encode(lng('Operation completed')); ?>);
                host.hidden = false;
                host.style.display = 'block';
                if (window.megaEditorResultTimer) clearTimeout(window.megaEditorResultTimer);
                window.megaEditorResultTimer = setTimeout(function () {
                    host.hidden = true;
                    host.style.display = 'none';
                }, 5000);
            }
            // Backward-compatible alias for other editor actions still calling toast().
            function toast(message, type) { megaEditorResult(message, type || 'success'); }

            // Save file
            var megaEditorSavePending = false;
            function edit_save(e, t) {
                if (megaEditorSavePending) return false;
                var n = "ace" == t ? editor.getSession().getValue() : document.getElementById("normal-editor").value;
                if (typeof n !== 'undefined' && n !== null) {
                    if (true) {
                        var data = {
                            ajax: true,
                            content: n,
                            type: 'save',
                            token: window.csrf
                        };

                        megaEditorSavePending = true;
                        if (window.megaOperationManager) window.megaOperationManager.begin('save');
                        var saveFinished = false;
                        var saveRequest = null;
                        // Do not leave the entire editor blocked when a MEGA backend
                        // response hangs after committing the file.
                        var saveWatchdog = setTimeout(function() {
                            if (saveFinished) return;
                            finishSave();
                            if (saveRequest && saveRequest.readyState !== 4) saveRequest.abort();
                            megaEditorResult(<?php echo json_encode(lng('Save failed') . ': '); ?> +
                                <?php echo json_encode(lng('The server did not confirm completion. The file may already have been saved; check before retrying.')); ?>, 'error');
                        }, 60000);
                        function finishSave() {
                            if (saveFinished) return false;
                            saveFinished = true;
                            clearTimeout(saveWatchdog);
                            megaEditorSavePending = false;
                            megaEditorFinishOperation();
                            return true;
                        }
                        saveRequest = $.ajax({
                            type: "POST",
                            url: window.location,
                            data: JSON.stringify(data),
                            contentType: "application/json; charset=utf-8",
                            timeout: 55000,
                            success: function(mes) {
                                if (!finishSave()) return;
                                if (megaEditorResponseIsSuccess(mes, 'save')) {
                                    window.megaAceDirty = false;
                                    megaEditorResult(<?php echo json_encode(lng('Saved Successfully')); ?>, 'success');
                                    window.onbeforeunload = function() { return; };
                                } else {
                                    megaEditorResult(<?php echo json_encode(lng('Save failed')); ?> + ': ' +
                                        (String(mes || '').trim() || <?php echo json_encode(lng('Unexpected server response')); ?>), 'error');
                                }
                            },
                            error: function(xhr, status) {
                                if (!finishSave()) return;
                                var detail = status === 'timeout'
                                    ? <?php echo json_encode(lng('The server did not confirm completion. The file may already have been saved; check before retrying.')); ?>
                                    : (xhr.responseText || xhr.statusText || <?php echo json_encode(lng('Please try again')); ?>);
                                megaEditorResult(<?php echo json_encode(lng('Save failed') . ': '); ?> + detail, 'error');
                            },
                            complete: function() {
                                // The success/error handlers normally close the indicator;
                                // this also covers unexpected jQuery callback ordering.
                                if (!saveFinished) finishSave();
                            }
                        });
                    } else {
                        var a = document.createElement("form");
                        a.setAttribute("method", "POST"), a.setAttribute("action", "");
                        var o = document.createElement("textarea");
                        o.setAttribute("type", "textarea"), o.setAttribute("name", "savedata");
                        let cx = document.createElement("input");
                        cx.setAttribute("type", "hidden");
                        cx.setAttribute("name", "token");
                        cx.setAttribute("value", window.csrf);
                        var c = document.createTextNode(n);
                        o.appendChild(c), a.appendChild(o), a.appendChild(cx), document.body.appendChild(a), a.submit()
                    }
                }
            }

            function show_new_pwd() {
                $(".js-new-pwd").toggleClass('hidden');
            }

            // Save Settings
            function save_settings($this) {
                try {
                    var prefs = {
                        lang: document.getElementById('js-language').value,
                        theme: document.getElementById('js-3-0').value,
                        view_mode: document.getElementById('js-view-mode').value,
                        delete_mode: document.getElementById('js-delete-mode') ? document.getElementById('js-delete-mode').value : 'rubbish',
                        show_hidden: document.getElementById('js-show-hidden').checked,
                        hide_Cols: true
                    };
                    if (prefs.theme !== 'dark' && prefs.theme !== 'light') throw new Error(<?php echo json_encode(lng('Invalid theme')); ?>);
                    if (['auto', 'mobile', 'desktop'].indexOf(prefs.view_mode) < 0) throw new Error('Invalid layout');
                    window.localStorage.setItem(window.megaPrefsStorageKey, JSON.stringify(prefs));
                    document.cookie = window.megaPrefsCookieName + '=' + encodeURIComponent(JSON.stringify(prefs)) +
                        '; path=' + window.megaPrefsCookiePath + '; max-age=31536000; SameSite=Lax' +
                        (location.protocol === 'https:' ? '; Secure' : '');
                    window.location.reload();
                } catch (error) {
                    window.megaNotify('error', <?php echo json_encode(lng('Unable to save browser settings. Check browser storage permissions.')); ?>);
                }
                return false;
            }

            //Create new password hash
            function new_password_hash($this) {
                let form = $($this),
                    $pwd = $("#js-pwd-result");
                $pwd.val('');
                $.ajax({
                    type: form.attr('method'),
                    url: form.attr('action'),
                    data: form.serialize() + "&token=" + window.csrf + "&ajax=" + true,
                    success: function(data) {
                        if (data) {
                            $pwd.val(data);
                        }
                    }
                });
                return false;
            }

            // Upload files using URL @param {Object}
            function upload_from_url($this) {
                var form = $($this), resultWrapper = $("div#js-url-upload__list");
                var input = form.find("input[name=uploadurl]");
                var button = form.find("button[type=submit]");
                var loader = form.find(".lds-facebook");
                if (form.data('megaUrlUploading')) return false;
                form.data('megaUrlUploading', true);
                var id = 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2, 14);
                var settled = false, pollTimer = null, request = null, pollInFlight = false;
                var originalUrl = input.val();
                // Serialize before disabling controls: jQuery omits disabled inputs.
                // Otherwise uploadurl is absent and the PHP upload handler never runs.
                var uploadPayload = form.serialize() + '&token=' + encodeURIComponent(window.csrf) + '&ajax=true&upload_id=' + encodeURIComponent(id);
                var errorLabel = <?php echo json_encode(lng('Error')); ?>;
                var successLabel = <?php echo json_encode(lng('Uploaded Successful')); ?>;
                function finish(ok, message) {
                    if (settled) return;
                    settled = true;
                    if (pollTimer) clearInterval(pollTimer);
                    input.prop('disabled', false);
                    button.prop('disabled', false).show();
                    loader.removeClass('show-me').hide();
                    form.data('megaUrlUploading', false);
                    if (window.megaOperationManager) window.megaOperationManager.end();
                    else if (window.megaHideWorking) window.megaHideWorking();
                    // A dedicated visible result host avoids inserting notices into
                    // a hidden tab, an unrelated parent, or a detached node.
                    var noticeHost = document.getElementById('megaUrlUploadResultHost');
                    if (!noticeHost) {
                        noticeHost = document.createElement('div');
                        noticeHost.id = 'megaUrlUploadResultHost';
                        noticeHost.className = 'mega-url-result-host';
                        var page = document.querySelector('.path');
                        if (page) page.insertBefore(noticeHost, page.firstChild);
                        else document.body.appendChild(noticeHost);
                    }
                    noticeHost.hidden = false;
                    noticeHost.style.display = 'block';
                    noticeHost.textContent = '';
                    var resultText = (ok ? successLabel : errorLabel) + ': ' + String(message || '');
                    var notice;
                    if (typeof window.megaNotify === 'function') {
                        notice = window.megaNotify(ok ? 'success' : 'error', resultText, noticeHost);
                    } else {
                        notice = document.createElement('div');
                        notice.className = 'mega-inline-notice mega-inline-notice--' + (ok ? 'success' : 'error');
                        notice.setAttribute('role', ok ? 'status' : 'alert');
                        notice.textContent = resultText;
                        noticeHost.appendChild(notice);
                        setTimeout(function(){ notice.hidden = true; }, 5000);
                    }
                    notice.classList.add('mega-url-upload-result');
                    notice.hidden = false;
                    notice.style.display = 'block';
                    // Do not scroll or move the notice after it is scheduled:
                    // it must remain in the visible upload page for five seconds.
                    if (ok) input.val('');
                    // Stop waiting for an HTTP response if the independent status
                    // endpoint has already confirmed completion.
                    if (request && request.readyState !== 4) request.abort();
                }
                function poll() {
                    if (settled || pollInFlight) return;
                    pollInFlight = true;
                    $.ajax({type:'POST', url:form.attr('action') || window.location.href,
                        data:{ajax:true, type:'url_upload_status', upload_id:id, token:window.csrf},
                        dataType:'json', timeout:12000, cache:false
                    }).done(function(state) {
                        if (!state) return;
                        if (state.state === 'done') finish(true, state.name || originalUrl.split('/').pop());
                        else if (state.state === 'failed') finish(false, state.message || errorLabel);
                    }).always(function(){pollInFlight = false;});
                }
                resultWrapper.empty();
                $('.mega-url-upload-result').remove();
                input.prop('disabled', true);
                button.prop('disabled', true).hide();
                // URL uploads use the same localized processing dialog as other MEGA operations.
                // The independent status poll remains responsible for closing it on completion.
                loader.removeClass('show-me').hide();
                if (window.megaHideWorking) window.megaHideWorking();
                if (window.megaShowWorking) window.megaShowWorking('upload');
                pollTimer = setInterval(poll, 2000);
                request = $.ajax({
                    type: form.attr('method'), url: form.attr('action'),
                    data: uploadPayload,
                    dataType:'json', timeout:180000
                }).done(function(data){
                    if (settled) return;
                    if (data && data.done) finish(true, data.done.name || originalUrl.split('/').pop());
                    else finish(false, data && data.fail && data.fail.message ? data.fail.message : errorLabel);
                }).fail(function(xhr,status){
                    if (!settled) finish(false, status === 'timeout' ? <?php echo json_encode(lng('Request timed out')); ?> : <?php echo json_encode(lng('URL upload request failed')); ?>);
                });
                return false;
            }

            // Search template
            function search_template(data) {
                var response = "";
                $.each(data, function(key, val) {
                    response += `<li><a href="?p=${val.path}&view=${val.name}">${val.path}/${val.name}</a></li>`;
                });
                return response;
            }

            // Advance search
            function fm_search() {
                var searchTxt = $("input#advanced-search").val(),
                    searchWrapper = $("ul#search-wrapper"),
                    path = $("#js-search-modal").attr("href"),
                    _html = "",
                    $loader = $("div.lds-facebook");
                if (!!searchTxt && searchTxt.length > 2 && path) {
                    var data = {
                        ajax: true,
                        content: searchTxt,
                        path: path,
                        type: 'search',
                        token: window.csrf
                    };
                    $.ajax({
                        type: "POST",
                        url: window.location,
                        data: data,
                        beforeSend: function() {
                            searchWrapper.html('');
                            $loader.addClass('show-me');
                        },
                        success: function(data) {
                            $loader.removeClass('show-me');
                            data = JSON.parse(data);
                            if (data && data.length) {
                                _html = search_template(data);
                                searchWrapper.html(_html);
                            } else {
                                searchWrapper.html('<p class="m-2"><?php echo lng("No result found!"); ?><p>');
                            }
                        },
                        error: function(xhr) {
                            $loader.removeClass('show-me');
                            searchWrapper.html('<p class="m-2"><?php echo lng("ERROR: Try again later!"); ?></p>');
                        },
                        failure: function(mes) {
                            $loader.removeClass('show-me');
                            searchWrapper.html('<p class="m-2"><?php echo lng("ERROR: Try again later!"); ?></p>');
                        }
                    });
                } else {
                    searchWrapper.html("<?php echo lng("OOPS: minimum 3 characters required!"); ?>");
                }
            }

            // action confirm dialog modal
            function confirmDialog(e, id = 0, title = "Action", content = "", action = null) {
                e.preventDefault();
                if (window.megaCloseRowMenus) window.megaCloseRowMenus();
                var fullName;
                try { fullName = decodeURIComponent(content.replace(/\+/g, ' ')); }
                catch (error) { fullName = String(content || ''); }
                var safeName = document.createElement('span'); safeName.textContent = fullName;
                const tplObj = {
                    id,
                    title,
                    content: safeName.innerHTML,
                    action,
                    confirmMessage: (function () {
                        var label = String(title || '').toLowerCase();
                        var phrases = <?php echo json_encode(array(
                            'file' => html_entity_decode(lng('Are you sure you want to delete this file?'), ENT_QUOTES, 'UTF-8'),
                            'folder' => html_entity_decode(lng('Are you sure you want to delete this folder?'), ENT_QUOTES, 'UTF-8'),
                            'item' => html_entity_decode(lng('Are you sure you want to delete this item?'), ENT_QUOTES, 'UTF-8')
                        ), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE); ?>;
                        if (label.indexOf('folder') >= 0 || label.indexOf(<?php echo json_encode(html_entity_decode(lng('Folder'), ENT_QUOTES, 'UTF-8')); ?>.toLowerCase()) >= 0) return phrases.folder;
                        if (label.indexOf('file') >= 0 || label.indexOf(<?php echo json_encode(html_entity_decode(lng('File'), ENT_QUOTES, 'UTF-8')); ?>.toLowerCase()) >= 0) return phrases.file;
                        return phrases.item;
                    })()
                };
                let tpl = $("#js-tpl-confirm").html();
                $(".modal.confirmDialog").remove();
                $('#wrapper').append(template(tpl, tplObj));
                const $confirmDialog = $("#confirmDialog-" + tplObj.id);
                $confirmDialog.find('.fm-confirm-filename').attr('title', fullName);
                $confirmDialog.modal('show');
                return false;
            }

            // on mouse hover image preview
            ! function(s) {
                s.previewImage = function(e) {
                    var o = s(document),
                        t = ".previewImage",
                        a = s.extend({
                            xOffset: 20,
                            yOffset: -20,
                            fadeIn: "fast",
                            css: {
                                padding: "5px",
                                border: "1px solid #cccccc",
                                "background-color": "#fff"
                            },
                            eventSelector: "[data-preview-image]",
                            dataKey: "previewImage",
                            overlayId: "preview-image-plugin-overlay"
                        }, e);
                    return o.off(t), o.on("mouseover" + t, a.eventSelector, function(e) {
                        s("p#" + a.overlayId).remove();
                        var o = s("<p>").attr("id", a.overlayId).css("position", "absolute").css("display", "none").append(s('<img class="c-preview-img">').attr("src", s(this).data(a.dataKey)));
                        a.css && o.css(a.css), s("body").append(o), o.css("top", e.pageY + a.yOffset + "px").css("left", e.pageX + a.xOffset + "px").fadeIn(a.fadeIn)
                    }), o.on("mouseout" + t, a.eventSelector, function() {
                        s("#" + a.overlayId).remove()
                    }), o.on("mousemove" + t, a.eventSelector, function(e) {
                        s("#" + a.overlayId).css("top", e.pageY + a.yOffset + "px").css("left", e.pageX + a.xOffset + "px")
                    }), this
                }, s.previewImage()
            }(jQuery);

            // Dom Ready Events
            $(document).ready(function() {
                // DataTables custom Name sorting: parent, folders, files.
                // Comparators keep the group order fixed in BOTH directions.
                function fmNameParts(value) {
                    var text = String(value || '');
                    var separator = text.indexOf('~');
                    return {
                        group: parseInt(text.substring(0, separator), 10) || 0,
                        name: text.substring(separator + 1)
                    };
                }
                $.fn.dataTable.ext.type.order['fm-folder-name-asc'] = function(a, b) {
                    var x = fmNameParts(a), y = fmNameParts(b);
                    if (x.group !== y.group) return x.group - y.group;
                    return x.name.localeCompare(y.name, undefined, {numeric: true, sensitivity: 'base'});
                };
                $.fn.dataTable.ext.type.order['fm-folder-name-desc'] = function(a, b) {
                    var x = fmNameParts(a), y = fmNameParts(b);
                    if (x.group !== y.group) return x.group - y.group;
                    return y.name.localeCompare(x.name, undefined, {numeric: true, sensitivity: 'base'});
                };
                var $table = $('#main-table'),
                    tableLng = $table.find('th').length,
                    nameColumn = <?php echo FM_READONLY ? 0 : 1; ?>,
                    _targets = (tableLng && tableLng == 7) ? [0, 4, 5, 6] : tableLng == 5 ? [0, 4] : [3];
                mainTable = $table.DataTable({
                    paging: false,
                    info: false,
                    order: [],
                    columnDefs: [{
                        targets: nameColumn,
                        type: 'fm-folder-name',
                        render: function(data, type, row, meta) {
                            if (type !== 'sort' && type !== 'type') return data;
                            var tr = meta.settings.aoData[meta.row].nTr;
                            var $tr = $(tr);
                            var group = $tr.hasClass('fm-parent-folder-row') ? 0 :
                                ($tr.hasClass('fm-folder-row') ? 1 : 2);
                            var name = $('<div>').html(data).text().trim().toLowerCase();
                            return group + '~' + name;
                        }
                    }, {
                        targets: _targets,
                        orderable: false
                    }],
                    drawCallback: function() {
                        // Keep the parent, folders, then files after every sort/filter.
                        // Stable partition preserves DataTables' selected sort order
                        // within each group, in both ascending and descending order.
                        var body = this.api().table().body();
                        var rows = Array.prototype.slice.call(body.children);
                        [0, 1, 2].forEach(function(group) {
                            rows.forEach(function(row) {
                                var kind = row.classList.contains('fm-parent-folder-row') ? 0 :
                                    (row.classList.contains('fm-folder-row') ? 1 : 2);
                                if (kind === group) body.appendChild(row);
                            });
                        });
                    }
                });

                // filter table
                $('#search-addon').on('keyup', function() {
                    mainTable.search(this.value).draw();
                });

                $("input#advanced-search").on('keyup', function(e) {
                    if (e.keyCode === 13) {
                        fm_search();
                    }
                });

                $('#search-addon3').on('click', function() {
                    fm_search();
                });

                //upload nav tabs
                $(".fm-upload-wrapper .card-header-tabs").on("click", 'a', function(e) {
                    e.preventDefault();
                    let target = $(this).data('target');
                    $(".fm-upload-wrapper .card-header-tabs a").removeClass('active');
                    $(this).addClass('active');
                    $(".fm-upload-wrapper .card-tabs-container").addClass('hidden');
                    $(target).removeClass('hidden');
                    // File-upload cancel belongs only to the file upload tab.
                    // URL upload already has its own Cancel / Upload action row.
                    $(".fm-file-upload-actions").toggleClass('hidden', target !== '#fileUploader');
                });
            });
        </script>

        <style>
          /* The editor must match the selected File Manager appearance. */
          body.theme-dark #editor { background:#1d252c!important; color:#e5edf5!important; }
          body.theme-dark #editor.ace_editor { border-color:#46525e; }
          body.theme-dark #editor .ace_gutter { background:#252f39!important; color:#aebdcb!important; }
          body.theme-dark #editor .ace_scroller { background:#1d252c!important; }
          body.theme-dark #editor .ace_cursor { color:#62aaff!important; border-left-color:#62aaff!important; }
          body.theme-dark #editor .ace_marker-layer .ace_active-line { background:rgba(118,154,193,.12)!important; }
          body.theme-dark #editor .ace_gutter-active-line { background:#334251!important; }
        </style>
        <?php if (isset($_GET['edit']) && isset($_GET['env']) && FM_EDIT_FILE && !FM_READONLY):
            $ext = pathinfo($_GET["edit"], PATHINFO_EXTENSION);
            $ext =  isset($ext_language[$ext]) ? $ext_language[$ext] :  $ext;
        ?>
            <?php print_external('js-ace'); ?>
            <script>
                var editor = ace.edit("editor");
                editor.getSession().setMode({
                    path: "ace/mode/<?php echo $ext; ?>",
                    inline: true
                });
                // Follow the File Manager theme instead of forcing the configured light Ace theme.
                var megaAceDark = document.body.classList.contains('theme-dark');
                editor.setTheme(megaAceDark ? 'ace/theme/tomorrow_night' : 'ace/theme/<?php echo ACE_THEME; ?>');
                editor.setShowPrintMargin(false); // Hide the vertical ruler
                // Better on-screen keyboard behavior and readability on phones.
                editor.setOptions({enableBasicAutocompletion:false, enableLiveAutocompletion:false});
                editor.getSession().setUseWrapMode(window.matchMedia && window.matchMedia('(max-width: 700px)').matches);
                if (window.matchMedia && window.matchMedia('(max-width: 700px)').matches) editor.setFontSize(Math.max(14, <?php echo (int) ACE_FONTSIZE; ?>));
                window.megaAceDirty = false;
                editor.getSession().on('change', function(){ window.megaAceDirty = true; });
                window.addEventListener('beforeunload', function(ev){
                    if (!window.megaAceDirty) return;
                    ev.preventDefault(); ev.returnValue = '';
                });

                function ace_commend(cmd) {
                    editor.commands.exec(cmd, editor);
                }
                editor.commands.addCommands([{
                    name: 'save',
                    bindKey: {
                        win: 'Ctrl-S',
                        mac: 'Command-S'
                    },
                    exec: function(editor) {
                        edit_save(this, 'ace');
                    }
                }]);

                function renderThemeMode() {
                    var $modeEl = $("select#js-ace-mode"),
                        $themeEl = $("select#js-ace-theme"),
                        $fontSizeEl = $("select#js-ace-fontSize"),
                        optionNode = function(type, arr) {
                            var $Option = "";
                            $.each(arr, function(i, val) {
                                $Option += "<option value='" + type + i + "'>" + val + "</option>";
                            });
                            return $Option;
                        },
                        _data = {
                            "aceTheme": {
                                "bright": {
                                    "chrome": "Chrome",
                                    "clouds": "Clouds",
                                    "crimson_editor": "Crimson Editor",
                                    "dawn": "Dawn",
                                    "dreamweaver": "Dreamweaver",
                                    "eclipse": "Eclipse",
                                    "github": "GitHub",
                                    "iplastic": "IPlastic",
                                    "solarized_light": "Solarized Light",
                                    "textmate": "TextMate",
                                    "tomorrow": "Tomorrow",
                                    "xcode": "XCode",
                                    "kuroir": "Kuroir",
                                    "katzenmilch": "KatzenMilch",
                                    "sqlserver": "SQL Server"
                                },
                                "dark": {
                                    "ambiance": "Ambiance",
                                    "chaos": "Chaos",
                                    "clouds_midnight": "Clouds Midnight",
                                    "dracula": "Dracula",
                                    "cobalt": "Cobalt",
                                    "gruvbox": "Gruvbox",
                                    "gob": "Green on Black",
                                    "idle_fingers": "idle Fingers",
                                    "kr_theme": "krTheme",
                                    "merbivore": "Merbivore",
                                    "merbivore_soft": "Merbivore Soft",
                                    "mono_industrial": "Mono Industrial",
                                    "monokai": "Monokai",
                                    "pastel_on_dark": "Pastel on dark",
                                    "solarized_dark": "Solarized Dark",
                                    "terminal": "Terminal",
                                    "tomorrow_night": "Tomorrow Night",
                                    "tomorrow_night_blue": "Tomorrow Night Blue",
                                    "tomorrow_night_bright": "Tomorrow Night Bright",
                                    "tomorrow_night_eighties": "Tomorrow Night 80s",
                                    "twilight": "Twilight",
                                    "vibrant_ink": "Vibrant Ink"
                                }
                            },
                            "aceMode": {
                                "javascript": "JavaScript",
                                "abap": "ABAP",
                                "abc": "ABC",
                                "actionscript": "ActionScript",
                                "ada": "ADA",
                                "apache_conf": "Apache Conf",
                                "asciidoc": "AsciiDoc",
                                "asl": "ASL",
                                "assembly_x86": "Assembly x86",
                                "autohotkey": "AutoHotKey",
                                "apex": "Apex",
                                "batchfile": "BatchFile",
                                "bro": "Bro",
                                "c_cpp": "C and C++",
                                "c9search": "C9Search",
                                "cirru": "Cirru",
                                "clojure": "Clojure",
                                "cobol": "Cobol",
                                "coffee": "CoffeeScript",
                                "coldfusion": "ColdFusion",
                                "csharp": "C#",
                                "csound_document": "Csound Document",
                                "csound_orchestra": "Csound",
                                "csound_score": "Csound Score",
                                "css": "CSS",
                                "curly": "Curly",
                                "d": "D",
                                "dart": "Dart",
                                "diff": "Diff",
                                "dockerfile": "Dockerfile",
                                "dot": "Dot",
                                "drools": "Drools",
                                "edifact": "Edifact",
                                "eiffel": "Eiffel",
                                "ejs": "EJS",
                                "elixir": "Elixir",
                                "elm": "Elm",
                                "erlang": "Erlang",
                                "forth": "Forth",
                                "fortran": "Fortran",
                                "fsharp": "FSharp",
                                "fsl": "FSL",
                                "ftl": "FreeMarker",
                                "gcode": "Gcode",
                                "gherkin": "Gherkin",
                                "gitignore": "Gitignore",
                                "glsl": "Glsl",
                                "gobstones": "Gobstones",
                                "golang": "Go",
                                "graphqlschema": "GraphQLSchema",
                                "groovy": "Groovy",
                                "haml": "HAML",
                                "handlebars": "Handlebars",
                                "haskell": "Haskell",
                                "haskell_cabal": "Haskell Cabal",
                                "haxe": "haXe",
                                "hjson": "Hjson",
                                "html": "HTML",
                                "html_elixir": "HTML (Elixir)",
                                "html_ruby": "HTML (Ruby)",
                                "ini": "INI",
                                "io": "Io",
                                "jack": "Jack",
                                "jade": "Jade",
                                "java": "Java",
                                "json": "JSON",
                                "jsoniq": "JSONiq",
                                "jsp": "JSP",
                                "jssm": "JSSM",
                                "jsx": "JSX",
                                "julia": "Julia",
                                "kotlin": "Kotlin",
                                "latex": "LaTeX",
                                "less": "LESS",
                                "liquid": "Liquid",
                                "lisp": "Lisp",
                                "livescript": "LiveScript",
                                "logiql": "LogiQL",
                                "lsl": "LSL",
                                "lua": "Lua",
                                "luapage": "LuaPage",
                                "lucene": "Lucene",
                                "makefile": "Makefile",
                                "markdown": "Markdown",
                                "mask": "Mask",
                                "matlab": "MATLAB",
                                "maze": "Maze",
                                "mel": "MEL",
                                "mixal": "MIXAL",
                                "mushcode": "MUSHCode",
                                "mysql": "MySQL",
                                "nix": "Nix",
                                "nsis": "NSIS",
                                "objectivec": "Objective-C",
                                "ocaml": "OCaml",
                                "pascal": "Pascal",
                                "perl": "Perl",
                                "perl6": "Perl 6",
                                "pgsql": "pgSQL",
                                "php_laravel_blade": "PHP (Blade Template)",
                                "php": "PHP",
                                "puppet": "Puppet",
                                "pig": "Pig",
                                "powershell": "Powershell",
                                "praat": "Praat",
                                "prolog": "Prolog",
                                "properties": "Properties",
                                "protobuf": "Protobuf",
                                "python": "Python",
                                "r": "R",
                                "razor": "Razor",
                                "rdoc": "RDoc",
                                "red": "Red",
                                "rhtml": "RHTML",
                                "rst": "RST",
                                "ruby": "Ruby",
                                "rust": "Rust",
                                "sass": "SASS",
                                "scad": "SCAD",
                                "scala": "Scala",
                                "scheme": "Scheme",
                                "scss": "SCSS",
                                "sh": "SH",
                                "sjs": "SJS",
                                "slim": "Slim",
                                "smarty": "Smarty",
                                "snippets": "snippets",
                                "soy_template": "Soy Template",
                                "space": "Space",
                                "sql": "SQL",
                                "sqlserver": "SQLServer",
                                "stylus": "Stylus",
                                "svg": "SVG",
                                "swift": "Swift",
                                "tcl": "Tcl",
                                "terraform": "Terraform",
                                "tex": "Tex",
                                "text": "Text",
                                "textile": "Textile",
                                "toml": "Toml",
                                "tsx": "TSX",
                                "twig": "Twig",
                                "typescript": "Typescript",
                                "vala": "Vala",
                                "vbscript": "VBScript",
                                "velocity": "Velocity",
                                "verilog": "Verilog",
                                "vhdl": "VHDL",
                                "visualforce": "Visualforce",
                                "wollok": "Wollok",
                                "xml": "XML",
                                "xquery": "XQuery",
                                "yaml": "YAML",
                                "django": "Django"
                            },
                            "fontSize": {
                                8: 8,
                                10: 10,
                                11: 11,
                                12: 12,
                                13: 13,
                                14: 14,
                                15: 15,
                                16: 16,
                                17: 17,
                                18: 18,
                                20: 20,
                                22: 22,
                                24: 24,
                                26: 26,
                                30: 30
                            }
                        };
                    if (_data && _data.aceMode) {
                        $modeEl.html(optionNode("ace/mode/", _data.aceMode));
                    }
                    if (_data && _data.aceTheme) {
                        var lightTheme = optionNode("ace/theme/", _data.aceTheme.bright),
                            darkTheme = optionNode("ace/theme/", _data.aceTheme.dark);
                        $themeEl.html("<optgroup label=\"Bright\">" + lightTheme + "</optgroup><optgroup label=\"Dark\">" + darkTheme + "</optgroup>");
                    }
                    if (_data && _data.fontSize) {
                        $fontSizeEl.html(optionNode("", _data.fontSize));
                    }
                    $modeEl.val(editor.getSession().$modeId);
                    $themeEl.val(editor.getTheme());
                    $(function() {
                        // Apply font size directly, then sync dropdown
                        editor.setFontSize(<?php echo (int) ACE_FONTSIZE; ?>);
                        $fontSizeEl.val(<?php echo (int) ACE_FONTSIZE; ?>);
                    });
                }

                $(function() {
                    renderThemeMode();
                    $(".js-ace-toolbar").on("click", 'button', function(e) {
                        e.preventDefault();
                        let cmdValue = $(this).attr("data-cmd"),
                            editorOption = $(this).attr("data-option");
                        if (cmdValue && cmdValue != "none") {
                            ace_commend(cmdValue);
                        } else if (editorOption) {
                            if (editorOption == "fullscreen") {
                                (void 0 !== document.fullScreenElement && null === document.fullScreenElement || void 0 !== document.msFullscreenElement && null === document.msFullscreenElement || void 0 !== document.mozFullScreen && !document.mozFullScreen || void 0 !== document.webkitIsFullScreen && !document.webkitIsFullScreen) &&
                                (editor.container.requestFullScreen ? editor.container.requestFullScreen() : editor.container.mozRequestFullScreen ? editor.container.mozRequestFullScreen() : editor.container.webkitRequestFullScreen ? editor.container.webkitRequestFullScreen(Element.ALLOW_KEYBOARD_INPUT) : editor.container.msRequestFullscreen && editor.container.msRequestFullscreen());
                            } else if (editorOption == "tab") {
                                editor.insert("\t");
                                editor.focus();
                            } else if (editorOption == "outdent") {
                                editor.blockOutdent();
                                editor.focus();
                            } else if (editorOption == "save") {
                                edit_save(null, 'ace');
                            } else if (editorOption == "wrap") {
                                let wrapStatus = (editor.getSession().getUseWrapMode()) ? false : true;
                                editor.getSession().setUseWrapMode(wrapStatus);
                            }
                        }
                    });

                    $("select#js-ace-mode, select#js-ace-theme, select#js-ace-fontSize").on("change", function(e) {
                        e.preventDefault();
                        let selectedValue = $(this).val(),
                            selectionType = $(this).attr("data-type");
                        if (selectedValue && selectionType == "mode") {
                            editor.getSession().setMode(selectedValue);
                        } else if (selectedValue && selectionType == "theme") {
                            editor.setTheme(selectedValue);
                        } else if (selectedValue && selectionType == "fontSize") {
                            editor.setFontSize(parseInt(selectedValue));
                        }
                    });
                });
            </script>
        <?php endif; ?>
        
    <script>
            /* Match the content offset to the real fixed header height, including
               wrapped breadcrumbs and the expanded mobile navigation. */
            (function () {
                function updateFixedNavHeight() {
                    var nav = document.querySelector('.main-nav.fixed-top');
                    if (!nav) return;
                    var height = Math.ceil(nav.getBoundingClientRect().height);
                    if (height > 0) document.documentElement.style.setProperty('--fm-nav-height', height + 'px');
                }
                document.addEventListener('DOMContentLoaded', function () {
                    updateFixedNavHeight();
                    var nav = document.querySelector('.main-nav.fixed-top');
                    if (nav && window.ResizeObserver) {
                        new ResizeObserver(updateFixedNavHeight).observe(nav);
                    }
                    window.addEventListener('resize', updateFixedNavHeight);
                    if (nav) nav.addEventListener('transitionend', updateFixedNavHeight);
                });
            })();
</script>
    <style>
/* Unified operation dialogs and inline notifications. */
/* Shared compact inline notices for errors, success, warning and information. */
.mega-inline-notice{box-sizing:border-box;margin:0!important;padding:5px 9px!important;line-height:1.25!important;border:1px solid;border-radius:0;font-size:inherit;background:transparent;overflow-wrap:anywhere}
.mega-inline-notice--error{color:#b42318;border-color:#dc3545}
.mega-inline-notice--success{color:#198754;border-color:#198754}
.mega-inline-notice--warning{color:#a66a00;border-color:#d49b29}
.mega-inline-notice--info{color:#0b6fa4;border-color:#0d6efd}
[data-bs-theme="dark"] .mega-inline-notice--error{color:#ff8585}
[data-bs-theme="dark"] .mega-inline-notice--success{color:#74d7a3}
[data-bs-theme="dark"] .mega-inline-notice--warning{color:#ffcf70}
[data-bs-theme="dark"] .mega-inline-notice--info{color:#87caff}
/* Theme-consistent file labels, selection buttons and preview actions */
body.theme-dark #main-table .filename a,[data-bs-theme="dark"] #main-table .filename a,
body.theme-dark #main-table .filename a:visited,[data-bs-theme="dark"] #main-table .filename a:visited,
body.theme-dark .bread-crumb,[data-bs-theme="dark"] .bread-crumb{color:#f1f5f9!important}
body.theme-dark .mega-actions,[data-bs-theme="dark"] .mega-actions{background:#293138!important;border-color:#48525d!important;box-shadow:none!important}
body.theme-dark .mega-selection-count,[data-bs-theme="dark"] .mega-selection-count{color:#f1f5f9!important}
body.theme-dark .mega-action,[data-bs-theme="dark"] .mega-action,
body.theme-dark .mega-clear,[data-bs-theme="dark"] .mega-clear{background:#37414b!important;border-color:#596674!important;color:#f1f5f9!important}
body.theme-dark .mega-action:hover:not(.disabled),[data-bs-theme="dark"] .mega-action:hover:not(.disabled),
body.theme-dark .mega-clear:hover,[data-bs-theme="dark"] .mega-clear:hover{background:#465362!important}
body.theme-dark .mega-action i,[data-bs-theme="dark"] .mega-action i{color:#9ac9ff!important}
body.theme-dark .mega-action.danger,[data-bs-theme="dark"] .mega-action.danger,
body.theme-dark .mega-action.danger i,[data-bs-theme="dark"] .mega-action.danger i{color:#ff9da6!important}
body.theme-dark .mega-action-separator,[data-bs-theme="dark"] .mega-action-separator{background:#48525d!important}
body.theme-dark .mega-preview-actions .btn,[data-bs-theme="dark"] .mega-preview-actions .btn{background:#37414b!important;color:#f1f5f9!important;border-color:#596674!important}
body.theme-dark .mega-preview-actions .btn:hover,[data-bs-theme="dark"] .mega-preview-actions .btn:hover{background:#465362!important}
body.theme-dark .mega-preview-actions .mega-danger,[data-bs-theme="dark"] .mega-preview-actions .mega-danger{background:#4c3037!important;color:#ffb1b8!important;border-color:#81535c!important}
body.theme-dark #main-table tfoot .badge,[data-bs-theme="dark"] #main-table tfoot .badge{background:#37414b!important;color:#f1f5f9!important;border-color:#596674!important}

/* Preview dark theme, scoped to preview content only. Keep original media/document colors. */
body.theme-dark .mega-preview-content {color:#e5edf5;color-scheme:dark}
body.theme-dark .mega-preview-content pre,
body.theme-dark .mega-preview-content pre code,
body.theme-dark .mega-preview-content pre code.hljs,
body.theme-dark .mega-preview-content code.maxheight,
body.theme-dark .mega-preview-content .hljs {
 background:#1d252c!important;color:#e5edf5!important;
}
body.theme-dark .mega-preview-content pre {border:1px solid #465462;border-radius:8px;overflow:auto;max-width:100%;}
body.theme-dark .mega-preview-content pre code {display:block;padding:14px;white-space:pre;overflow:auto}
body.theme-dark .mega-preview-content .hljs-keyword,
body.theme-dark .mega-preview-content .hljs-selector-tag,
body.theme-dark .mega-preview-content .hljs-built_in {color:#a8c9ff!important}
body.theme-dark .mega-preview-content .hljs-string,
body.theme-dark .mega-preview-content .hljs-title {color:#a8e4c6!important}
body.theme-dark .mega-preview-content .hljs-comment {color:#aeb9c4!important}
body.theme-dark .mega-preview-content #mega-pdf-viewer,
body.theme-dark .mega-preview-content #mega-pptx-viewer,
body.theme-dark .mega-preview-content #mega-docx-viewer,
body.theme-dark .mega-preview-content #mega-excel-viewer,
body.theme-dark .mega-preview-content #mega-vsdx-viewer {
 background:#1d252c!important;color:#e5edf5!important;border-color:#465462!important;
}
body.theme-dark .mega-preview-content #mega-pdf-viewer > div:first-child,
body.theme-dark .mega-preview-content #mega-pptx-viewer > div:first-child,
body.theme-dark .mega-preview-content #mega-docx-toolbar,
body.theme-dark .mega-preview-content #mega-excel-viewer > div:first-child,
body.theme-dark .mega-preview-content #mega-vsdx-viewer > div:first-child {
 background:#293138!important;color:#e5edf5!important;border-bottom-color:#465462!important;
}
body.theme-dark .mega-preview-content #mega-pdf-pages,
body.theme-dark .mega-preview-content #mega-docx-pages,
body.theme-dark .mega-preview-content #mega-vsdx-scroll,
body.theme-dark .mega-preview-content #mega-excel-scroll,
body.theme-dark .mega-preview-content #mega-pptx-viewer > div:nth-child(3) {
 background:#1d252c!important;
}
body.theme-dark .mega-preview-content #mega-pdf-viewer .btn,
body.theme-dark .mega-preview-content #mega-pptx-viewer .btn,
body.theme-dark .mega-preview-content #mega-docx-viewer .btn,
body.theme-dark .mega-preview-content #mega-excel-viewer .btn,
body.theme-dark .mega-preview-content #mega-vsdx-viewer .btn {
 background:#37414b!important;color:#f1f5f9!important;border-color:#596674!important;
}
body.theme-dark .mega-preview-content #mega-pdf-viewer .btn:hover,
body.theme-dark .mega-preview-content #mega-pptx-viewer .btn:hover,
body.theme-dark .mega-preview-content #mega-docx-viewer .btn:hover,
body.theme-dark .mega-preview-content #mega-excel-viewer .btn:hover,
body.theme-dark .mega-preview-content #mega-vsdx-viewer .btn:hover {background:#465362!important}
body.theme-dark .mega-preview-content #mega-pptx-viewer > p,
body.theme-dark .mega-preview-content #mega-excel-viewer > div:last-child,
body.theme-dark .mega-preview-content #mega-vsdx-viewer > div:last-child {
 background:#293138!important;color:#cbd5e1!important;
}
/* Match the PDF document pages to the user-selected dark theme.
   Only the PDF canvas is color-adjusted; viewer buttons and text use the
   existing theme rules. The original PDF bytes are never modified. */
body.theme-dark .mega-preview-content #mega-pdf-pages canvas {
    filter: invert(0.88) hue-rotate(180deg);
    background-color: #1b2229;
    border-radius: 3px;
}
body:not(.theme-dark) .mega-preview-content #mega-pdf-pages canvas {
    filter: none;
    background-color: white;
}
body.theme-dark .mega-preview-content #mega-pdf-pages canvas,
body.theme-dark .mega-preview-content #pptx-slide,
body.theme-dark .mega-preview-content #mega-docx-document,
body.theme-dark .mega-preview-content #mega-excel-grid,
body.theme-dark .mega-preview-content #mega-vsdx-sheet {
 /* Do not recolor document content. */ color-scheme:light;
}
body.theme-dark .mega-preview-content .preview-video,
body.theme-dark .mega-preview-content audio,
body.theme-dark .mega-preview-content video {background:#1d252c;color-scheme:dark;max-width:100%}
body.theme-dark .mega-preview-content .preview-img {max-width:100%;height:auto}

/* Office preview contrast repair: scope to the Office viewer only. */
body.theme-dark #mega-pptx-viewer #pptx-slide {
 background:#ffffff!important;color:#182230!important;color-scheme:light!important;
}
body.theme-dark #mega-pptx-viewer #pptx-slide p,
body.theme-dark #mega-pptx-viewer #pptx-slide h3,
body.theme-dark #mega-pptx-viewer #pptx-slide span {
 color:#182230!important;
}
body.theme-dark #mega-pptx-viewer #pptx-status,
body.theme-dark #mega-excel-viewer #mega-excel-status {
 color:#e5edf5!important;background:#293138!important;
}
body.theme-dark #mega-excel-viewer #mega-excel-scroll,
body.theme-dark #mega-excel-viewer #mega-excel-grid {
 background:#1f2831!important;color:#f1f5f9!important;
}
body.theme-dark #mega-excel-viewer #mega-excel-grid table,
body.theme-dark #mega-excel-viewer #mega-excel-grid tbody,
body.theme-dark #mega-excel-viewer #mega-excel-grid tr,
body.theme-dark #mega-excel-viewer #mega-excel-grid td {
 background:#1f2831!important;color:#f1f5f9!important;
}
body.theme-dark #mega-excel-viewer #mega-excel-grid thead th {
 background:#34414d!important;color:#f1f5f9!important;
}
body.theme-dark #mega-excel-viewer #mega-excel-grid tbody th {
 background:#2b3742!important;color:#dbe5ef!important;
}
body.theme-dark #mega-excel-viewer #mega-excel-grid td,
body.theme-dark #mega-excel-viewer #mega-excel-grid th {
 border-color:#4a5866!important;
}




.mega-file-conflict{margin:0!important;padding:5px 9px!important;line-height:1.25!important}
.modal.modal-alert .modal-footer .btn{font-size:15px!important;min-height:44px!important;font-weight:500!important}
#megaBulkConfirm .modal-footer .btn,#renameDialog .modal-footer .btn,.confirmDialog .modal-footer .btn{line-height:1.15!important}
/* Keep confirmation scroll gutters visually continuous with the panel.
   Touch/keyboard scrolling is retained; only scrollbar chrome is hidden. */
.modal.modal-alert .modal-body{background-color:inherit;scrollbar-width:none!important}
.modal.modal-alert .modal-body::-webkit-scrollbar{width:0!important;height:0!important;background:transparent!important}
.modal.modal-alert .modal-content{scrollbar-width:none!important}
.modal.modal-alert .modal-content::-webkit-scrollbar{width:0!important;height:0!important;background:transparent!important}
/* Confirmation and processing use the same centered dialog footprint. */
:root{--mega-operation-dialog-width:380px;--mega-operation-dialog-height:140px;}
.modal.modal-alert.confirmDialog .modal-dialog,
#renameDialog .modal-dialog,
#megaBulkConfirm .modal-dialog,
#megaMessageDialog .modal-dialog {
  position:fixed!important;
  top:50%;left:50%;
  transform:translate(-50%,-50%);
  margin:0!important;
  width:min(calc(100vw - 40px),var(--mega-operation-dialog-width))!important;
  max-width:var(--mega-operation-dialog-width)!important;
}
.modal.modal-alert.confirmDialog .modal-content,
#renameDialog .modal-content,
#megaBulkConfirm .modal-content,
#megaMessageDialog .modal-content {height:var(--mega-operation-dialog-height);min-height:0;display:flex;justify-content:space-between;overflow:hidden;}
.modal.modal-alert.confirmDialog .modal-body,
#renameDialog .modal-body,
#megaBulkConfirm .modal-body,
#megaMessageDialog .modal-body {display:flex;flex:1;flex-direction:column;justify-content:center;min-height:0;padding:12px 16px!important;overflow-wrap:anywhere;}
/* Grow confirmation panels to the processing size, allowing long translations
   and editable forms to grow further rather than clipping their contents. */
.modal.modal-alert.confirmDialog .modal-content,
#megaBulkConfirm .modal-content,
#renameDialog .modal-content,
#megaMessageDialog .modal-content,
#megaStopSharingDialog .modal-content {
  box-sizing:border-box;
  height:auto!important;
  min-height:var(--mega-operation-dialog-height)!important;
}
/* Keep the action buttons compact; remove excess space around the question. */
.modal.modal-alert.confirmDialog .modal-footer,
#renameDialog .modal-footer,
#megaBulkConfirm .modal-footer,
#megaMessageDialog .modal-footer {min-height:46px!important;}
.modal.modal-alert.confirmDialog .modal-body h5,
#renameDialog .modal-body h5,
#megaBulkConfirm .modal-body h5 {margin:0!important;line-height:1.3;}
#megaBulkConfirm .modal-body p:empty {display:none;}
#renameDialog .modal-content,#megaMessageDialog .modal-content{height:auto;min-height:var(--mega-operation-dialog-height);}
/* Keep each shared link's two actions together, including mobile layouts. */
html body #wrapper .mega-search-page .mega-shared-link-actions {
  display:grid!important;
  grid-template-columns:repeat(2,minmax(max-content,1fr))!important;
  flex-wrap:nowrap!important;
  gap:8px!important;
  width:100%!important;
  overflow-x:auto;
}
html body #wrapper .mega-search-page .mega-shared-link-actions > .fm-unified-button {
  display:inline-flex!important;
  width:100%!important;
  min-width:0!important;
  max-width:none!important;
  margin:0!important;
  padding:9px 8px!important;
  gap:6px!important;
  white-space:nowrap!important;
}
@media<?php echo fm_layout_media_query(); ?>{
  html body #wrapper .mega-search-page .mega-shared-link-actions > .fm-unified-button {
    font-size:13px!important;
  }
}
/* Desktop sharing actions use the same compact sizing as other page buttons. */
@media<?php echo fm_desktop_media_query(); ?>{
  html body #wrapper .mega-search-page .mega-shared-link-actions {
    display:flex!important;
    justify-content:center!important;
  }
  html body #wrapper .mega-search-page .mega-shared-link-actions > .fm-unified-button {
    flex:0 0 auto!important;
    width:auto!important;
    min-width:120px!important;
    padding:9px 16px!important;
  }
}
/* Desktop only: Cancel precedes both share actions in one common row. */
@media<?php echo fm_desktop_media_query(); ?>{
 html body #wrapper .mega-create-link-controls {
   display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:10px;
 }
 html body #wrapper .mega-create-link-controls > label,
 html body #wrapper .mega-create-link-controls > input,
 html body #wrapper .mega-create-link-controls > p {
   flex:0 0 100%;width:100%;order:-2;margin:0!important;
 }
 html body #wrapper .mega-create-link-controls > p {order:-1;}
 html body #wrapper .mega-create-link-controls > form,
 html body #wrapper .mega-create-link-controls .fm-unified-actions {
   display:contents!important;
 }
 html body #wrapper .mega-create-link-controls .fm-unified-button {
   order:1;flex:0 0 auto!important;width:auto!important;min-width:120px!important;margin:0!important;
 }
 html body #wrapper .mega-create-link-controls .mega-rubbish-close > a {
   order:0;
 }
}
/* Keep the Copy Link popup action centered and comfortably wide on all screens. */
#megaMessageDialog .modal-footer > .btn {
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  width:180px;max-width:100%;min-height:44px;
}
/* Rename has an editable field: keep a small, consistent gap without stretching the dialog. */
#renameDialog .modal-body p {width:100%;margin:10px 0 0!important;}
#renameDialog .modal-body input.form-control {width:100%;min-width:0;}
#renameDialog .modal-body {gap:0;}
/* Search contains a larger form and deliberately remains a scrollable, wider modal. */
/* When a confirmation was dragged previously, the next opening starts centered. */
.modal.modal-alert.confirmDialog .modal-dialog.mega-dragging,
#renameDialog .modal-dialog.mega-dragging,
#megaBulkConfirm .modal-dialog.mega-dragging {transform:none!important;}
/* Android requires touch-action to be set before pointerdown, not during it. */
.modal .modal-header, .modal.modal-alert .modal-body, .modal .modal-body.mega-drag-handle {touch-action:none!important;cursor:grab}
.mega-menu-drag-handle{height:28px;display:flex;align-items:center;justify-content:center;touch-action:none;cursor:grab}
.mega-menu-drag-handle::before{content:'';width:38px;height:4px;border-radius:4px;background:currentColor;opacity:.45}
.mega-row-actions-menu.mega-dragging{transition:none!important;user-select:none;cursor:grabbing}
.modal .modal-dialog.mega-dragging {transition:none!important;cursor:grabbing}
.modal .modal-dialog.mega-dragging * {user-select:none!important;-webkit-user-select:none!important}
</style>
<script>
(function(){
  var drag=null;
  function clamp(v,min,max){return Math.min(Math.max(v,min),max);}
  function interactive(node){return node.closest('button,a,input,select,textarea,label,[role="button"],.btn,.form-control,.mega-search-results,[contenteditable="true"]');}
  // Mark suitable non-form body areas before a gesture starts.
  function prepare(modal){
    if(!modal)return;
    var header=modal.querySelector('.modal-header');
    if(header)header.style.touchAction='none';
    if(modal.classList.contains('modal')){
      var body=modal.querySelector('.modal-body');
      if(body)body.classList.add('mega-drag-handle');
    }
  }
  document.addEventListener('show.bs.modal',function(e){
    prepare(e.target);
    var d=e.target&&e.target.querySelector('.modal-dialog');
    if(d){['position','margin','left','top','transform'].forEach(function(k){d.style.removeProperty(k)});d.classList.remove('mega-dragging');}
  },true);
  document.addEventListener('DOMContentLoaded',function(){
    document.querySelectorAll('.modal').forEach(prepare);
  });
  document.addEventListener('pointerdown',function(e){
    if(e.pointerType==='mouse'&&e.button!==0)return;
    var modal=e.target.closest('.modal.show');
    var grip=e.target.closest('.mega-menu-drag-handle');
    if((!modal&&!grip)||interactive(e.target))return;
    var dialog=grip?grip.parentElement:modal.querySelector('.modal-dialog');if(!dialog)return;
    var handle=grip||e.target.closest('.modal-header,.modal-body');
    if(!handle||(!grip&&!modal.contains(handle)))return;
    if(handle.classList.contains('modal-body') && !handle.classList.contains('mega-drag-handle'))return;
    var rect=dialog.getBoundingClientRect();
    drag={id:e.pointerId,dialog:dialog,handle:handle,x:e.clientX,y:e.clientY,left:rect.left,top:rect.top,width:rect.width,height:rect.height};
    dialog.style.setProperty('position','fixed','important');
    dialog.style.setProperty('margin','0','important');
    dialog.style.setProperty('left',rect.left+'px','important');
    dialog.style.setProperty('top',rect.top+'px','important');
    dialog.style.setProperty('transform','none','important');
    dialog.classList.add('mega-dragging');
    if(handle.setPointerCapture)try{handle.setPointerCapture(e.pointerId)}catch(_){}
    if(e.cancelable)e.preventDefault();
  },{capture:true,passive:false});
  document.addEventListener('pointermove',function(e){
    if(!drag||e.pointerId!==drag.id)return;
    var vv=window.visualViewport, left=vv?vv.offsetLeft:0, top=vv?vv.offsetTop:0;
    var width=vv?vv.width:window.innerWidth, height=vv?vv.height:window.innerHeight;
    var x=clamp(drag.left+e.clientX-drag.x,left,left+Math.max(0,width-drag.width));
    var y=clamp(drag.top+e.clientY-drag.y,top,top+Math.max(0,height-drag.height));
    drag.dialog.style.setProperty('left',x+'px','important');
    drag.dialog.style.setProperty('top',y+'px','important');
    if(e.cancelable)e.preventDefault();
  },{capture:true,passive:false});
  function stop(e){if(drag&&(!e||e.pointerId===drag.id)){drag.dialog.classList.remove('mega-dragging');drag=null;}}
  document.addEventListener('pointerup',stop,true);
  document.addEventListener('pointercancel',stop,true);
  document.addEventListener('hidden.bs.modal',function(e){
    var d=e.target.querySelector('.modal-dialog');if(!d)return;
    ['position','margin','left','top','transform'].forEach(function(k){d.style.removeProperty(k)});
    d.classList.remove('mega-dragging');drag=null;
  });
})();
</script>
    <!-- Shared non-blocking operation feedback for slow MEGA actions. -->
<style>
#megaWorkingOverlay{position:fixed;inset:0;z-index:2147483000;background:rgba(15,23,42,.36);display:none;align-items:center;justify-content:center;padding:20px}
#megaWorkingOverlay.mega-visible{display:flex}
/* Once processing starts, the confirmation must no longer be visible behind the spinner. */
body.mega-operation-busy .modal.show,body.mega-operation-busy .modal.in,body.mega-operation-busy .modal-backdrop{visibility:hidden!important;pointer-events:none!important}
#megaWorkingPanel{touch-action:none!important;cursor:grab;user-select:none;-webkit-user-select:none;position:relative;box-sizing:border-box;width:min(calc(100vw - 40px),var(--mega-operation-dialog-width));height:var(--mega-operation-dialog-height);min-height:0;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#fff;color:#202833;border:1px solid #d7dde5;border-radius:12px;padding:12px 16px;box-shadow:0 15px 45px rgba(0,0,0,.2);text-align:center}
#megaWorkingSpinner{display:block;box-sizing:border-box;flex:0 0 36px;flex-shrink:0;width:36px;min-width:36px;max-width:36px;height:36px;min-height:36px;max-height:36px;aspect-ratio:1 / 1;border:4px solid #dbeafe;border-top-color:#1673cf;border-radius:50%;animation:megaWorkingSpin .8s linear infinite;margin:0 0 7px;transform-origin:center center}
@keyframes megaWorkingSpin{to{transform:rotate(360deg)}}
#megaWorkingTitle{touch-action:none;user-select:none;-webkit-user-select:none;cursor:grab;padding:0;line-height:1.25}
#megaWorkingPanel.mega-working-dragging,#megaWorkingPanel.mega-working-dragging *{cursor:grabbing!important}
#megaWorkingTitle{font-weight:650;font-size:19px;margin:0 0 3px}
#megaWorkingDetail{font-size:14px;line-height:1.3;color:#64748b;margin:0 0 3px}
#megaWorkingElapsed{font-size:13px;color:#64748b;font-variant-numeric:tabular-nums}
[data-bs-theme="dark"] #megaWorkingPanel,.theme-dark #megaWorkingPanel{background:#24292e;color:#f2f5f8;border-color:#49515b}
</style>
<div id="megaWorkingOverlay" role="status" aria-live="polite" aria-label="<?php echo htmlspecialchars(isset($lang) && $lang === 'zh-TW' ? '檔案操作進行中' : (isset($lang) && $lang === 'zh-CN' ? '文件操作进行中' : 'File operation in progress'), ENT_QUOTES, 'UTF-8'); ?>">
 <div id="megaWorkingPanel"><span id="megaWorkingSpinner" aria-hidden="true"></span><div id="megaWorkingTitle"><?php echo isset($lang) && $lang === 'zh-TW' ? '正在處理檔案…' : (isset($lang) && $lang === 'zh-CN' ? '正在处理文件…' : 'Processing files…'); ?></div><p id="megaWorkingDetail"><?php echo isset($lang) && $lang === 'zh-TW' ? '請稍候，正在處理操作' : (isset($lang) && $lang === 'zh-CN' ? '请稍候，正在处理操作' : 'Please wait while the operation completes'); ?></p><div id="megaWorkingElapsed"><?php echo isset($lang) && $lang === 'zh-TW' ? '已用時間：0秒' : (isset($lang) && $lang === 'zh-CN' ? '已用时间：0秒' : 'Elapsed: 0s'); ?></div></div>
</div>
<script>
(function(){
 var overlay=document.getElementById('megaWorkingOverlay'), timer=null, start=0, busy=false;
 var megaWorkingLanguage=<?php echo json_encode(isset($lang) ? $lang : 'en', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
 var megaWorkingLocales={en:{names:{"delete":"Deleting selected items…","zip":"Creating ZIP archive…","tar":"Creating TAR archive…","copy":"Copying selected items…","move":"Moving files…","rename":"Renaming item…","create":"Creating item…","unzip":"Unzipping archive…","unzip-folder":"Unzipping archive to folder…","extract":"Extracting archive…","upload":"Uploading files…","settings":"Saving settings…","save":"Saving file…","backup":"Creating backup…"},detail:'Please wait while the operation completes',elapsed:'Elapsed',fallback:'Processing files…',aria:'File operation in progress'},'zh-TW':{names:{"delete":"正在刪除選取的項目…","zip":"正在建立 ZIP 壓縮檔…","tar":"正在建立 TAR 壓縮檔…","copy":"正在複製選取的項目…","move":"正在移動檔案…","rename":"正在重新命名…","create":"正在建立項目…","unzip":"正在解壓縮檔案…","unzip-folder":"正在解壓縮至資料夾…","extract":"正在解壓縮檔案…","upload":"正在上傳檔案…","settings":"正在儲存設定…","save":"正在儲存檔案…","backup":"正在建立備份…"},detail:'請稍候，正在處理操作',elapsed:'已用時間',fallback:'正在處理檔案…',aria:'檔案操作進行中'},'zh-CN':{names:{"delete":"正在删除所选项目…","zip":"正在创建 ZIP 压缩文件…","tar":"正在创建 TAR 压缩文件…","copy":"正在复制所选项目…","move":"正在移动文件…","rename":"正在重命名…","create":"正在创建项目…","unzip":"正在解压文件…","unzip-folder":"正在解压到文件夹…","extract":"正在解压文件…","upload":"正在上传文件…","settings":"正在保存设置…","save":"正在保存文件…","backup":"正在创建备份…"},detail:'请稍候，正在处理操作',elapsed:'已用时间',fallback:'正在处理文件…',aria:'文件操作进行中'}};
 // Localized labels reuse translation.json; shared status text covers every configured language.
 Object.assign(megaWorkingLocales,{"ro":{"names":{"delete":"Șterge…","zip":"Generează…","tar":"Generează…","copy":"Copiază…","move":"Mută…","rename":"Redenumește…","create":"Creează element nou…","unzip":"Decomprimă…","unzip-folder":"Decomprimă în dosar…","extract":"Decomprimă…","upload":"Se încarcă fișiere…","settings":"Configurări…","save":"Salvează…","backup":"Copie de rezervă…"},"detail":"Vă rugăm așteptați până se finalizează operațiunea.","elapsed":"Timp scurs","fallback":"Se procesează fișiere…","aria":"Se procesează fișiere"},"hu":{"names":{"delete":"Törlés…","zip":"Generálás…","tar":"Generálás…","copy":"Másolás…","move":"Mozgatás…","rename":"Átnevezés…","create":"Új létrehozása…","unzip":"Kitömörítés…","unzip-folder":"Kitömörítás adott mappába…","extract":"Kitömörítés…","upload":"Fájlok feltöltése…","settings":"Beállítások…","save":"Mentés…","backup":"Biztonsági mentés…"},"detail":"Kérjük, várjon, amíg a művelet befejeződik.","elapsed":"Eltelt idő","fallback":"Fájlok feldolgozása…","aria":"Fájlok feldolgozása"},"no":{"names":{"delete":"Slett…","zip":"Generer…","tar":"Generer…","copy":"Kopier…","move":"Flytt…","rename":"Gi nytt navn…","create":"Lag ny…","unzip":"Pakk ut…","unzip-folder":"Pakk ut til mappe…","extract":"Pakk ut…","upload":"Laster opp filer…","settings":"Instillinger…","save":"Lagre…","backup":"Sikkerhetskopier…"},"detail":"Vennligst vent til operasjonen er fullført.","elapsed":"Forløpt tid","fallback":"Behandler filer…","aria":"Behandler filer"},"fa":{"names":{"delete":"حذف…","zip":"ایجاد…","tar":"ایجاد…","copy":"کپی…","move":"جابجایی…","rename":"تغییر نام…","create":"Create…","unzip":"UnZip…","unzip-folder":"Unzip-folder…","extract":"UnZip…","upload":"Upload…","settings":"تنظیمات…","save":"ذخیره…","backup":"Backup…"},"detail":"لطفاً تا پایان عملیات صبر کنید.","elapsed":"زمان سپری‌شده","fallback":"در حال پردازش فایل‌ها…","aria":"در حال پردازش فایل‌ها"},"ru":{"names":{"delete":"Удалить…","zip":"Сгенерировать…","tar":"Сгенерировать…","copy":"Копировать…","move":"Переместить…","rename":"Переименовать…","create":"Создать новый…","unzip":"Разархивировать…","unzip-folder":"Разархивировать в папку…","extract":"Разархивировать…","upload":"Загрузка файлов…","settings":"Настройки…","save":"Сохранить…","backup":"Резервная копия…"},"detail":"Подождите, пока операция завершится.","elapsed":"Прошло времени","fallback":"Обработка файлов…","aria":"Обработка файлов"},"it":{"names":{"delete":"Elimina…","zip":"Genera…","tar":"Genera…","copy":"Copia…","move":"Sposta…","rename":"Rinomina…","create":"Nuovo elemento…","unzip":"Decomprimi…","unzip-folder":"Decomprimi in una cartella…","extract":"Decomprimi…","upload":"Caricamento file…","settings":"Impostazioni…","save":"Salva…","backup":"Backup…"},"detail":"Attendi il completamento dell’operazione.","elapsed":"Tempo trascorso","fallback":"Elaborazione file…","aria":"Elaborazione file"},"fr":{"names":{"delete":"Supprimer…","zip":"Générer…","tar":"Générer…","copy":"Copier…","move":"Déplacer…","rename":"Renommer…","create":"Créer un nouveau fichier…","unzip":"Décompresser…","unzip-folder":"Décompresser dans un dossier…","extract":"Décompresser…","upload":"Téléverser des fichiers…","settings":"Réglages…","save":"Sauvegarder…","backup":"Sauvegarder…"},"detail":"Veuillez patienter pendant l’opération.","elapsed":"Temps écoulé","fallback":"Traitement des fichiers…","aria":"Traitement des fichiers"},"es":{"names":{"delete":"Borrar…","zip":"Nuevo Ítem…","tar":"Nuevo Ítem…","copy":"Copiar…","move":"Mover…","rename":"Cambiar Nombre…","create":"Crear nuevo Item…","unzip":"Descomprimir…","unzip-folder":"Descomprimir en Carpeta…","extract":"Descomprimir…","upload":"Subir Archivos…","settings":"Preferencias…","save":"Guardar…","backup":"Copia de Seguridad…"},"detail":"Espere mientras se completa la operación.","elapsed":"Tiempo transcurrido","fallback":"Procesando archivos…","aria":"Procesando archivos"},"gl":{"names":{"delete":"Borrar…","zip":"Novo Elemento…","tar":"Novo Elemento…","copy":"Copiar…","move":"Mover…","rename":"Renomear…","create":"Crear novo Elemento…","unzip":"Descomprimir…","unzip-folder":"Descomprimir no Cartafol…","extract":"Descomprimir…","upload":"Subir Arquivos…","settings":"Preferencias…","save":"Gardar…","backup":"Copia de Seguridade…"},"detail":"Agarde mentres se completa a operación.","elapsed":"Tempo transcorrido","fallback":"Procesando ficheiros…","aria":"Procesando ficheiros"},"ca":{"names":{"delete":"Esborrar…","zip":"Generar…","tar":"Generar…","copy":"Copiar…","move":"Moure…","rename":"Canviar Nom…","create":"Crear un Nou Ítem…","unzip":"Descomprimir…","unzip-folder":"Descomprimir a Carpeta…","extract":"Descomprimir…","upload":"Pujar Arxius…","settings":"Preferències…","save":"Desar…","backup":"Còpia de Seguretat…"},"detail":"Espereu mentre es completa l’operació.","elapsed":"Temps transcorregut","fallback":"Processant fitxers…","aria":"Processant fitxers"},"de":{"names":{"delete":"Löschen…","zip":"Erzeugen…","tar":"Erzeugen…","copy":"Kopieren…","move":"Verschieben…","rename":"Umbenennen…","create":"Neues Element erstellen…","unzip":"Entpacken…","unzip-folder":"Entpacken im Ordner…","extract":"Entpacken…","upload":"Dateien hochladen…","settings":"Einstellungen…","save":"Speichern…","backup":"Backup…"},"detail":"Bitte warten, bis der Vorgang abgeschlossen ist.","elapsed":"Verstrichene Zeit","fallback":"Dateien werden verarbeitet…","aria":"Dateien werden verarbeitet"},"th":{"names":{"delete":"ลบ…","zip":"สร้างใหม่…","tar":"สร้างใหม่…","copy":"คัดลอก…","move":"ย้าย…","rename":"เปลี่ยนชื่อ…","create":"สร้างไฟล์ใหม่…","unzip":"แตก Zip…","unzip-folder":"แตกไฟล์ในโฟเดอร์นี้…","extract":"แตก Zip…","upload":"อัพโหลด…","settings":"การตั้งค่า…","save":"บันทึก…","backup":"สำรองข้อมูล…"},"detail":"โปรดรอจนกว่าการดำเนินการจะเสร็จสิ้น","elapsed":"เวลาที่ผ่านไป","fallback":"กำลังประมวลผลไฟล์…","aria":"กำลังประมวลผลไฟล์"},"id":{"names":{"delete":"Hapus…","zip":"Hasilkan…","tar":"Hasilkan…","copy":"Salin…","move":"Pindah…","rename":"Ganti nama…","create":"Buat item baru…","unzip":"UnZip…","unzip-folder":"UnZip ke folder…","extract":"UnZip…","upload":"Mengunggah berkas…","settings":"Setelan…","save":"Simpan…","backup":"Cadangkan…"},"detail":"Harap tunggu hingga proses selesai.","elapsed":"Waktu berlalu","fallback":"Memproses berkas…","aria":"Memproses berkas"},"gr":{"names":{"delete":"Διαγραφή…","zip":"Νέο Αντικείμενο…","tar":"Νέο Αντικείμενο…","copy":"Αντιγραφή…","move":"Μετακίνση…","rename":"Μετονομασία…","create":"Δημιουργία νέου αντικειμένου…","unzip":"Αποσυμπίεση…","unzip-folder":"Αποσυμπίεση σε φάκελο…","extract":"Αποσυμπίεση…","upload":"Ανέβασμα αρχείων…","settings":"Ρυθμίσεις…","save":"Αποθήκευση…","backup":"Back-Up…"},"detail":"Περιμένετε μέχρι να ολοκληρωθεί η διαδικασία.","elapsed":"Χρόνος που πέρασε","fallback":"Επεξεργασία αρχείων…","aria":"Επεξεργασία αρχείων"},"pt_BR":{"names":{"delete":"Excluir…","zip":"Gerar…","tar":"Gerar…","copy":"Copiar…","move":"Mover…","rename":"Renomear…","create":"Criar novo item…","unzip":"Descompactar os arquivos…","unzip-folder":"Descompactar na pasta…","extract":"Descompactar os arquivos…","upload":"Upload de arquivos…","settings":"Preferências…","save":"Salvar…","backup":"Cópia de segurança…"},"detail":"Aguarde enquanto a operação é concluída.","elapsed":"Tempo decorrido","fallback":"Processando arquivos…","aria":"Processando arquivos"},"pt_PT":{"names":{"delete":"Eliminar…","zip":"Gerar…","tar":"Gerar…","copy":"Copiar…","move":"Mover…","rename":"Renomear…","create":"Criar novo item…","unzip":"Descomprimir…","unzip-folder":"Descomprimir para pasta…","extract":"Descomprimir…","upload":"A enviar ficheiros…","settings":"Definições…","save":"Guardar…","backup":"Cópia de segurança…"},"detail":"Aguarde até a operação estar concluída.","elapsed":"Tempo decorrido","fallback":"A processar ficheiros…","aria":"A processar ficheiros"},"pl":{"names":{"delete":"Usuń…","zip":"Nowy plik…","tar":"Nowy plik…","copy":"Kopiuj…","move":"Przenieś…","rename":"Zmień nazwę…","create":"Utwórz nowy plik…","unzip":"Rozpakuj…","unzip-folder":"Rozpakuj do…","extract":"Rozpakuj…","upload":"Wysyłanie plików…","settings":"Ustawienia…","save":"Zapisz…","backup":"Kopia zapasowa…"},"detail":"Poczekaj na zakończenie operacji.","elapsed":"Upłynęło","fallback":"Przetwarzanie plików…","aria":"Przetwarzanie plików"},"vi":{"names":{"delete":"Xóa…","zip":"Tạo…","tar":"Tạo…","copy":"Sao chép…","move":"Di chuyển…","rename":"Đổi tên…","create":"Tạo mới…","unzip":"Giải nén…","unzip-folder":"Giải nén đến thư mục…","extract":"Giải nén…","upload":"Tải lên file…","settings":"Cài đặt…","save":"Lưu…","backup":"Sao lưu…"},"detail":"Vui lòng đợi cho đến khi thao tác hoàn tất.","elapsed":"Thời gian đã trôi qua","fallback":"Đang xử lý tệp…","aria":"Đang xử lý tệp"},"he":{"names":{"delete":"מחק…","zip":"חדש…","tar":"חדש…","copy":"העתק…","move":"העבר…","rename":"שנה שם…","create":"צור פריט חדש…","unzip":"חילוץ…","unzip-folder":"חלץ לתיקייה…","extract":"חילוץ…","upload":"מעלה קבצים…","settings":"הגדרות…","save":"שמור…","backup":"גיבוי…"},"detail":"נא להמתין עד לסיום הפעולה.","elapsed":"זמן שחלף","fallback":"מעבד קבצים…","aria":"מעבד קבצים"},"ar":{"names":{"delete":"حذف…","zip":"توليد…","tar":"توليد…","copy":"نسخ…","move":"نقل…","rename":"تسمية…","create":"انشاء عنصر جديد…","unzip":"فك الضغط…","unzip-folder":"فك الصغط لملف…","extract":"فك الضغط…","upload":"رفع ملفات…","settings":"اعدادات…","save":"حفظ…","backup":"نسخة احتياطية…"},"detail":"يرجى الانتظار حتى اكتمال العملية.","elapsed":"الوقت المنقضي","fallback":"جارٍ معالجة الملفات…","aria":"جارٍ معالجة الملفات"},"cz":{"names":{"delete":"Smazat…","zip":"Generovat…","tar":"Generovat…","copy":"Kopírovat…","move":"Přesunout…","rename":"Přejmenovat…","create":"Vytvoř novou položku…","unzip":"Rozbalit…","unzip-folder":"Rozbalit do…","extract":"Rozbalit…","upload":"Nahrát soubory…","settings":"Nastavení…","save":"Uložit…","backup":"Záloha…"},"detail":"Počkejte prosím na dokončení operace.","elapsed":"Uplynulý čas","fallback":"Zpracovávání souborů…","aria":"Zpracovávání souborů"},"tr":{"names":{"delete":"Sil…","zip":"Oluştur…","tar":"Oluştur…","copy":"Kopyala…","move":"Taşı…","rename":"Yeniden Adlandır…","create":"Yeni Öğe Oluştur…","unzip":"Zip Aç…","unzip-folder":"Klasöre Zip Aç…","extract":"Zip Aç…","upload":"Dosya Yükle…","settings":"Ayarlar…","save":"Kaydet…","backup":"Yedekle…"},"detail":"İşlem tamamlanana kadar lütfen bekleyin.","elapsed":"Geçen süre","fallback":"Dosyalar işleniyor…","aria":"Dosyalar işleniyor"},"sk":{"names":{"delete":"Zmazať…","zip":"Nový súbor…","tar":"Nový súbor…","copy":"Kopírovať…","move":"Presunúť…","rename":"Premenovať…","create":"Vytvoriť nový súbor…","unzip":"Rozbaliť…","unzip-folder":"Rozbaliť do…","extract":"Rozbaliť…","upload":"Nahrať súbory…","settings":"Nastavenia…","save":"Uložiť…","backup":"Záloha…"},"detail":"Počkajte na dokončenie operácie.","elapsed":"Uplynutý čas","fallback":"Spracúvajú sa súbory…","aria":"Spracúvajú sa súbory"},"sl":{"names":{"delete":"Izbriši…","zip":"Nov objekt…","tar":"Nov objekt…","copy":"Kopiraj…","move":"Premakni…","rename":"Preimenuj…","create":"Ustvari nov objekt…","unzip":"Razširi…","unzip-folder":"Razširi v mapo…","extract":"Razširi…","upload":"Naloži datoteko…","settings":"Nastavitve…","save":"Shrani…","backup":"Varnostna kopija…"},"detail":"Počakajte, da se postopek zaključi.","elapsed":"Pretečeni čas","fallback":"Obdelava datotek…","aria":"Obdelava datotek"},"fi":{"names":{"delete":"Poista…","zip":"Luo uusi…","tar":"Luo uusi…","copy":"Kopioi…","move":"Siirrä…","rename":"Nimeä uudelleen…","create":"Luo uusi tiedosto tai kansio…","unzip":"Pura…","unzip-folder":"Pura kansioon…","extract":"Pura…","upload":"Siirrä tiedostoja…","settings":"Asetukset…","save":"Tallenna…","backup":"Varmuuskopioi…"},"detail":"Odota, kunnes toiminto on valmis.","elapsed":"Kulunut aika","fallback":"Käsitellään tiedostoja…","aria":"Käsitellään tiedostoja"},"sv":{"names":{"delete":"Ta bort…","zip":"Generera…","tar":"Generera…","copy":"Kopiera…","move":"Flytta…","rename":"Byt namn…","create":"Skapa ny fil eller mapp…","unzip":"Packa upp…","unzip-folder":"Packa upp till mapp…","extract":"Packa upp…","upload":"Laddar upp filer…","settings":"Inställningar…","save":"Spara…","backup":"Säkerhetskopiera…"},"detail":"Vänta tills åtgärden är klar.","elapsed":"Förfluten tid","fallback":"Bearbetar filer…","aria":"Bearbetar filer"},"ko":{"names":{"delete":"삭제…","zip":"생성…","tar":"생성…","copy":"복사…","move":"이동…","rename":"이름 변경…","create":"Create…","unzip":"압축 해제…","unzip-folder":"Unzip-folder…","extract":"압축 해제…","upload":"Upload…","settings":"설정…","save":"저장…","backup":"Backup…"},"detail":"작업이 완료될 때까지 기다려 주세요.","elapsed":"경과 시간","fallback":"파일 처리 중…","aria":"파일 처리 중"},"ja":{"names":{"delete":"削除…","zip":"生成…","tar":"生成…","copy":"コピー…","move":"移動…","rename":"名前の変更…","create":"新規作成…","unzip":"解凍…","unzip-folder":"フォルダに解凍…","extract":"解凍…","upload":"ファイルをアップロード…","settings":"設定…","save":"保存…","backup":"バックアップ…"},"detail":"処理が完了するまでお待ちください。","elapsed":"経過時間","fallback":"ファイルを処理しています…","aria":"ファイルを処理しています"},"mn_MN":{"names":{"delete":"Устгах…","zip":"Үүсгэх…","tar":"Үүсгэх…","copy":"Хуулах…","move":"Зөөх…","rename":"Нэр солих…","create":"Шинээр үүсгэх…","unzip":"Задлах…","unzip-folder":"Хавтсанд задлах…","extract":"Задлах…","upload":"Файлуудыг хуулж байна…","settings":"Тохиргоо…","save":"Хадгалах…","backup":"Бакап…"},"detail":"Үйлдэл дуусах хүртэл түр хүлээнэ үү.","elapsed":"Өнгөрсөн хугацаа","fallback":"Файл боловсруулж байна…","aria":"Файл боловсруулж байна"},"nl":{"names":{"delete":"Verwijder…","zip":"Genereer…","tar":"Genereer…","copy":"Kopiëren…","move":"Verplaatsen…","rename":"Hernoem…","create":"Maak nieuw item…","unzip":"Uitpakken…","unzip-folder":"Uitpakken in map…","extract":"Uitpakken…","upload":"Bestanden uploaden…","settings":"Instellingen…","save":"Opslaan…","backup":"Back-up maken…"},"detail":"Wacht tot de bewerking is voltooid.","elapsed":"Verstreken tijd","fallback":"Bestanden verwerken…","aria":"Bestanden verwerken"},"da":{"names":{"delete":"Slet…","zip":"Generer…","tar":"Generer…","copy":"Kopi…","move":"Flyt…","rename":"Omdøb…","create":"Opret ny…","unzip":"Pak ud…","unzip-folder":"Pak ud i mappe…","extract":"Pak ud…","upload":"Uploader filer…","settings":"Indstillinger…","save":"Gem…","backup":"Backup…"},"detail":"Vent venligst, indtil handlingen er fuldført.","elapsed":"Forløbet tid","fallback":"Behandler filer…","aria":"Behandler filer"},"bn":{"names":{"delete":"মুছে ফেলা…","zip":"উৎপন্ন…","tar":"উৎপন্ন…","copy":"কপি…","move":"সরান…","rename":"নাম পরিবর্তন করা হয়েছে…","create":"নতুন আইটেম তৈরি করুন…","unzip":"আনজিপ করুন…","unzip-folder":"ফোল্ডারে আনজিপ…","extract":"আনজিপ করুন…","upload":"ফাইল আপলোড করা হচ্ছে…","settings":"সেটিংস…","save":"সংরক্ষণ…","backup":"ব্যাকআপ…"},"detail":"কাজটি সম্পূর্ণ হওয়া পর্যন্ত অপেক্ষা করুন।","elapsed":"অতিবাহিত সময়","fallback":"ফাইল প্রক্রিয়াকরণ চলছে…","aria":"ফাইল প্রক্রিয়াকরণ চলছে"}});
 // Resolve the active browser preference at the moment each operation starts.
 // PHP's language may be stale when a page is restored from browser cache.
 function megaResolveWorkingLanguage(){
  var chosen='';
  try {
   var select=document.getElementById('js-language');
   if(select && select.value) chosen=select.value;
   if(!chosen && window.megaPrefsStorageKey){
    var raw=window.localStorage.getItem(window.megaPrefsStorageKey);
    if(raw){var stored=JSON.parse(raw);if(stored && typeof stored.lang==='string')chosen=stored.lang;}
   }
   if(!chosen && window.megaPrefsCookieName){
    var key=window.megaPrefsCookieName+'=';
    var parts=document.cookie.split(';');
    for(var i=0;i<parts.length;i++){
     var part=parts[i].trim();
     if(part.indexOf(key)===0){
      var pref=JSON.parse(decodeURIComponent(part.slice(key.length)));
      if(pref && typeof pref.lang==='string')chosen=pref.lang;
      break;
     }
    }
   }
  } catch(_error){}
  if(!chosen)chosen=megaWorkingLanguage;
  var normalized=String(chosen).replace(/_/g,'-').toLowerCase();
  var locales=Object.keys(megaWorkingLocales);
  for(var j=0;j<locales.length;j++){
   if(locales[j].toLowerCase()===normalized)return locales[j];
  }
  return megaWorkingLocales[megaWorkingLanguage]?megaWorkingLanguage:'en';
 }
 Object.keys(megaWorkingLocales).forEach(function(code){
  var names=megaWorkingLocales[code].names;
  names.untar=names.extract||names.unzip;
  names['untar-folder']=names['unzip-folder'];
 });
 megaWorkingLocales.en.names.untar='Extracting TAR archive…';
 megaWorkingLocales.en.names['untar-folder']='Extracting TAR archive to folder…';
 var shareProgressLabels={"ro": {"share-create": "Creează link…", "share-stop": "Oprește partajarea…"}, "hu": {"share-create": "Hivatkozás létrehozása…", "share-stop": "Megosztás leállítása…"}, "no": {"share-create": "Opprett lenke…", "share-stop": "Stopp deling…"}, "fa": {"share-create": "ایجاد پیوند…", "share-stop": "توقف اشتراک‌گذاری…"}, "ru": {"share-create": "Создать ссылку…", "share-stop": "Отключить общий доступ…"}, "it": {"share-create": "Crea link…", "share-stop": "Interrompi condivisione…"}, "fr": {"share-create": "Créer un lien…", "share-stop": "Arrêter le partage…"}, "es": {"share-create": "Crear enlace…", "share-stop": "Dejar de compartir…"}, "gl": {"share-create": "Crear ligazón…", "share-stop": "Deixar de compartir…"}, "ca": {"share-create": "Crea un enllaç…", "share-stop": "Deixa de compartir…"}, "de": {"share-create": "Link erstellen…", "share-stop": "Freigabe beenden…"}, "th": {"share-create": "สร้างลิงก์…", "share-stop": "หยุดแชร์…"}, "zh-CN": {"share-create": "正在创建分享链接…", "share-stop": "正在停止分享…"}, "zh-TW": {"share-create": "正在建立分享連結…", "share-stop": "正在停止分享…"}, "id": {"share-create": "Buat tautan…", "share-stop": "Hentikan berbagi…"}, "gr": {"share-create": "Δημιουργία συνδέσμου…", "share-stop": "Διακοπή κοινής χρήσης…"}, "pt_BR": {"share-create": "Criar link…", "share-stop": "Parar de compartilhar…"}, "pt_PT": {"share-create": "Criar ligação…", "share-stop": "Parar de partilhar…"}, "pl": {"share-create": "Utwórz link…", "share-stop": "Zatrzymaj udostępnianie…"}, "vi": {"share-create": "Tạo liên kết…", "share-stop": "Dừng chia sẻ…"}, "he": {"share-create": "יצירת קישור…", "share-stop": "הפסקת שיתוף…"}, "ar": {"share-create": "إنشاء رابط…", "share-stop": "إيقاف المشاركة…"}, "cz": {"share-create": "Vytvořit odkaz…", "share-stop": "Ukončit sdílení…"}, "tr": {"share-create": "Bağlantı oluştur…", "share-stop": "Paylaşımı durdur…"}, "sk": {"share-create": "Vytvoriť odkaz…", "share-stop": "Ukončiť zdieľanie…"}, "sl": {"share-create": "Ustvari povezavo…", "share-stop": "Ustavi skupno rabo…"}, "fi": {"share-create": "Luo linkki…", "share-stop": "Lopeta jakaminen…"}, "sv": {"share-create": "Skapa länk…", "share-stop": "Sluta dela…"}, "ko": {"share-create": "링크 만들기…", "share-stop": "공유 중지…"}, "ja": {"share-create": "リンクを作成…", "share-stop": "共有を停止…"}, "mn_MN": {"share-create": "Холбоос үүсгэх…", "share-stop": "Хуваалцахыг зогсоох…"}, "nl": {"share-create": "Link maken…", "share-stop": "Delen stoppen…"}, "da": {"share-create": "Opret link…", "share-stop": "Stop deling…"}, "bn": {"share-create": "লিংক তৈরি করুন…", "share-stop": "শেয়ার বন্ধ করুন…"}, "en": {"share-create": "Creating share link…", "share-stop": "Stopping sharing…"}};
 Object.keys(megaWorkingLocales).forEach(function(code){Object.assign(megaWorkingLocales[code].names,shareProgressLabels[code]||shareProgressLabels.en);});
 Object.keys(megaWorkingLocales).forEach(function(code){var names=megaWorkingLocales[code].names;names['rubbish-restore']=names.move;names['rubbish-delete']=names.delete;});
 megaWorkingLocales.en.names['rubbish-restore']='Restoring selected items…';
 megaWorkingLocales.en.names['rubbish-delete']='Permanently deleting selected items…';
 window.megaWorkingActiveLanguage=megaResolveWorkingLanguage;
 // One sizing function for all operation confirmations and processing.
 // CSS owns the common compact dimensions; translated content may grow to fit.
 window.megaSizeOperationDialog=function(panel){
  if(!panel)return;
  panel.style.removeProperty('height');
  var base=parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--mega-operation-dialog-height'))||140;
  var height=Math.max(base,panel.scrollHeight);
  panel.style.setProperty('height',height+'px','important');
  return height;
 };
 document.addEventListener('shown.bs.modal',function(e){
  var modal=e.target;
  if(modal.matches('.confirmDialog,#megaBulkConfirm,#renameDialog,#megaMessageDialog,#megaStopSharingDialog'))
   window.megaSizeOperationDialog(modal.querySelector('.modal-content'));
 });
 // Carry the actual visible panel footprint across confirmation -> processing.
 // Snapshot before Bootstrap hides/resets a dragged dialog or a form navigates.
 var previousDialog=null, carriedModal=null;
 window.megaRememberDialog=function(modal){
  var content=modal&&modal.querySelector('.modal-content');
  if(!content)return;
  var r=content.getBoundingClientRect();
  if(r.width>0&&r.height>0)previousDialog={left:r.left,top:r.top,width:r.width,height:r.height,time:Date.now(),modal:modal};
 };
 document.addEventListener('click',function(e){
  var button=e.target.closest('.modal button,.modal input[type="submit"],.modal a');
  if(button)window.megaRememberDialog(button.closest('.modal'));
 },true);
 document.addEventListener('submit',function(e){
  var modal=e.target.closest&&e.target.closest('.modal');
  if(modal)window.megaRememberDialog(modal);
 },true);
 document.addEventListener('show.bs.modal',function(){previousDialog=null;},true);
 function carryDialogPosition(){
  var panel=document.getElementById('megaWorkingPanel');
  var visible=document.querySelector('.modal.show');
  if(visible)window.megaRememberDialog(visible);
  var r=previousDialog;previousDialog=null;
  if(!r||Date.now()-r.time>2000)return;
  // Enlarge confirmations to the shared processing footprint; never shrink the
  // processing panel to fit a smaller confirmation from another operation.
  var baseline=panel.getBoundingClientRect();
  r.width=Math.max(r.width,baseline.width);
  r.height=Math.max(r.height,baseline.height);
  ['left','top','width','height'].forEach(function(k){panel.style.setProperty(k,r[k]+'px','important');});
  panel.style.setProperty('max-width','none','important');
  panel.style.setProperty('position','fixed','important');
  panel.style.setProperty('margin','0','important');
  panel.style.setProperty('transform','none','important');
  // Remove the old panel/backdrop immediately so it cannot show through or flash.
  carriedModal=r.modal;r.modal.style.visibility='hidden';
  r.modal.addEventListener('hidden.bs.modal',function restore(){r.modal.style.removeProperty('visibility');r.modal.removeEventListener('hidden.bs.modal',restore);});
 }
 window.megaShowWorking=function(action){
  if(busy)return;busy=true;
  megaWorkingLanguage=megaResolveWorkingLanguage();
  var megaWorkingLocale=megaWorkingLocales[megaWorkingLanguage]||megaWorkingLocales.en;
  var names=megaWorkingLocale.names;
  var key=String(action||'').toLowerCase();
  var title=names[key]||megaWorkingLocale.fallback;
  document.getElementById('megaWorkingTitle').textContent=title;
  document.getElementById('megaWorkingDetail').textContent=megaWorkingLocale.detail;
  overlay.setAttribute('aria-label',megaWorkingLocale.aria);
  overlay.setAttribute('lang',megaWorkingLanguage.replace('_','-'));
  document.body.classList.add('mega-operation-busy');
  if(window.megaResetWorkingPosition)window.megaResetWorkingPosition();overlay.classList.add('mega-visible');window.megaSizeOperationDialog(document.getElementById('megaWorkingPanel'));carryDialogPosition();start=Date.now();
  var elapsed=document.getElementById('megaWorkingElapsed');
  function tick(){var seconds=Math.floor((Date.now()-start)/1000);elapsed.textContent=megaWorkingLocale.elapsed+': '+((megaWorkingLanguage==='zh-TW'||megaWorkingLanguage==='zh-CN')?(Math.floor(seconds/60)+'分 '+(seconds%60)+'秒'):(Math.floor(seconds/60)+'m '+(seconds%60)+'s'));}
  tick();timer=setInterval(tick,1000);
 };
 window.megaHideWorking=function(){if(carriedModal){carriedModal.style.removeProperty('visibility');carriedModal=null;}previousDialog=null;window.megaOperationSubmitting=null;busy=false;document.body.classList.remove('mega-operation-busy');overlay.classList.remove('mega-visible');if(window.megaResetWorkingPosition)window.megaResetWorkingPosition();if(timer){clearInterval(timer);timer=null;}};
 // Drag from anywhere on the processing panel, including the spinner and elapsed time.
 // Use native touch events on Android (avoids pointercancel from scrolling/gestures).
 (function(){
  var panel=document.getElementById('megaWorkingPanel');
  if(!panel)return;
  var drag=null, suppressMouseUntil=0;
  function clamp(n,min,max){return Math.max(min,Math.min(max,n));}
  function startAt(x,y,kind,id,e){
   if(!overlay.classList.contains('mega-visible')||drag)return;
   var r=panel.getBoundingClientRect();
   drag={x:x,y:y,left:r.left,top:r.top,kind:kind,id:id};
   panel.style.setProperty('position','fixed','important');
   panel.style.setProperty('left',r.left+'px','important');
   panel.style.setProperty('top',r.top+'px','important');
   panel.style.setProperty('margin','0','important');
   panel.style.setProperty('transform','none','important');
   panel.classList.add('mega-working-dragging');
   if(e&&e.cancelable)e.preventDefault();
  }
  function moveTo(x,y,e){
   if(!drag)return;
   var w=panel.offsetWidth,h=panel.offsetHeight;
   panel.style.setProperty('left',clamp(drag.left+x-drag.x,0,Math.max(0,window.innerWidth-w))+'px','important');
   panel.style.setProperty('top',clamp(drag.top+y-drag.y,0,Math.max(0,window.innerHeight-h))+'px','important');
   if(e&&e.cancelable)e.preventDefault();
  }
  function stop(){drag=null;panel.classList.remove('mega-working-dragging');}
  panel.addEventListener('touchstart',function(e){
   if(e.touches.length!==1)return;
   suppressMouseUntil=Date.now()+1200;
   var t=e.touches[0];startAt(t.clientX,t.clientY,'touch',t.identifier,e);
  },{passive:false});
  document.addEventListener('touchmove',function(e){
   if(!drag||drag.kind!=='touch')return;
   for(var i=0;i<e.touches.length;i++)if(e.touches[i].identifier===drag.id){
    moveTo(e.touches[i].clientX,e.touches[i].clientY,e);return;
   }
  },{passive:false,capture:true});
  document.addEventListener('touchend',function(e){
   if(drag&&drag.kind==='touch')for(var i=0;i<e.changedTouches.length;i++)if(e.changedTouches[i].identifier===drag.id){stop();break;}
  },true);
  document.addEventListener('touchcancel',function(){if(drag&&drag.kind==='touch')stop();},true);
  panel.addEventListener('mousedown',function(e){
   if(e.button!==0||Date.now()<suppressMouseUntil)return;
   startAt(e.clientX,e.clientY,'mouse',null,e);
  });
  document.addEventListener('mousemove',function(e){if(drag&&drag.kind==='mouse')moveTo(e.clientX,e.clientY,e);},true);
  document.addEventListener('mouseup',function(){if(drag&&drag.kind==='mouse')stop();},true);
  window.megaResetWorkingPosition=function(){
   stop();['position','left','top','margin','transform','width','height','max-width'].forEach(function(k){panel.style.removeProperty(k);});
  };
 })();
 // Centralized modal and operation interfaces. Existing modal and drag handlers remain compatible.
 window.megaDialogManager={
  show:function(id){var el=document.getElementById(id);if(!el)return;var d=el.querySelector('.modal-dialog');if(d){['position','margin','left','top','transform'].forEach(function(k){d.style.removeProperty(k)});d.classList.remove('mega-dragging');}if(window.bootstrap&&bootstrap.Modal)bootstrap.Modal.getOrCreateInstance(el).show();},
  hide:function(id){var el=document.getElementById(id);if(el&&window.bootstrap&&bootstrap.Modal){var m=bootstrap.Modal.getInstance(el);if(m)m.hide();}},
  processing:function(action){window.megaShowWorking(action);},done:function(){window.megaHideWorking();}
 };
 window.megaOperationManager={
  begin:function(action){window.megaShowWorking(action);},end:function(){window.megaHideWorking();},
  ajax:function(action,options){
   if(!window.jQuery)return null;
   var before=options.beforeSend,complete=options.complete,started=false;
   options.beforeSend=function(xhr,settings){if(typeof before==='function'&&before.call(this,xhr,settings)===false)return false;started=true;window.megaShowWorking(action);};
   options.complete=function(xhr,status){if(started)window.megaHideWorking();if(typeof complete==='function')complete.call(this,xhr,status);};
   return jQuery.ajax(options);
  }
 };
 // Capture the actual button, including browsers that omit SubmitEvent.submitter.
 document.addEventListener('click',function(e){
  var btn=e.target.closest('button[type="submit"],input[type="submit"]');
  if(btn&&btn.form)btn.form._megaClickedSubmitter=btn;
 },true);
 // Single-file destination picker uses GET links to commit Copy/Move.
 // Opening the picker itself must never show the processing overlay.
 document.addEventListener('click',function(e){
  var link=e.target.closest('a#mega-picker-copy-link,a#mega-picker-move-link');
  if(!link||e.defaultPrevented||e.ctrlKey||e.metaKey||e.shiftKey||e.altKey||e.button!==0)return;
  if(link.getAttribute('href')&&/[?&]finish=1(?:&|$)/.test(link.getAttribute('href'))){
   window.megaShowWorking(link.id==='mega-picker-move-link'?'move':'copy');
  }
 },false);
 // Recognize actual mutations from submitted form fields, not only the clicked
 // submit button: browsers differ in their support for SubmitEvent.submitter.
 function operationFor(form,e){
  var submitter=e.submitter||form._megaClickedSubmitter||document.activeElement;
  var name=(submitter&&submitter.form===form&&submitter.name)||form.getAttribute('data-operation')||'';
  name=String(name).toLowerCase();
  var action=form.getAttribute('action')||'';
  if(/[?&]dl=/.test(action)||form.hasAttribute('data-no-processing'))return '';
  var trashAction=form.elements.namedItem('rubbish_action');
  if(trashAction)return trashAction.value==='restore'?'rubbish-restore':(['delete','empty'].indexOf(trashAction.value)!==-1?'rubbish-delete':'');
  var shareAction=form.elements.namedItem('share_action');
  if(shareAction)return shareAction.value==='stop'?'share-stop':(shareAction.value==='create'?'share-create':'');
  // Archive extraction uses the exact same shared processing dialog as Copy/Move/Delete.
  var sharedOperation=form.getAttribute('data-mega-operation');
  if(['unzip','unzip-folder','untar','untar-folder'].indexOf(sharedOperation)!==-1)return sharedOperation;
  if(form.elements.namedItem('untar'))return form.elements.namedItem('tofolder')?'untar-folder':'untar';
  if(form.elements.namedItem('unzip'))return form.elements.namedItem('tofolder')?'unzip-folder':'unzip';
  if(form.elements.namedItem('newfile')&&form.elements.namedItem('newfilename'))return 'create';
  if(form.elements.namedItem('rename_to')&&form.elements.namedItem('rename_from'))return 'rename';
  if(form.elements.namedItem('copy_to')&&form.elements.namedItem('finish')){
   // Both buttons share this form; the Move submit button's presence alone
   // must not cause Copy to be labeled as Moving.
   return submitter&&submitter.form===form&&submitter.name==='move'?'move':'copy';
  }
  if(/[?&]del=/.test(action))return 'delete';
  if(name==='copy'&&form.querySelector('#a-copy'))return ''; // destination picker only
  if(/^(delete|zip|tar|copy|move|rename|unzip|extract|upload)$/.test(name))return name;
  for(var i=0,ops=['delete','zip','tar','move'];i<ops.length;i++){
   if(form.elements.namedItem(ops[i])&&form.elements.namedItem(ops[i]).type==='hidden')return ops[i];
  }
  return '';
 }
 document.addEventListener('submit',function(e){
  var form=e.target;if(!form||!form.matches||!form.matches('form'))return;
  if((form.getAttribute('method')||'get').toLowerCase()!=='post')return;
  if(form.classList.contains('dropzone')||form.id==='js-settings-form'||form.id==='js-form-url-upload'||form.dataset.type==='ajax')return;
  if(e.defaultPrevented||(form.checkValidity&&!form.checkValidity()))return;
  var operation=operationFor(form,e);
  if(operation){
   if(window.megaOperationSubmitting===form){e.preventDefault();return;}
   window.megaOperationSubmitting=form;
   window.megaOperationManager.begin(operation);
   if(['share-create','share-stop','rubbish-restore','rubbish-delete'].indexOf(operation)!==-1){
    e.preventDefault();
    // Allow the common indicator to paint before the blocking navigation.
    var frame=window.requestAnimationFrame||function(fn){setTimeout(fn,0);};
    frame(function(){frame(function(){HTMLFormElement.prototype.submit.call(form);});});
   }

  }
 },false);
 // Restore UI if navigation is canceled or the user returns using browser history.
 window.addEventListener('pageshow',function(){window.megaHideWorking();});
 window.addEventListener('pagehide',function(){window.megaHideWorking();});
 // AJAX requests that perform file mutations are tracked only when explicitly tagged.
 if(window.jQuery){jQuery(document).ajaxComplete(function(_event,_xhr,settings){if(settings&&settings.megaFileOperation)window.megaHideWorking();});}
})();
</script>
<script>
/* One shared auto-dismiss controller for all inline operation results. */
(function () {
    'use strict';
    var delay = 5000;
    var timers = typeof WeakMap !== 'undefined' ? new WeakMap() : null;
    // Every operation result shares one full-width region above page content.
    window.megaPlaceResult = function(note) {
        var wrapper = document.getElementById('wrapper');
        if (!wrapper || !note) return;
        var region = document.getElementById('mega-page-results');
        if (!region) {
            region = document.createElement('div');
            region.id = 'mega-page-results';
            region.style.cssText = 'width:100%;min-width:0;flex:0 0 100%;';
            // Mobile reserves header space inside the wrapper. Putting notices
            // before that spacer hides them underneath the fixed header.
            var spacer = wrapper.querySelector('.mega-mobile-header-spacer');
            wrapper.insertBefore(region, spacer ? spacer.nextSibling : wrapper.firstChild);
        }
        if (note.parentNode !== region) region.appendChild(note);
    };

    function schedule(note) {
        if (!note || !note.classList || !note.classList.contains('mega-inline-notice')) return;
        if (timers && timers.has(note)) clearTimeout(timers.get(note));
        if (note.hidden || note.style.display === 'none') return;
        window.megaPlaceResult(note);
        var timer = setTimeout(function () {
            note.hidden = true;
            note.style.display = 'none';
            if (timers) timers.delete(note);
        }, delay);
        if (timers) timers.set(note, timer);
    }
    window.megaNoticeSchedule = schedule;
    function scan(root) {
        if (!root || root.nodeType !== 1) return;
        if (root.matches && root.matches('.mega-inline-notice')) schedule(root);
        if (root.querySelectorAll) {
            var notes = root.querySelectorAll('.mega-inline-notice');
            for (var i = 0; i < notes.length; i++) schedule(notes[i]);
        }
    }
    function start() {
        scan(document.body);
        if (typeof MutationObserver === 'undefined') return;
        var observer = new MutationObserver(function (records) {
            for (var i = 0; i < records.length; i++) {
                var record = records[i];
                if (record.type === 'childList') {
                    for (var j = 0; j < record.addedNodes.length; j++) scan(record.addedNodes[j]);
                    if (record.target && record.target.closest) {
                        var parent = record.target.closest('.mega-inline-notice');
                        if (parent) schedule(parent);
                    }
                } else if (record.type === 'characterData' && record.target.parentElement) {
                    var note = record.target.parentElement.closest('.mega-inline-notice');
                    if (note) schedule(note);
                }
            }
        });
        observer.observe(document.body, {childList:true, subtree:true, characterData:true});
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
}());
</script>
<script id="mega-mobile-common-v41">
(function(){
'use strict';
function enhance(){
 if(!window.matchMedia('<?php echo fm_layout_media_query(); ?>').matches)return;
 var field=document.getElementById('inp_copy_to');
 if(field){field.setAttribute('autocomplete','off');field.setAttribute('spellcheck','false');}
 document.querySelectorAll('#mega-folder-picker #mega-folder-entries>button').forEach(function(b){if(!b.hasAttribute('type'))b.type='button';});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',enhance);else enhance();
var picker=document.getElementById('mega-folder-entries');
if(picker&&window.MutationObserver)new MutationObserver(enhance).observe(picker,{childList:true});
})();
</script>

<style id="mega-v68-sort-popup-theme">
@media<?php echo fm_layout_media_query(); ?>{
 html body .mega-view-controls #mega-mobile-sort{display:none!important}
 html body .mega-view-controls #mega-sort-custom-trigger{display:flex!important;align-items:center;justify-content:space-between;order:1;flex:0 0 105px;width:105px;min-width:0;padding:5px 7px;background:transparent;border:0;border-radius:6px;color:var(--bs-body-color,#212529);font-size:12px;white-space:nowrap;gap:7px}
 html body .mega-view-controls #mega-sort-custom-trigger:focus-visible{outline:2px solid #1672ed;outline-offset:1px}
 html body .mega-view-controls #mega-sort-custom-trigger .mega-sort-chevron{font-size:19px;line-height:1}
}
@media<?php echo fm_desktop_media_query(); ?>{#mega-sort-custom-trigger{display:none!important}}
#mega-sort-custom-menu[hidden]{display:none!important}
#mega-sort-custom-menu{position:fixed!important;z-index:2147483000!important;box-sizing:border-box!important;width:190px;max-width:75vw;padding:5px!important;border:1px solid #d7dce3!important;border-radius:12px!important;background:#fff!important;color:#212529!important;box-shadow:0 8px 24px rgba(0,0,0,.20)!important;overflow:auto!important}
#mega-sort-custom-menu .mega-sort-option{display:flex;width:100%;align-items:center;justify-content:space-between;gap:12px;padding:11px 12px;border:0;border-radius:8px;background:transparent;color:inherit;font:inherit;text-align:left;white-space:nowrap}
#mega-sort-custom-menu .mega-sort-option[aria-selected="true"]{font-weight:600;background:rgba(22,114,237,.10)}
#mega-sort-custom-menu .mega-sort-check{color:#1672ed;font-weight:bold}
html[data-bs-theme="dark"] #mega-sort-custom-menu,body.theme-dark #mega-sort-custom-menu{background:#242b30!important;color:#f1f5f9!important;border-color:#48535d!important;box-shadow:0 8px 24px rgba(0,0,0,.5)!important}
html[data-bs-theme="dark"] #mega-sort-custom-menu .mega-sort-option[aria-selected="true"],body.theme-dark #mega-sort-custom-menu .mega-sort-option[aria-selected="true"]{background:rgba(90,160,255,.20)}
html[data-bs-theme="dark"] #mega-sort-custom-trigger,body.theme-dark #mega-sort-custom-trigger{color:#e8edf4!important}
</style>
<script id="mega-v68-sort-popup-script">
(function(){
 var select=document.getElementById('mega-mobile-sort'),trigger=document.getElementById('mega-sort-custom-trigger'),menu=document.getElementById('mega-sort-custom-menu'),label=document.getElementById('mega-sort-custom-label');
 if(!select||!trigger||!menu)return;
 function close(){menu.hidden=true;trigger.setAttribute('aria-expanded','false')}
 function update(){var option=select.options[select.selectedIndex];label.textContent=option?option.textContent:'';Array.prototype.forEach.call(menu.children,function(b){var active=b.dataset.value===select.value;b.setAttribute('aria-selected',active?'true':'false');b.querySelector('.mega-sort-check').textContent=active?'✓':''})}
 Array.prototype.forEach.call(select.options,function(opt){var b=document.createElement('button');b.type='button';b.className='mega-sort-option';b.dataset.value=opt.value;b.setAttribute('role','option');var t=document.createElement('span');t.textContent=opt.textContent;var check=document.createElement('span');check.className='mega-sort-check';check.setAttribute('aria-hidden','true');b.appendChild(t);b.appendChild(check);b.addEventListener('click',function(){select.value=opt.value;select.dispatchEvent(new Event('change',{bubbles:true}));update();close();trigger.focus()});menu.appendChild(b)});
 function position(){var r=trigger.getBoundingClientRect(),w=Math.min(190,window.innerWidth*.75),h=menu.offsetHeight;menu.style.width=w+'px';menu.style.left=Math.max(8,Math.min(window.innerWidth-w-8,r.right-w))+'px';var below=window.innerHeight-r.bottom-8,above=r.top-8;menu.style.maxHeight=Math.max(80,Math.min(240,Math.max(below,above)))+'px';h=menu.offsetHeight;menu.style.top=(below>=h||below>=above?Math.min(r.bottom+4,window.innerHeight-h-8):Math.max(8,r.top-h-4))+'px'}
 trigger.addEventListener('click',function(e){e.stopPropagation();if(!menu.hidden){close();return}update();menu.hidden=false;trigger.setAttribute('aria-expanded','true');position()});
 document.addEventListener('click',function(e){if(!menu.contains(e.target)&&e.target!==trigger&&!trigger.contains(e.target))close()});
 document.addEventListener('keydown',function(e){if(e.key==='Escape')close()});
 window.addEventListener('resize',close);window.addEventListener('scroll',close,true);
 select.addEventListener('change',update);update();
})();
</script>
<style id="mega-v70-settings-select-style">
.mega-settings-panel .mega-settings-native-hidden{position:absolute!important;width:1px!important;height:1px!important;opacity:0!important;pointer-events:none!important}
.mega-settings-panel .mega-settings-select-trigger{width:100%;min-height:42px;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 12px;border:1px solid #d8dee5;border-radius:7px;background:#fff;color:#212529;text-align:left;font:inherit;cursor:pointer}
.mega-settings-panel .mega-settings-select-trigger .mega-settings-arrow{font-size:15px;flex-shrink:0}
body.theme-dark .mega-settings-panel .mega-settings-select-trigger,.mega-settings-panel[data-bs-theme="dark"] .mega-settings-select-trigger,[data-bs-theme="dark"] .mega-settings-panel .mega-settings-select-trigger{background:#171a1e;color:#f1f5f9;border-color:#48535d}
#mega-settings-choice-menu[hidden]{display:none!important}
#mega-settings-choice-menu{position:fixed;z-index:2147483000;box-sizing:border-box;width:210px;max-width:calc(100vw - 24px);max-height:65vh;overflow-y:auto;overscroll-behavior:contain;padding:5px;border:1px solid #d8dee5;border-radius:10px;background:#fff;color:#212529;box-shadow:0 8px 24px rgba(0,0,0,.22)}
#mega-settings-choice-menu .mega-settings-choice{display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;padding:10px 12px;border:0;border-radius:6px;background:transparent;color:inherit;text-align:left;font:inherit;cursor:pointer}
#mega-settings-choice-menu .mega-settings-choice[aria-selected="true"]{background:rgba(22,114,237,.12);font-weight:600}
#mega-settings-choice-menu .mega-settings-choice:hover{background:rgba(22,114,237,.10)}
#mega-settings-choice-menu .mega-settings-choice-check{color:#1672ed}
#mega-settings-choice-menu[data-bs-theme="dark"],body.theme-dark #mega-settings-choice-menu,html[data-bs-theme="dark"] #mega-settings-choice-menu{background:#242b30;color:#f1f5f9;border-color:#48535d;box-shadow:0 8px 24px rgba(0,0,0,.5)}
#mega-settings-choice-menu[data-bs-theme="dark"] .mega-settings-choice[aria-selected="true"],body.theme-dark #mega-settings-choice-menu .mega-settings-choice[aria-selected="true"],html[data-bs-theme="dark"] #mega-settings-choice-menu .mega-settings-choice[aria-selected="true"]{background:rgba(90,160,255,.20)}
</style>
<script id="mega-v70-settings-select-script">
(function(){
function init(){
 var panel=document.querySelector('.mega-settings-panel');if(!panel)return;
 var selects=[document.getElementById('js-language'),document.getElementById('js-3-0'),document.getElementById('js-view-mode'),document.getElementById('js-delete-mode')].filter(Boolean);
 if(!selects.length)return;
 var menu=document.createElement('div');menu.id='mega-settings-choice-menu';menu.hidden=true;menu.setAttribute('role','listbox');document.body.appendChild(menu);menu.setAttribute('data-bs-theme',panel.getAttribute('data-bs-theme')||'light');
 var active=null,activeTrigger=null;
 function close(){menu.hidden=true;if(activeTrigger)activeTrigger.setAttribute('aria-expanded','false');active=null;activeTrigger=null}
 function place(){if(!activeTrigger)return;var r=activeTrigger.getBoundingClientRect();var w=Math.min(Math.max(r.width,190),280,window.innerWidth-24);menu.style.width=w+'px';menu.style.left=Math.max(12,Math.min(window.innerWidth-w-12,r.left))+'px';var below=window.innerHeight-r.bottom-12,above=r.top-12;menu.style.maxHeight=Math.max(100,Math.min(360,Math.max(below,above)))+'px';var h=menu.offsetHeight;menu.style.top=(below>=h||below>=above?Math.min(r.bottom+4,window.innerHeight-h-8):Math.max(8,r.top-h-4))+'px'}
 selects.forEach(function(sel){
  if(sel.dataset.megaSettingsEnhanced)return;sel.dataset.megaSettingsEnhanced='1';sel.classList.add('mega-settings-native-hidden');sel.tabIndex=-1;
  var trigger=document.createElement('button');trigger.type='button';trigger.className='mega-settings-select-trigger';trigger.setAttribute('aria-haspopup','listbox');trigger.setAttribute('aria-expanded','false');
  var label=document.createElement('span'),arrow=document.createElement('span');arrow.className='mega-settings-arrow';arrow.textContent='⌄';trigger.appendChild(label);trigger.appendChild(arrow);sel.insertAdjacentElement('afterend',trigger);
  function sync(){label.textContent=sel.options[sel.selectedIndex]?sel.options[sel.selectedIndex].textContent.trim():''}
  sel.addEventListener('change',sync);sync();
  trigger.addEventListener('click',function(e){e.stopPropagation();if(active===sel&&!menu.hidden){close();return}close();active=sel;activeTrigger=trigger;menu.replaceChildren();
   Array.prototype.forEach.call(sel.options,function(opt){var item=document.createElement('button');item.type='button';item.className='mega-settings-choice';item.setAttribute('role','option');item.setAttribute('aria-selected',opt.selected?'true':'false');var txt=document.createElement('span');txt.textContent=opt.textContent.trim();var check=document.createElement('span');check.className='mega-settings-choice-check';check.textContent=opt.selected?'✓':'';item.appendChild(txt);item.appendChild(check);item.addEventListener('click',function(){sel.value=opt.value;sel.dispatchEvent(new Event('change',{bubbles:true}));close();trigger.focus()});menu.appendChild(item)});
   menu.setAttribute('data-bs-theme',panel.getAttribute('data-bs-theme')||'light');menu.hidden=false;trigger.setAttribute('aria-expanded','true');place();
  });
 });
 document.addEventListener('click',function(e){if(!menu.contains(e.target)&&(!activeTrigger||!activeTrigger.contains(e.target)))close()});document.addEventListener('keydown',function(e){if(e.key==='Escape')close()});window.addEventListener('resize',close);window.addEventListener('scroll',function(e){if(!menu.contains(e.target))close()},true);
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
</script>

<script id="mega-v95-button-icon-spacing-script">
(function () {
    'use strict';
    var selector = 'button, a.btn, .swal-button, .swal2-actions button';
    function normalize(root) {
        if (!root || !root.querySelectorAll) return;
        var controls = [];
        if (root.matches && root.matches(selector)) controls.push(root);
        root.querySelectorAll(selector).forEach(function (el) { controls.push(el); });
        controls.forEach(function (control) {
            // Do not add space to icon-only controls (file-list action icons).
            var icons = Array.prototype.filter.call(control.children, function (child) {
                return child.matches && child.matches('i.fa, i.fas, i.far, i.fab, svg, .glyphicon');
            });
            var hasCaption = Array.prototype.some.call(control.childNodes, function (node) {
                if (node.nodeType === 3) return !!node.textContent.trim();
                return node.nodeType === 1 && icons.indexOf(node) < 0 &&
                    !!node.textContent.trim() && !node.matches('svg, .sr-only, .visually-hidden');
            });
            control.classList.toggle('mega-icon-label-gap', hasCaption && icons.length > 0);
            icons.forEach(function (icon) {
                icon.classList.toggle('mega-caption-icon', hasCaption);
            });
        });
    }
    function start() {
        normalize(document);
        // Confirm dialogs and file actions can be inserted after initial load.
        var pending = false;
        new MutationObserver(function () {
            if (pending) return;
            pending = true;
            Promise.resolve().then(function () { pending = false; normalize(document); });
        }).observe(document.body, {childList: true, subtree: true});
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
})();
</script>
</body>

    </html>
<?php
    }

    /**
     * Language Translation System
     * @param string $txt
     * @return string
     */
    function lng($txt)
    {
        global $lang;

        // English Language
        $tr['en']['AppName']        = 'Tiny File Manager';
        $tr['en']['AppTitle']       = 'File Manager';
        $tr['en']['Login']          = 'Sign in';
        $tr['en']['Username']       = 'Username';
        $tr['en']['Password']       = 'Password';
        $tr['en']['Logout']         = 'Sign Out';
        $tr['en']['Move']           = 'Move';
        $tr['en']['Copy']           = 'Copy';
        $tr['en']['Save']           = 'Save';
        $tr['en']['SelectAll']      = 'Select all';
        $tr['en']['UnSelectAll']    = 'Unselect all';
        $tr['en']['File']           = 'File';
        $tr['en']['Back']           = 'Back';
        $tr['en']['Size']           = 'Size';
        $tr['en']['Perms']          = 'Perms';
        $tr['en']['Modified']       = 'Modified';
        $tr['en']['Owner']          = 'Owner';
        $tr['en']['Search']         = 'Search';
        $tr['en']['NewItem']        = 'New Item';
        $tr['en']['Folder']         = 'Folder';
        $tr['en']['Delete']         = 'Delete';
        $tr['en']['Rename']         = 'Rename';
        $tr['en']['CopyTo']         = 'Copy to';
        $tr['en']['UploadingFiles'] = 'Upload Files';
        $tr['en']['ChangePermissions']  = 'Change Permissions';
        $tr['en']['Copying']        = 'Copying';
        $tr['en']['CreateNewItem']  = 'Create New Item';
        $tr['en']['Name']           = 'Name';
        $tr['en']['AdvancedEditor'] = 'Advanced Editor';
        $tr['en']['Actions']        = 'Actions';
        $tr['en']['Folder is empty'] = 'Folder is empty';
        $tr['en']['Upload']         = 'Upload';
        $tr['en']['Cancel']         = 'Cancel';
        $tr['en']['InvertSelection'] = 'Invert Selection';
        $tr['en']['DestinationFolder']  = 'Destination Folder';
        $tr['en']['ItemType']       = 'Item Type';
        $tr['en']['ItemName']       = 'Item Name';
        $tr['en']['CreateNow']      = 'Create Now';
        $tr['en']['Create']         = 'Create';
        $tr['en']['Download']       = 'Download';
        $tr['en']['Open']           = 'Open';
        $tr['en']['Link created.'] = 'Link created.';
        $tr['en']['UnTar'] = 'Untar';
        $tr['en']['UnTarToFolder'] = 'Untar to folder';
        $tr['en']['UnZip']          = 'UnZip';
        $tr['en']['UnZipToFolder']  = 'UnZip to folder';
        $tr['en']['Edit']           = 'Edit';
        $tr['en']['NormalEditor']   = 'Normal Editor';
        $tr['en']['BackUp']         = 'Back Up';
        $tr['en']['SourceFolder']   = 'Source Folder';
        $tr['en']['Files']          = 'Files';
        $tr['en']['Change']         = 'Change';
        $tr['en']['Settings']       = 'Settings';
        $tr['en']['Language']       = 'Language';
        $tr['en']['ErrorReporting'] = 'Error Reporting';
        $tr['en']['ShowHiddenFiles'] = 'Show Hidden Files';
        $tr['en']['Help']           = 'Help';
        $tr['en']['Created']        = 'Created';
        $tr['en']['Help Documents'] = 'Help Documents';
        $tr['en']['Report Issue']   = 'Report Issue';
        $tr['en']['Generate']       = 'Generate';
        $tr['en']['FullSize']       = 'Full Size';
        $tr['en']['HideColumns']    = 'Hide Perms/Owner columns';
        $tr['en']['You are logged in'] = 'You are logged in';
        $tr['en']['Nothing selected']  = 'Nothing selected';
        $tr['en']['Paths must be not equal']    = 'Paths must be not equal';
        $tr['en']['Renamed from']       = 'Renamed from';
        $tr['en']['Archive not unpacked'] = 'Archive not unpacked';
        $tr['en']['Deleted']            = 'Deleted';
        $tr['en']['Archive not created'] = 'Archive not created';
        $tr['en']['Copied from']        = 'Copied from';
        $tr['en']['Permissions changed'] = 'Permissions changed';
        $tr['en']['to']                 = 'to';
        $tr['en']['Saved Successfully'] = 'Saved Successfully';
        $tr['en']['not found!']         = 'not found!';
        $tr['en']['File Saved Successfully']    = 'File Saved Successfully';
        $tr['en']['Archive']            = 'Archive';
        $tr['en']['Permissions not changed']    = 'Permissions not changed';
        $tr['en']['Select folder']      = 'Select folder';
        $tr['en']['Source path not defined']    = 'Source path not defined';
        $tr['en']['already exists']     = 'already exists';
        $tr['en']['Error while moving from']    = 'Error while moving from';
        $tr['en']['Create archive?']    = 'Create archive?';
        $tr['en']['Invalid file or folder name']    = 'Invalid file or folder name';
        $tr['en']['Archive unpacked']   = 'Archive unpacked';
        $tr['en']['File extension is not allowed']  = 'File extension is not allowed';
        $tr['en']['Root path']          = 'Root path';
        $tr['en']['Error while renaming from']  = 'Error while renaming from';
        $tr['en']['File not found']     = 'File not found';
        $tr['en']['Error while deleting items'] = 'Error while deleting items';
        $tr['en']['Moved from']         = 'Moved from';
        $tr['en']['Generate new password hash'] = 'Generate new password hash';
        $tr['en']['Login failed. Invalid username or password'] = 'Login failed. Invalid username or password';
        $tr['en']['password_hash not supported, Upgrade PHP version'] = 'password_hash not supported, Upgrade PHP version';
        $tr['en']['Advanced Search']    = 'Advanced Search';
        $tr['en']['Error while copying from']    = 'Error while copying from';
        $tr['en']['Invalid characters in file name']                = 'Invalid characters in file name';
        $tr['en']['FILE EXTENSION IS NOT SUPPORTED']                = 'FILE EXTENSION IS NOT SUPPORTED';
        $tr['en']['Selected files and folder deleted']              = 'Selected files and folder deleted';
        $tr['en']['Error while fetching archive info']              = 'Error while fetching archive info';
        $tr['en']['Delete selected files and folders?']             = 'Delete selected files and folders?';
        $tr['en']['Search file in folder and subfolders...']        = 'Search file in folder and subfolders...';
        $tr['en']['Access denied. IP restriction applicable']       = 'Access denied. IP restriction applicable';
        $tr['en']['Invalid characters in file or folder name']      = 'Invalid characters in file or folder name';
        $tr['en']['Operations with archives are not available']     = 'Operations with archives are not available';
        $tr['en']['File or folder with this path already exists']   = 'File or folder with this path already exists';
        $tr['en']['Are you sure to rename?']                     = 'Are you sure to rename?';
        $tr['en']['Are you sure to']                                = 'Are you sure to';
        $tr['en']['Date Modified']                                  = 'Date Modified';
        $tr['en']['File size']                                      = 'File size';
        $tr['en']['MIME-type']                                      = 'MIME-type';
        $tr['en']['a files']                                        = 'files';
// Pre-existing inputs that were never inserted into the lng() function
        $tr['en']['Cannot open file! Aborting download'] = 'Cannot open file! Aborting download';
        $tr['en']['Charset']            = 'Charset';
        $tr['en']['Compression']        = 'Compression';
        $tr['en']['dark']               = 'dark';
        $tr['en']['light']              = 'light';
        $tr['en']['ERROR: Try again later!'] = 'ERROR: Try again later!';
        $tr['en']['Enter here...']      = 'Enter here...';
        $tr['en']['Enter new file name'] = 'Enter new file name';
        $tr['en']['Error']              = 'Error';
        $tr['en']['Error while copying items'] = 'Error while copying items';
        $tr['en']['Error while moving items']  = 'Error while moving items';
        $tr['en']['Error: try again']   = 'Error: try again';
        $tr['en']['Execute']            = 'Execute';
        $tr['en']['Files in archive']   = 'Files in archive';
        $tr['en']['Fullscreen']         = 'Fullscreen';
        $tr['en']['Group']              = 'Group';
        $tr['en']['Image size']         = 'Image size';
        $tr['en']['Invalid Token.']     = 'Invalid Token.';
        $tr['en']['No result found!']   = 'No result found!';
        $tr['en']['not created']        = 'not created';
        $tr['en']['not deleted']        = 'not deleted';
        $tr['en']['OOPS: minimum 3 characters required!'] = 'OOPS: minimum 3 characters required!';
        $tr['en']['Okay']               = 'OK';
        $tr['en']['Other']              = 'Other';
        $tr['en']['Read']               = 'Read';
        $tr['en']['Redo']               = 'Redo';
        $tr['en']['Select Document Type'] = 'Select Document Type';
        $tr['en']['Select Font Size']   = 'Select Font Size';
        $tr['en']['Select Mode']        = 'Select Mode';
        $tr['en']['Select Theme']       = 'Select Theme';
        $tr['en']['Source and destination are the same folder.'] = 'Source and destination are the same folder.';
        $tr['en']['Are you sure you want to delete this file?'] = 'Are you sure you want to delete this file?';
        $tr['en']['Are you sure you want to delete this folder?'] = 'Are you sure you want to delete this folder?';
        $tr['en']['Are you sure you want to delete this item?'] = 'Are you sure you want to delete this item?';
        $tr['en']['Okay'] = 'OK';
        $tr['en']['Are you sure to delete selected files and folders?'] = 'Are you sure to delete selected files and folders?';
        $tr['en']['Are you sure to create zip archive?'] = 'Are you sure to create zip archive?';
        $tr['en']['Are you sure to create tar archive?'] = 'Are you sure to create tar archive?';
        $tr['en']['Selected files and folder deleted'] = 'Selected files and folder deleted';
        $tr['en']['Error while deleting items'] = 'Error while deleting items';
        $tr['en']['Selected files and folders copied'] = 'Selected files and folders copied';
        $tr['en']['Selected files and folders moved']  = 'Selected files and folders moved';
        $tr['en']['Size in archive']    = 'Size in archive';
        $tr['en']['Sometimes the save action may not work on the first try, so please attempt it again'] = 'Sometimes the save action may not work on the first try, so please attempt it again';
        $tr['en']['Tar']                = 'Tar';
        $tr['en']['Theme']              = 'Theme';
        $tr['en']['File already exists: '] = 'File already exists: ';
        $tr['en'][' succeeded, '] = ' succeeded, ';
        $tr['en'][' failed'] = ' failed';
        $tr['en'][' items failed'] = ' items failed';
        $tr['en'][' of '] = ' of ';
        $tr['en']['Server administrator setting (not saved in browser).'] = 'Server administrator setting (not saved in browser).';
        $tr['en']['Drop files here to upload'] = 'Drop files here to upload';
        $tr['en']['Please fill out this field.'] = 'Please fill out this field.';
        $tr['en']['Archive'] = 'Archive';
        $tr['en']['Full Path'] = 'Full Path';
        $tr['en']['Files in archive'] = 'Files in archive';
        $tr['en']['Total size'] = 'Total size';
        $tr['en']['Size in archive'] = 'Size in archive';
        $tr['en']['Compression'] = 'Compression';
        $tr['en']['light'] = 'light';
        $tr['en']['dark'] = 'dark';
        $tr['en']['Copy/Move'] = 'Copy/Move';
        $tr['en']['Enter here...'] = 'Enter here...';
        $tr['en']['File already exists'] = 'File already exists';

        $tr['en']['Total size']         = 'Total size';
        $tr['en']['Unable to create destination folder'] = 'Unable to create destination folder';
        $tr['en']['Undo']               = 'Undo';
        $tr['en']['Upload from URL']    = 'Upload from URL';
        $tr['en']['Uploaded Successful'] = 'Uploaded Successful';
        $tr['en']['Word Wrap']          = 'Word Wrap';
        $tr['en']['Write']              = 'Write';
        $tr['en']['Zero byte file! Aborting download'] = 'Zero byte file! Aborting download';
        $tr['en']['Zip']                = 'Zip';
// New entries, which deserve to be translated
        $tr['en']['Author']             = 'Author';
        $tr['en']['Mail Us']            = 'Mail Us';

        $i18n = fm_get_translations($tr);
        $tr = $i18n ? $i18n : $tr;


        if (!strlen($lang)) $lang = 'en';
        if (isset($tr[$lang][$txt])) return fm_enc($tr[$lang][$txt]);
        else if (isset($tr['en'][$txt])) return fm_enc($tr['en'][$txt]);
        else return "$txt";
    }

?>


<?php
/** Integrated authenticated MEGA search. No separate page or navigation template. */
/** Local search: bounded traversal without following symlinks. */
function fm_local_search_page() {
    $term = trim((string)($_GET['q'] ?? ''));
    fm_show_header();
    fm_show_nav_path(FM_PATH);
    echo '<div class="container-fluid"><form method="get" class="mb-3">'
       . '<input type="hidden" name="local_tools" value="1">'
       . '<input type="hidden" name="p" value="' . fm_enc(FM_PATH) . '">'
       . '<input name="q" class="form-control" value="' . fm_enc($term) . '" placeholder="Search files">'
       . '<button class="btn btn-primary mt-2" type="submit"><i class="fa fa-search" aria-hidden="true"></i> ' . lng('Search') . '</button></form>';
    if ($term !== '') {
        $base = FM_ROOT_PATH . (FM_PATH !== '' ? '/' . FM_PATH : '');
        $count = 0;
        try {
            $flags = FilesystemIterator::SKIP_DOTS;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, $flags),
                RecursiveIteratorIterator::SELF_FIRST);
            echo '<div class="list-group">';
            foreach ($it as $entry) {
                if ($count >= 500) break;
                if ($it->getDepth() > 15 || $entry->isLink()) continue;
                if (stripos($entry->getFilename(), $term) === false) continue;
                $relative = ltrim(substr($entry->getPathname(), strlen(FM_ROOT_PATH)), '/');
                $parent = dirname($relative); if ($parent === '.') $parent = '';
                echo '<a class="list-group-item" href="?p=' . rawurlencode($parent) . '">'
                   . fm_enc($relative) . '</a>';
                $count++;
            }
            echo '</div>';
        } catch (Throwable $e) { echo '<p>Search could not be completed.</p>'; }
    }
    echo '</div>';
    fm_show_footer();
}

function fm_mega_search_path($handle, &$memo, &$visiting) {
    if (array_key_exists($handle, $memo)) return $memo[$handle];
    if (isset($visiting[$handle]) || !isset(MegaApi::$nodes[$handle])) return null;
    $visiting[$handle] = true;
    $node = MegaApi::$nodes[$handle];
    if ($handle === MegaApi::$root) $path = '';
    else {
        $parent = fm_mega_search_path($node['p'], $memo, $visiting);
        $path = $parent === null ? null : ltrim($parent . '/' . $node['n'], '/');
    }
    unset($visiting[$handle]);
    return $memo[$handle] = $path;
}

function fm_mega_search_page() {
    $scope = FM_PATH;
    $q = trim((string)($_GET['q'] ?? ''));
    $exactMatch = isset($_GET['exact_match']) && (string)$_GET['exact_match'] === '1';
    $caseSensitive = isset($_GET['case_sensitive']) && (string)$_GET['case_sensitive'] === '1';
    if (strlen($q) > 256) $q = substr($q, 0, 256);
    if (strlen($scope) > 2048 || strpos($scope, "\\0") !== false || preg_match('~(^|/)\\.\\.?(/|$)~', $scope)) {
        http_response_code(400); exit('Invalid search folder');
    }
    try { MegaApi::load(); } catch (Throwable $e) { http_response_code(502); exit('Cannot load cloud metadata'); }
    $memo = []; $visiting = [];
    $scopeFound = ($scope === '');
    if (!$scopeFound) {
        foreach (MegaApi::$nodes as $handle => $node) {
            if ((int)($node['t'] ?? 0) !== 1) continue;
            if (fm_mega_search_path($handle, $memo, $visiting) === $scope) { $scopeFound = true; break; }
        }
    }
    if (!$scopeFound) { http_response_code(404); exit(lng('Search folder not found')); }
    fm_show_header();
    fm_show_nav_path($scope);
    ?>
    <main class="container-fluid fm-page-content mega-search-page">
      <section class="card mega-search-card fm-form-panel mb-4" data-bs-theme="<?php echo FM_THEME; ?>">
        <div class="card-header"><i class="fa fa-search fa-fw" aria-hidden="true"></i> <?php echo lng('Search File'); ?></div>
        <div class="card-body">
          <p class="text-secondary mega-search-scope"><?php echo lng('Search in'); ?>: <strong><?php echo fm_enc($scope === '' ? 'MEGA root /' : 'MEGA root / ' . $scope); ?></strong> <?php echo lng('and subfolders'); ?></p>
          <form method="get" action="index.php" class="mega-search-form">
            <input type="hidden" name="mega_tools" value="1">
            <input type="hidden" name="p" value="<?php echo fm_enc($scope); ?>">
            <input type="search" name="q" class="form-control" value="<?php echo fm_enc($q); ?>" placeholder="<?php echo lng('Search by file or folder name'); ?>" aria-label="<?php echo lng('Search MEGA files and folders'); ?>" maxlength="256">
            <div class="mega-search-options" role="group" aria-label="<?php echo lng('Search options'); ?>">
              <label class="mega-search-option"><input type="checkbox" name="exact_match" value="1" <?php echo $exactMatch ? 'checked' : ''; ?>> <?php echo lng('Exact match'); ?></label>
              <label class="mega-search-option"><input type="checkbox" name="case_sensitive" value="1" <?php echo $caseSensitive ? 'checked' : ''; ?>> <?php echo lng('Case sensitive'); ?></label>
            </div>
            <div class="fm-unified-actions mega-search-actions">
              <a class="btn btn-outline-secondary fm-unified-button" href="?p=<?php echo rawurlencode($scope); ?>"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></a>
              <button type="submit" class="btn btn-primary fm-unified-button"><i class="fa fa-search" aria-hidden="true"></i> <?php echo lng('Search'); ?></button>
            </div>
          </form>
          <?php if ($q !== ''):
              $matches = [];
              foreach (MegaApi::$nodes as $handle => $node) {
                  if (!isset($node['n'])) continue;
                  $name = (string)$node['n'];
                  $found = $exactMatch
                      ? ($caseSensitive ? strcmp($name, $q) === 0 : strcasecmp($name, $q) === 0)
                      : ($caseSensitive ? strpos($name, $q) !== false : stripos($name, $q) !== false);
                  if (!$found) continue;
                  $path = fm_mega_search_path($handle, $memo, $visiting);
                  if ($path === null || ($scope !== '' && $path !== $scope && strpos($path, $scope . '/') !== 0)) continue;
                  $isFile = ((int)($node['t'] ?? 0) === 0);
                  $folder = $isFile ? dirname($path) : $path;
                  if ($folder === '.') $folder = '';
                  $matches[] = ['name' => $node['n'], 'folder' => $folder, 'isFile' => $isFile, 'size' => $node['s'] ?? null];
                  if (count($matches) >= 500) break;
              }
          ?>
          <p class="text-secondary mt-3 mb-2"><?php echo count($matches); ?> <?php echo lng(count($matches) === 1 ? 'result' : 'results'); ?><?php echo count($matches) >= 500 ? ' (' . lng('limit reached') . ')' : ''; ?></p>
          <div class="mega-search-results">
            <?php if (!$matches): ?><div class="mega-search-empty"><?php echo lng('No files or folders match your search.'); ?></div>
            <?php else: foreach ($matches as $match): ?>
              <article class="mega-search-result">
                <span class="mega-search-file-icon" aria-hidden="true"><i class="fa <?php echo $match['isFile'] ? 'fa-file-o' : 'fa-folder-o'; ?>"></i></span>
                <div class="mega-search-detail">
                  <div class="mega-search-filename"><?php echo fm_enc($match['name']); ?></div>
                  <div class="mega-search-folder"><a href="?p=<?php echo rawurlencode($match['folder']); ?>" title="<?php echo lng('Open folder'); ?>"><?php echo fm_enc('/' . $match['folder']); ?></a></div>
                </div>
                <span class="mega-search-size"><?php echo $match['isFile'] ? ($match['size'] === null ? '—' : fm_enc(fm_get_filesize($match['size']))) : lng('Folder'); ?></span>
              </article>
            <?php endforeach; endif; ?>
          </div>
          <p class="text-secondary small mt-3"><?php echo lng('Search includes this folder and its subfolders. Up to 500 matches are displayed.'); ?></p>
          <?php endif; ?>
        </div>
      </section>
    </main>
    <?php
    fm_show_footer();
}

/** True only for file/folder nodes inside this account's rubbish tree. */
function fm_mega_in_rubbish($handle) {
    $seen=[];
    while (isset(MegaApi::$nodes[$handle]) && !isset($seen[$handle])) {
        $seen[$handle]=true;
        $parent=MegaApi::$nodes[$handle]['p'] ?? '';
        if ($parent === MegaApi::$trash) return true;
        $handle=$parent;
    }
    return false;
}

function fm_mega_rubbish_mutate($action, $handles) {
    if (FM_STORAGE_TYPE !== 'mega' || FM_READONLY) throw new Exception(lng('Read-only mode'));
    if (!in_array($action,['restore','delete'],true) || !is_array($handles) || !$handles || count($handles)>1000) throw new Exception(lng('Invalid file'));
    MegaApi::invalidate(); MegaApi::load();
    foreach ($handles as $h) {
        if (!is_string($h) || !preg_match('/\A[A-Za-z0-9_-]{8}\z/',$h) || !fm_mega_in_rubbish($h)) throw new Exception(lng('Invalid file'));
        if ($action==='restore' && (MegaApi::$nodes[$h]['p']??'')!==MegaApi::$trash) throw new Exception(lng('Only items directly in the Rubbish Bin can be restored.'));
    }
    $handles=array_values(array_unique($handles));
    // A selected parent already includes its selected descendants.
    $selected=array_fill_keys($handles,true); $done=0;
    foreach ($handles as $h) {
        $parent=MegaApi::$nodes[$h]['p']; $skip=false; $seen=[];
        while (isset(MegaApi::$nodes[$parent]) && !isset($seen[$parent])) {
            if (isset($selected[$parent])) {$skip=true;break;}
            $seen[$parent]=true;$parent=MegaApi::$nodes[$parent]['p'];
        }
        if ($skip) continue;
        if ($action==='delete') $ok=MegaApi::delete($h);
        else {
            $node=MegaApi::$nodes[$h]; $target=$node['rr'] ?? '';
            // Missing/deleted original folders restore to the Cloud Drive root.
            if (!isset(MegaApi::$nodes[$target]) || !in_array((int)MegaApi::$nodes[$target]['t'],[1,2],true) || fm_mega_in_rubbish($target)) $target=MegaApi::$root;
            $name=$node['n'];$suffix=1;
            while (isset(MegaApi::$kids[$target][$name])) $name=$node['n'].' ('.$suffix++.')';
            $ok=MegaApi::move($h,$target,$name);
            if ($ok) MegaApi::$kids[$target][$name]=$h;
        }
        if (!$ok) throw new Exception(lng('Operation failed'). ' ('.$done.')');
        $done++;
    }
    MegaApi::invalidate();
    return $done;
}

/** Stage only formats requiring server-side inspection; client viewers fetch the
 * authenticated rubbish endpoint directly and never restore or modify the file. */
function fm_rubbish_preview($node) {
    $file=$node['n'];$ext=strtolower(pathinfo($file,PATHINFO_EXTENSION));
    $file_url=FM_SELF_URL.'?mega_rubbish=1&p=&trash_open='.rawurlencode($node['h']);
    $path='mega://rubbish';$file_path='';$filesize_raw=(int)$node['s'];
    $is_zip=in_array($ext,['zip','tar'],true);$filenames=false;$content='';
    $is_image=in_array($ext,['png','jpg','jpeg','gif','bmp','webp','avif','ico'],true);
    $is_audio=in_array($ext,['mp3','wav','ogg','m4a','flac'],true);
    $is_video=in_array($ext,['mp4','webm','ogv'],true);
    $is_text=in_array($ext,array_merge(fm_get_text_exts(),['json','csv','md','log','yaml','yml']),true);
    $is_onlineViewer=false;$online_viewer='';$tmp=false;
    $supported=$is_zip||$is_image||$is_audio||$is_video||$is_text||in_array($ext,['pdf','doc','docx','xls','xlsx','xlsm','ppt','pptx','vsdx'],true);
    echo '<div class="text-secondary small mb-2">'.fm_enc(lng('Read-only preview')).'</div>';
    try {
        if(!$supported){echo '<p role="status">'.fm_enc(lng('Preview is unavailable for this file type.')).'</p>';return;}
        if($filesize_raw>67108864)throw new Exception(lng('Preview file exceeds 64 MiB limit.'));
        if($is_zip||$is_text||in_array($ext,['doc','ppt'],true)) {
            if($is_text&&$filesize_raw>2097152)throw new Exception(lng('Text preview exceeds 2 MiB limit.'));
            $tmp=tempnam(sys_get_temp_dir(),'mega_trash_view_');
            if($tmp===false)throw new Exception(lng('Operation failed'));
            $named=$tmp.'.'.$ext;if(!rename($tmp,$named))throw new Exception(lng('Operation failed'));$tmp=$named;
            if(!MegaApi::download($node['h'],$tmp)||filesize($tmp)!==$filesize_raw)throw new Exception(lng('Operation failed'));
            $file_path=$tmp;
            if($is_zip)$filenames=fm_get_zip_info($tmp,$ext);
            if($is_text)$content=file_get_contents($tmp);
        }
        fm_render_readonly_preview(compact('file','ext','file_url','path','file_path','filesize_raw','is_zip','filenames','content','is_image','is_audio','is_video','is_text','is_onlineViewer','online_viewer'));
    } catch(Throwable $e){echo '<p class="text-danger" role="alert">'.fm_enc($e->getMessage()).'</p>';}
    finally {if($tmp!==false)@unlink($tmp);}
}

/** Render the shared navigation with unrelated rubbish-context actions disabled. */
function fm_show_rubbish_nav() {
    ob_start();fm_show_nav_path('');$nav=ob_get_clean();
    $nav=preg_replace_callback('/<a\b([^>]*?)href="([^"]*)"([^>]*)>(.*?)<\/a>/s',function($m){
        $url=html_entity_decode($m[2],ENT_QUOTES,'UTF-8');
        parse_str((string)parse_url($url,PHP_URL_QUERY),$query);
        $blocked=['upload','new_item','mega_tools','mega_shared_links','mega_rubbish'];
        if(!array_intersect($blocked,array_keys($query)))return $m[0];
        $attrs=$m[1].$m[3];
        if(preg_match('/class="([^"]*)"/',$attrs))$attrs=preg_replace('/class="([^"]*)"/','class="$1 fm-nav-disabled"',$attrs,1);
        else $attrs.=' class="fm-nav-disabled"';
        return '<a '.$attrs.' role="link" aria-disabled="true" tabindex="-1">'.$m[4].'</a>';
    },$nav);
    echo $nav;
    echo '<style>.fm-nav-disabled{opacity:.45!important;cursor:default!important;pointer-events:none!important}
</style>';
}

/** Shared translated summary for live and rubbish file lists. */
function fm_file_list_summary($bytes,$files,$folders) {
    echo lng('FullSize').': <span class="badge text-bg-light border-radius-0">'.fm_enc(fm_get_filesize($bytes)).'</span> ';
    echo lng('File').': <span class="badge text-bg-light border-radius-0">'.(int)$files.'</span> ';
    echo lng('Folder').': <span class="badge text-bg-light border-radius-0">'.(int)$folders.'</span>';
}

function fm_mega_rubbish_page() {
    fm_share_require_mega();
    if (isset($_GET['trash_open'])) {
        $tmp=false;
        try {
            MegaApi::invalidate();MegaApi::load();
            $h=(string)$_GET['trash_open'];
            if (!fm_mega_in_rubbish($h) || (int)MegaApi::$nodes[$h]['t']!==0) throw new Exception(lng('Invalid file'));
            $node=MegaApi::$nodes[$h];$tmp=tempnam(sys_get_temp_dir(),'mega_trash_');
            if ($tmp===false || !MegaApi::download($h,$tmp)) throw new Exception(lng('Operation failed'));
            $ext=strtolower(pathinfo($node['n'],PATHINFO_EXTENSION));
            $mime=$ext==='pdf'?'application/pdf':(in_array($ext,['txt','log','json','csv','md','java','php','html','css','js'],true)?'text/plain; charset=utf-8':'application/octet-stream');
            $media=['png'=>'image/png','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','gif'=>'image/gif','webp'=>'image/webp','bmp'=>'image/bmp','avif'=>'image/avif','ico'=>'image/x-icon','mp3'=>'audio/mpeg','wav'=>'audio/wav','ogg'=>'audio/ogg','m4a'=>'audio/mp4','flac'=>'audio/flac','mp4'=>'video/mp4','webm'=>'video/webm','ogv'=>'video/ogg'];
            if(isset($media[$ext]))$mime=$media[$ext];
            header('Content-Type: '.$mime);header('X-Content-Type-Options: nosniff');
            header("Content-Security-Policy: sandbox");header('Cache-Control: private, no-store');
            header('Content-Disposition: '.($mime==='application/octet-stream'?'attachment':'inline')."; filename*=UTF-8''".rawurlencode($node['n']));
            header('Content-Length: '.filesize($tmp));readfile($tmp);
        } catch (Throwable $e) {http_response_code(400);echo fm_enc($e->getMessage());}
        finally {if($tmp!==false)@unlink($tmp);}
        exit;
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '')==='POST') {
        try {
            if (!verifyToken($_POST['token'] ?? '')) throw new Exception(lng('Invalid security token'));
            $action=$_POST['rubbish_action'] ?? '';
            if(FM_READONLY)throw new Exception(lng('Read-only mode'));
            if(!in_array($action,['restore','delete','empty'],true))throw new Exception(lng('Invalid file'));
            $handles=$_POST['handles'] ?? [];
            if ($action==='empty') {
                if(FM_READONLY)throw new Exception(lng('Read-only mode'));
                MegaApi::invalidate();MegaApi::load();$handles=[];
                foreach(MegaApi::$nodes as $h=>$n)if(($n['p']??'')===MegaApi::$trash)$handles[]=$h;
                $action='delete';
            }
            if(!$handles&&($_POST['rubbish_action']??'')!=='empty')throw new Exception(lng('Invalid file'));
            $count=$handles?fm_mega_rubbish_mutate($action,$handles):0;
            fm_set_msg(fm_enc(lng($action==='restore'?'Items restored.':'Items permanently deleted.')).' ('.$count.')');
        } catch (Throwable $e) {fm_set_msg(fm_enc($e->getMessage()),'error');}
        fm_redirect(FM_SELF_URL.'?mega_rubbish=1&p='); return;
    }
    $items=[];$error='';$folder='';$detail=null;$preview='';$mime='application/octet-stream';
    try {
        MegaApi::invalidate();MegaApi::load();
        if (!MegaApi::$trash) throw new Exception(lng('MEGA Rubbish Bin is unavailable'));
        $folder=(string)($_GET['trash_folder'] ?? MegaApi::$trash);
        if ($folder!==MegaApi::$trash && (!fm_mega_in_rubbish($folder) || (int)MegaApi::$nodes[$folder]['t']!==1)) throw new Exception(lng('Invalid file'));
        if(isset($_GET['trash_detail'])) {
            $h=(string)$_GET['trash_detail'];
            if(!fm_mega_in_rubbish($h))throw new Exception(lng('Invalid file'));
            // Folders always browse their contents, including old detail URLs.
            if((int)MegaApi::$nodes[$h]['t']===1){
                fm_redirect(FM_SELF_URL.'?mega_rubbish=1&p=&trash_folder='.rawurlencode($h));
                return;
            }
            $detail=MegaApi::$nodes[$h];$folder=$detail['p'];
            $ext=strtolower(pathinfo($detail['n'],PATHINFO_EXTENSION));
            $types=['pdf'=>'application/pdf','html'=>'text/html','htm'=>'text/html','txt'=>'text/plain','json'=>'application/json','csv'=>'text/csv','md'=>'text/markdown','java'=>'text/x-java-source','php'=>'text/x-php','css'=>'text/css','js'=>'text/javascript','png'=>'image/png','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','gif'=>'image/gif','webp'=>'image/webp'];
            $types+=['tar'=>'application/x-tar','zip'=>'application/zip','docx'=>'application/vnd.openxmlformats-officedocument.wordprocessingml.document','xlsx'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','pptx'=>'application/vnd.openxmlformats-officedocument.presentationml.presentation','vsdx'=>'application/vnd.ms-visio.drawing'];
            $mime=$types[$ext]??'application/octet-stream';

        }
        foreach (MegaApi::$nodes as $node) if (($node['p'] ?? '')===$folder) $items[]=$node;
        usort($items,function($a,$b){return ((int)$b['t']<=>(int)$a['t']) ?: strnatcasecmp($a['n'],$b['n']);});
    } catch (Throwable $e) {$error=$e->getMessage();}
    $trashBytes=0;$trashFiles=0;$trashFolders=0;
    foreach($items as $entry){if((int)$entry['t']===1)$trashFolders++;else{$trashFiles++;$trashBytes+=(int)($entry['s']??0);}}
    fm_show_header();fm_show_rubbish_nav();fm_show_message(); ?>
    <?php
    $trashCrumbs=[];$crumbFolder=$folder;$crumbSeen=[];
    while($crumbFolder && $crumbFolder!==MegaApi::$trash && isset(MegaApi::$nodes[$crumbFolder]) && !isset($crumbSeen[$crumbFolder])) {
        $crumbSeen[$crumbFolder]=true;$crumbNode=MegaApi::$nodes[$crumbFolder];
        array_unshift($trashCrumbs,['name'=>$crumbNode['n'],'handle'=>$crumbFolder]);
        $crumbFolder=$crumbNode['p']??'';
    }
    $trashParent=$folder && $folder!==MegaApi::$trash ? (MegaApi::$nodes[$folder]['p']??MegaApi::$trash) : null;
    ?>
    <script>
    (function(){
      var folders=<?php echo json_encode($trashCrumbs,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT); ?>;
      var parent=<?php echo json_encode($trashParent,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT); ?>;
      document.querySelectorAll('.fm-path-links,.mega-mobile-crumb-links').forEach(function(el){
        var crumb=document.createElement('a');crumb.href='?mega_rubbish=1&p=';
        crumb.title=<?php echo json_encode(lng('Rubbish Bin'),JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT); ?>;
        crumb.innerHTML='<i class="fa fa-trash-o fm-rubbish-crumb-icon" aria-hidden="true"></i>';crumb.setAttribute('aria-label',crumb.title);
        var sep=document.createElement('span');sep.className=el.classList.contains('fm-path-links')?'bread-crumb':'mega-crumb-separator';sep.textContent='/';el.appendChild(sep);el.appendChild(crumb);
        folders.forEach(function(folder){
          var link=document.createElement('a');link.href='?mega_rubbish=1&p=&trash_folder='+encodeURIComponent(folder.handle);
          link.textContent=folder.name;link.title=folder.name;
          var sep=document.createElement('span');sep.className=el.classList.contains('fm-path-links')?'bread-crumb':'mega-crumb-separator';sep.textContent='/';el.appendChild(sep);el.appendChild(link);
        });
        if(parent){
          var up=document.createElement('a');up.href='?mega_rubbish=1&p=&trash_folder='+encodeURIComponent(parent);
          up.className=el.classList.contains('fm-path-links')?'mega-desktop-parent':'mega-mobile-parent';
          up.title=<?php echo json_encode(lng('Parent folder'),JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT); ?>;
          up.setAttribute('aria-label',up.title);up.innerHTML='<i class="fa fa-level-up" aria-hidden="true"></i>';
          el.appendChild(up);
        }
      });
    })();
    </script>
    <main class="fm-page-content container-fluid mega-search-page mega-trash-page" data-bs-theme="<?php echo FM_THEME; ?>">
      <div <?php if($detail): ?>hidden<?php endif; ?>>
      <?php if ($error): ?><div class="mega-inline-notice mega-inline-notice--error" role="alert"><?php echo fm_enc($error); ?></div><?php endif; ?>
      <?php if (!FM_READONLY): ?><div id="mega-trash-bulk-home"><div class="d-flex gap-2 mb-2" id="mega-trash-bulk-bar">
        <?php if($folder===MegaApi::$trash): ?><button type="button" class="btn btn-outline-primary" data-trash-bulk="restore" disabled><i class="fa fa-history"></i> <?php echo lng('Restore'); ?></button><?php endif; ?>
        <button type="button" class="btn btn-outline-danger mega-desktop-delete" data-trash-bulk="delete" disabled><i class="fa fa-trash-o"></i> <?php echo lng('Delete permanently'); ?></button>
        <button type="button" class="btn btn-outline-danger mega-desktop-delete" id="mega-trash-empty" <?php if(!$items&&$folder===MegaApi::$trash): ?>disabled<?php endif; ?>><i class="fa fa-trash-o"></i> <?php echo lng('Empty Rubbish Bin'); ?></button>
      </div></div><?php endif; ?>
      <div class="mega-view-controls mega-trash-sort">
        <?php if(!FM_READONLY): ?><button type="button" class="btn btn-sm btn-outline-secondary" id="mega-trash-select-toggle"><?php echo lng('SelectAll'); ?></button><?php endif; ?>
        <label for="mega-mobile-sort"><?php echo lng('Sort'); ?></label>
        <select id="mega-mobile-sort" class="form-select form-select-sm" aria-label="<?php echo fm_enc(lng('Sort')); ?>"><option value="name"><?php echo lng('Name'); ?></option><option value="size"><?php echo lng('Size'); ?></option><option value="date"><?php echo lng('Modified'); ?></option></select>
        <button type="button" id="mega-sort-custom-trigger" aria-haspopup="listbox" aria-expanded="false"><span id="mega-sort-custom-label"><?php echo lng('Name'); ?></span><span aria-hidden="true" class="mega-sort-chevron">⌄</span></button>
        <div id="mega-sort-custom-menu" role="listbox" aria-label="<?php echo fm_enc(lng('Sort')); ?>" hidden></div>
        <button type="button" id="mega-sort-direction" class="btn btn-sm btn-outline-secondary" aria-label="<?php echo fm_enc(lng('Sort')); ?>">↑</button>
      </div>
      <div class="table-responsive"><table class="table table-bordered table-hover table-sm align-middle" id="mega-trash-table"><thead><tr>
        <?php if (!FM_READONLY): ?><th class="mega-trash-selection"><input type="checkbox" id="mega-trash-all" aria-label="<?php echo fm_enc(lng('Select all')); ?>"></th><?php endif; ?>
        <th aria-sort="ascending"><button type="button" class="mega-trash-sort-header" data-trash-sort="name"><?php echo lng('Name'); ?> <span class="trash-sort-arrow">↑</span></button></th><th class="mega-trash-meta" aria-sort="none"><button type="button" class="mega-trash-sort-header" data-trash-sort="size"><?php echo lng('Size'); ?> <span class="trash-sort-arrow"></span></button></th><th class="mega-trash-meta" aria-sort="none"><button type="button" class="mega-trash-sort-header" data-trash-sort="date"><?php echo lng('Modified'); ?> <span class="trash-sort-arrow"></span></button></th><th><?php echo lng('Actions'); ?></th>
      </tr></thead><tbody>
      <?php foreach ($items as $node): $isFolder=(int)$node['t']===1; ?>
        <tr data-detail="?mega_rubbish=1&amp;<?php echo $isFolder?'trash_folder':'trash_detail'; ?>=<?php echo rawurlencode($node['h']); ?>&amp;p=" data-name="<?php echo fm_enc($node['n']); ?>" data-size="<?php echo (int)$node['s']; ?>" data-date="<?php echo (int)$node['ts']; ?>" data-kind="<?php echo $isFolder?1:0; ?>">
          <?php if (!FM_READONLY): ?><td><input type="checkbox" class="mega-trash-select" value="<?php echo fm_enc($node['h']); ?>" aria-label="<?php echo fm_enc($node['n']); ?>"></td><?php endif; ?>
          <td class="mega-trash-name"><div class="text-truncate" title="<?php echo fm_enc($node['n']); ?>"><i class="<?php echo fm_enc($isFolder ? 'fa fa-folder-o' : fm_get_file_icon_class($node['n'])); ?>" aria-hidden="true"></i>
          <?php if ($isFolder): ?><a href="?mega_rubbish=1&amp;trash_folder=<?php echo rawurlencode($node['h']); ?>&amp;p="><?php echo fm_enc($node['n']); ?></a><?php else: ?><a href="?mega_rubbish=1&amp;trash_detail=<?php echo rawurlencode($node['h']); ?>&amp;p="><?php echo fm_enc($node['n']); ?></a><?php endif; ?></div>
          <small class="mega-trash-mobile-meta text-secondary"><?php echo $isFolder?lng('Folder'):fm_enc(fm_get_filesize($node['s'])); ?> · <?php echo fm_enc(date(FM_DATETIME_FORMAT,$node['ts'])); ?></small></td>
          <td class="mega-trash-meta"><?php echo $isFolder?lng('Folder'):fm_enc(fm_get_filesize($node['s'])); ?></td><td class="mega-trash-meta"><?php echo fm_enc(date(FM_DATETIME_FORMAT,$node['ts'])); ?></td>
          <td><button type="button" class="btn btn-link mega-trash-more" aria-expanded="false" aria-label="<?php echo fm_enc(lng('Actions')); ?>"><i class="fa fa-ellipsis-v"></i></button><div class="mega-trash-row-actions">
            <div class="mega-menu-drag-handle" aria-hidden="true"></div>
            <?php if (!FM_READONLY): ?>
            <?php if(($node['p']??'')===MegaApi::$trash): ?><button type="button" class="btn btn-link p-1" data-trash-action="restore" data-handle="<?php echo fm_enc($node['h']); ?>" title="<?php echo fm_enc(lng('Restore')); ?>"><i class="fa fa-history"></i><span><?php echo lng('Restore'); ?></span></button><?php endif; ?>
            <button type="button" class="btn btn-link text-danger p-1" data-trash-action="delete" data-handle="<?php echo fm_enc($node['h']); ?>" title="<?php echo fm_enc(lng('Delete permanently')); ?>"><i class="fa fa-trash-o"></i><span><?php echo lng('Delete permanently'); ?></span></button>
          <?php endif; ?></div></td>
        </tr>
      <?php endforeach; ?>
      </tbody><tfoot><tr><td class="gray fs-7 mega-trash-summary" colspan="<?php echo FM_READONLY?4:5; ?>"><?php fm_file_list_summary($trashBytes,$trashFiles,$trashFolders); ?></td></tr></tfoot></table></div>
      <?php if (!$items && !$error): ?><p><?php echo lng('Rubbish Bin is empty.'); ?></p><?php endif; ?>

      </div>
      <?php if($detail): ?>
      <section class="card mb-3">
        <div class="card-header bg-primary text-white"><strong><?php echo lng((int)$detail['t']===1?'Folder':'File'); ?>:</strong><div><?php echo fm_enc($detail['n']); ?></div></div>
        <ul class="list-group list-group-flush">
          <li class="list-group-item"><strong><?php echo lng('Full Path'); ?>:</strong><div><?php
            $parts=[$detail['n']];$parent=$detail['p'];$seen=[];
            while(isset(MegaApi::$nodes[$parent])&&!isset($seen[$parent])){$seen[$parent]=true;array_unshift($parts,MegaApi::$nodes[$parent]['n']);$parent=MegaApi::$nodes[$parent]['p'];}
            echo fm_enc('mega://rubbish/'.implode('/',$parts));
          ?></div></li>
          <li class="list-group-item"><strong><?php echo lng('Modified'); ?>:</strong> <?php echo fm_enc(date(FM_DATETIME_FORMAT,$detail['ts'])); ?></li>
          <li class="list-group-item"><strong><?php echo lng('File size'); ?>:</strong> <?php echo (int)$detail['t']===1?lng('Folder'):fm_enc(fm_get_filesize($detail['s'])); ?></li>
          <li class="list-group-item"><strong><?php echo lng('MIME-type'); ?>:</strong> <?php echo fm_enc($mime); ?></li>
          <?php if($preview!==''): ?><li class="list-group-item"><strong><?php echo lng('Charset'); ?>:</strong> UTF-8</li><?php endif; ?>
        </ul>
      </section>
      <div class="fm-unified-actions mega-search-actions mega-trash-detail-actions mb-3">
        <a class="btn btn-outline-secondary fm-unified-button" href="?mega_rubbish=1&amp;trash_folder=<?php echo rawurlencode($folder); ?>&amp;p="><i class="fa fa-times"></i> <?php echo lng('Cancel'); ?></a>
        <?php if(!FM_READONLY): ?><button type="button" class="btn btn-outline-danger fm-unified-button" data-trash-action="delete" data-handle="<?php echo fm_enc($detail['h']); ?>"><i class="fa fa-trash-o"></i> <?php echo lng('Delete'); ?></button><?php if(($detail['p']??'')===MegaApi::$trash): ?><button type="button" class="btn btn-outline-primary fm-unified-button" data-trash-action="restore" data-handle="<?php echo fm_enc($detail['h']); ?>"><i class="fa fa-history"></i> <?php echo lng('Restore'); ?></button><?php endif; ?><?php endif; ?>
      </div>
      <?php if((int)$detail['t']===0)fm_rubbish_preview($detail); endif; ?>

    </main>
    <style>
    #mega-trash-table .mega-trash-name a,
    #mega-trash-table .mega-trash-name a:visited,
    #mega-trash-table .mega-trash-name a:hover,
    #mega-trash-table .mega-trash-name a:focus {
      color:var(--bs-body-color,#212529)!important;
      text-decoration:none;
    }
    #mega-trash-table{width:100%;table-layout:fixed}#mega-trash-table .mega-trash-selection{width:36px}#mega-trash-table th:last-child{width:145px}.mega-trash-mobile-meta{display:none}
    @media<?php echo fm_desktop_media_query(); ?>{
      .mega-trash-page{padding-left:0!important;padding-right:0!important}
      .mega-trash-page>h5{display:none}
      #mega-trash-bulk-home{display:none}
      .main-nav #mega-trash-bulk-bar{margin:0!important;gap:0!important}
      #mega-trash-table .mega-trash-selection{width:3%}
      #mega-trash-table th:has([data-trash-sort="name"]){width:28%}
      #mega-trash-table th:has([data-trash-sort="size"]){width:12%}
      #mega-trash-table th:has([data-trash-sort="date"]){width:28%}
      #mega-trash-table th:last-child{width:29%}
      #mega-trash-table td,#mega-trash-table th{padding:4px 6px;line-height:1.4;border-color:var(--bs-border-color,#e2e6e9)}
      #mega-trash-table [data-trash-sort]{display:block;position:relative;width:100%;padding:0 18px 0 0!important;text-align:left;text-decoration:none!important;font:inherit;font-weight:700;color:inherit!important;border:0}
      #mega-trash-table .trash-sort-arrow{font-size:0}
      #mega-trash-table .trash-sort-arrow::before,#mega-trash-table .trash-sort-arrow::after{position:absolute;right:0;font-size:10px;line-height:9px;opacity:.2}
      #mega-trash-table .trash-sort-arrow::before{content:'▲';top:1px}
      #mega-trash-table .trash-sort-arrow::after{content:'▼';bottom:1px}
      #mega-trash-table th[aria-sort="ascending"] .trash-sort-arrow::before,#mega-trash-table th[aria-sort="descending"] .trash-sort-arrow::after{opacity:.7}
      .mega-trash-row-actions{align-items:center;gap:8px}
      .mega-trash-row-actions>.btn{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;min-height:0;padding:2px!important;font-size:14px;line-height:18px;border:0;background:transparent}
    }
    .mega-trash-row-actions{display:flex;gap:4px}.mega-trash-row-actions span,.mega-trash-row-actions .mega-menu-drag-handle,.mega-trash-more{display:none}
    @media<?php echo fm_desktop_media_query(); ?>{.mega-trash-sort{display:none}}
    @media<?php echo fm_layout_media_query(); ?>{
      #mega-trash-table th:last-child{width:40px}.mega-trash-more{display:inline-flex}.mega-trash-row-actions{display:none}
      .mega-trash-row-actions.mega-open{display:flex;position:fixed;flex-direction:column;z-index:1040;background:var(--bs-body-bg,#fff);color:var(--bs-body-color,#212529);border:1px solid var(--bs-border-color,#ccc);border-radius:12px;box-shadow:0 8px 24px #0003;padding:6px;overflow:auto;max-width:calc(100vw - 24px)}
      .mega-trash-row-actions.mega-open span{display:inline}.mega-trash-row-actions.mega-open .mega-menu-drag-handle{display:flex}.mega-trash-row-actions .btn{text-align:left;display:flex;gap:10px;align-items:center;white-space:nowrap;padding:10px!important}
    }
    @media<?php echo fm_layout_media_query(); ?>{.mega-trash-meta{display:none}.mega-trash-mobile-meta{display:block}.mega-trash-name{width:auto}}

    #mega-trash-table th,#mega-trash-table td{padding:6px 8px;border-color:var(--bs-border-color,#eee);vertical-align:middle}
    #mega-trash-table th{font-weight:700;color:var(--bs-body-color,#212529)}
    .mega-trash-sort-header{display:flex;align-items:center;justify-content:space-between;width:100%;padding:0;border:0;background:none;color:inherit;font:inherit;text-align:left;cursor:pointer}
    .trash-sort-arrow{color:var(--bs-secondary-color,#aaa);font-size:12px}
    .mega-trash-row-actions .btn{font-size:14px;line-height:1;padding:3px 5px!important}
    @media<?php echo fm_desktop_media_query(); ?>{
      .mega-trash-page{padding:0!important}.mega-trash-heading{display:none}
      #mega-trash-table .mega-trash-selection{width:3%}#mega-trash-table th:nth-child(2){width:27%}#mega-trash-table th:nth-child(3){width:12%}#mega-trash-table th:nth-child(4){width:28%}#mega-trash-table th:last-child{width:30%}
      .mega-trash-bulk button{font-size:13px}.main-nav .mega-trash-bulk{margin:0!important;gap:0!important}
    }
    /* Mobile rubbish rows match the compact main-list layout. */
    @media<?php echo fm_layout_media_query(); ?>{
      .mega-trash-page{padding-left:0!important;padding-right:0!important}
      #mega-trash-bulk-home{display:none!important}
      #mega-mobile-menu #mega-trash-bulk-bar{display:flex!important;flex-direction:column;gap:0!important;margin:0!important;align-items:stretch}
      #mega-mobile-menu #mega-trash-bulk-bar button{display:flex;width:100%;align-items:center;gap:10px;padding:10px 12px!important;border:0!important;border-radius:0;background:transparent!important;color:inherit;font-size:inherit;text-align:left}
      #mega-mobile-menu #mega-trash-bulk-bar button:disabled{opacity:.45}
      #mega-trash-select-toggle{order:0;margin-right:auto;font-size:12px;padding:3px 4px}
      #mega-trash-select-toggle,
      #mega-trash-select-toggle:hover,
      #mega-trash-select-toggle:focus,
      #mega-trash-select-toggle:focus-visible,
      #mega-trash-select-toggle:active,
      #mega-trash-select-toggle.active {
        color:var(--bs-body-color,#212529)!important;
        background:transparent!important;border-color:transparent!important;box-shadow:none!important;
      }
      #mega-trash-table,#mega-trash-table tbody{display:block!important;width:100%!important;max-width:100%;border:0!important}
      #mega-trash-table thead{display:none!important}
      #mega-trash-table tbody tr{display:flex!important;align-items:center!important;gap:6px!important;min-height:53px!important;margin:0!important;padding:5px 4px!important;border:0!important;border-bottom:1px solid var(--bs-border-color,#e2e6e9)!important;border-radius:0!important;box-shadow:none!important;background:transparent!important;box-sizing:border-box}
      #mega-trash-table tbody td{display:block;border:0!important;padding:0!important;box-shadow:none!important;background:transparent!important;min-width:0}
      #mega-trash-table tbody td:first-child:has(.mega-trash-select){flex:0 0 30px;width:30px;text-align:center}
      #mega-trash-table .mega-trash-select{width:16px;height:16px;vertical-align:middle}
      #mega-trash-table .mega-trash-name{flex:1 1 0;width:0!important;font-size:14px;line-height:1.35}
      #mega-trash-table .mega-trash-name>div{display:flex;align-items:center;gap:6px;min-width:0}
      #mega-trash-table .mega-trash-name>div>i{flex:0 0 17px;width:17px;font-size:17px;text-align:center}
      #mega-trash-table .mega-trash-name a{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
      #mega-trash-table .mega-trash-mobile-meta{margin:3px 0 0 23px;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      #mega-trash-table tbody td.mega-trash-meta{display:none!important}
      #mega-trash-table tbody td:last-child{flex:0 0 30px;width:30px!important;text-align:center}
      #mega-trash-table .mega-trash-row-actions .btn,
      #mega-trash-table .mega-trash-row-actions .btn:hover,
      #mega-trash-table .mega-trash-row-actions .btn:focus,
      #mega-trash-table .mega-trash-row-actions .btn:active {
        padding:10px!important;font-size:15px;
        color:var(--bs-body-color,#212529)!important;
        text-decoration:none!important;
      }
      #mega-trash-table .mega-trash-row-actions .btn i,
      #mega-trash-table .mega-trash-row-actions .btn span {
        color:inherit!important;text-decoration:none!important;
      }
      #mega-trash-table .mega-trash-more{align-items:center;justify-content:center;width:30px;min-height:34px;padding:0!important;font-size:18px;color:var(--bs-body-color,#212529)}
      #mega-trash-table tbody tr.table-active{background:var(--bs-secondary-bg,rgba(127,127,127,.15))!important}
    }
    #mega-trash-table .mega-trash-summary{padding:6px 10px;line-height:1.5;border:0;color:var(--bs-body-color,#212529)}
    body.theme-dark #mega-trash-table tfoot .badge{color:#f1f5f9!important;background:#37414b!important;border-color:#596674!important}
    @media<?php echo fm_layout_media_query(); ?>{
      #mega-trash-table tfoot,#mega-trash-table tfoot tr,#mega-trash-table tfoot td{display:block!important;width:100%!important;box-sizing:border-box;border:0!important;background:transparent!important}
      html body #mega-trash-table tfoot .badge{color:var(--bs-body-color,#212529)!important;background:transparent!important}
    }
    .mega-trash-detail-actions{display:flex!important;justify-content:center;gap:10px;flex-wrap:wrap}
    .mega-trash-detail-actions>.btn{width:auto!important;min-width:100px!important}
    </style>
    <?php if (!FM_READONLY): ?>
    <div class="modal modal-alert confirmDialog" id="megaTrashConfirm" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false" aria-labelledby="mega-trash-question" data-bs-theme="<?php echo FM_THEME; ?>">
      <div class="modal-dialog"><form method="post" class="modal-content rounded-3 shadow">
        <input type="hidden" name="token" value="<?php echo fm_enc($_SESSION['token']); ?>"><input type="hidden" name="rubbish_action" id="mega-trash-action">
        <div id="mega-trash-handles"></div>
        <div class="modal-body p-4 text-center"><h5 id="mega-trash-question"></h5><p id="mega-trash-detail" class="fm-confirm-filename mb-1"></p></div>
        <div class="modal-footer flex-nowrap p-0"><button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal"><i class="fa fa-times"></i> <?php echo lng('Cancel'); ?></button><button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0"><i class="fa fa-check"></i> <strong><?php echo lng('Okay'); ?></strong></button></div>
      </form></div>
    </div>
    <?php endif; ?>
    <script>
    (function(){
      var table=document.getElementById('mega-trash-table'),all=document.getElementById('mega-trash-all');
      var bulk=document.getElementById('mega-trash-bulk-bar'),home=document.getElementById('mega-trash-bulk-home'),nav=document.querySelector('.main-nav');
      var desktop=window.matchMedia(<?php echo json_encode(fm_desktop_media_query()); ?>);
      function placeBulk(){
        if(!bulk||!home||!nav)return;
        bulk.classList.toggle('mega-desktop-bulk',desktop.matches);
        var remove=bulk.querySelector('[data-trash-bulk="delete"]');if(remove)remove.classList.toggle('mega-desktop-delete',desktop.matches);
        var menu=document.getElementById('mega-mobile-menu');var parent=desktop.matches?nav:(menu||home);if(bulk.parentNode!==parent){if(!desktop.matches&&menu)parent.insertBefore(bulk,parent.firstChild);else parent.appendChild(bulk);}
      }
      placeBulk();if(desktop.addEventListener)desktop.addEventListener('change',placeBulk);else desktop.addListener(placeBulk);
      function closeHeaderMenu(){var menu=document.getElementById('mega-mobile-menu'),trigger=document.querySelector('.mega-mobile-menu-trigger');if(menu)menu.hidden=true;if(trigger)trigger.setAttribute('aria-expanded','false');}
      var toggle=document.getElementById('mega-trash-select-toggle');if(toggle&&all)toggle.addEventListener('click',function(){all.checked=!all.checked;table.querySelectorAll('.mega-trash-select').forEach(function(c){c.checked=all.checked;});update();});
      function selected(){return Array.from(table.querySelectorAll('.mega-trash-select:checked'));}
      function update(){if(!all)return;table.querySelectorAll('.mega-trash-select').forEach(function(c){c.closest('tr').classList.toggle('table-active',c.checked);});var count=selected().length,total=table.querySelectorAll('.mega-trash-select').length;all.checked=total>0&&count===total;all.indeterminate=count>0&&count<total;document.querySelectorAll('[data-trash-bulk]').forEach(function(b){b.disabled=!count;});}
      if(all)all.addEventListener('change',function(){table.querySelectorAll('.mega-trash-select').forEach(function(c){c.checked=all.checked;});update();});table.addEventListener('change',update);
      function ask(action,handles){
        if(!handles.length&&action!=='empty')return;
        closeHeaderMenu();
        document.getElementById('mega-trash-action').value=action;
        var host=document.getElementById('mega-trash-handles');host.replaceChildren();
        handles.forEach(function(h){var field=document.createElement('input');field.type='hidden';field.name='handles[]';field.value=h;host.appendChild(field);});
        document.getElementById('mega-trash-question').textContent=action==='empty'?<?php echo json_encode(lng('Empty the entire Rubbish Bin? All items will be permanently deleted. This cannot be undone.')); ?>:action==='restore'?<?php echo json_encode(lng('Restore selected items? Missing original folders restore to Cloud Drive.')); ?>:<?php echo json_encode(lng('Permanently delete selected items? This cannot be undone.')); ?>;
        var names=handles.map(function(h){return Array.from(table.querySelectorAll('.mega-trash-select')).find(function(c){return c.value===h;}).getAttribute('aria-label');}).join(', ');
        var detail=document.getElementById('mega-trash-detail');detail.textContent=names;detail.title=names;
        window.megaDialogManager.show('megaTrashConfirm');
      }
      document.querySelectorAll('[data-trash-bulk]').forEach(function(b){b.addEventListener('click',function(){ask(b.dataset.trashBulk,selected().map(function(c){return c.value;}));});});
      document.addEventListener('click',function(e){var b=e.target.closest('[data-trash-action]');if(b){closeMenus();ask(b.dataset.trashAction,[b.dataset.handle]);}});
      table.addEventListener('dblclick',function(e){if(e.target.closest('button,input,.mega-trash-row-actions'))return;var row=e.target.closest('tr[data-detail]');if(row)location.href=row.dataset.detail;});
      var empty=document.getElementById('mega-trash-empty');if(empty)empty.addEventListener('click',function(){ask('empty',[]);});
      var sort=document.getElementById('mega-mobile-sort'),direction=document.getElementById('mega-sort-direction'),ascending=true;
      function order(){var key=sort.value;Array.from(table.tBodies[0].rows).sort(function(a,b){var group=Number(b.dataset.kind)-Number(a.dataset.kind);if(group)return group;var cmp=key==='name'?a.dataset.name.localeCompare(b.dataset.name,undefined,{numeric:true,sensitivity:'base'}):Number(a.dataset[key])-Number(b.dataset[key]);return ascending?cmp:-cmp;}).forEach(function(row){table.tBodies[0].appendChild(row);});direction.textContent=ascending?'↑':'↓';table.querySelectorAll('[data-trash-sort]').forEach(function(btn){var active=btn.dataset.trashSort===key;btn.parentNode.setAttribute('aria-sort',active?(ascending?'ascending':'descending'):'none');btn.querySelector('.trash-sort-arrow').textContent=active?direction.textContent:'↕';});}
      sort.addEventListener('change',order);direction.addEventListener('click',function(){ascending=!ascending;order();});
      table.querySelectorAll('[data-trash-sort]').forEach(function(btn){btn.addEventListener('click',function(){if(sort.value===btn.dataset.trashSort)ascending=!ascending;else{sort.value=btn.dataset.trashSort;ascending=true;}sort.dispatchEvent(new Event('change'));});});
      function closeMenus(){table.querySelectorAll('.mega-trash-row-actions.mega-open').forEach(function(menu){menu.classList.remove('mega-open');menu.previousElementSibling.setAttribute('aria-expanded','false');});}
      window.megaCloseRowMenus=closeMenus;
      table.addEventListener('click',function(e){
        var more=e.target.closest('.mega-trash-more');
        if(more){var menu=more.nextElementSibling,wasOpen=menu.classList.contains('mega-open');closeMenus();if(!wasOpen){menu.classList.add('mega-open');more.setAttribute('aria-expanded','true');var vv=window.visualViewport,left=vv?vv.offsetLeft:0,top=vv?vv.offsetTop:0,w=vv?vv.width:innerWidth,h=vv?vv.height:innerHeight;var header=document.querySelector('.mega-mobile-header');if(header)top=Math.max(top,header.getBoundingClientRect().bottom);menu.style.maxHeight=Math.max(40,h-(top-(vv?vv.offsetTop:0))-20)+'px';menu.style.top=(top+8)+'px';menu.style.left=(left+12)+'px';var r=more.getBoundingClientRect(),m=menu.getBoundingClientRect();menu.style.left=Math.max(left+12,Math.min(r.right-m.width,left+w-m.width-12))+'px';menu.style.top=Math.max(top+8,Math.min(r.bottom+4,(vv?vv.offsetTop:0)+h-m.height-12))+'px';}return;}
        if(e.target.closest('.mega-trash-row-actions a'))closeMenus();
      });
      document.addEventListener('click',function(e){if(!e.target.closest('.mega-trash-more,.mega-trash-row-actions'))closeMenus();});document.addEventListener('show.bs.modal',closeMenus);window.addEventListener('resize',closeMenus);window.addEventListener('scroll',closeMenus);document.addEventListener('keydown',function(e){if(e.key==='Escape')closeMenus();});

    })();
    </script>
    <?php fm_show_footer();
}

function fm_mega_link_page() {
    fm_share_require_mega();
    $folder = FM_PATH; $file = (string)($_GET['file'] ?? '');
    $error = ''; $link = ''; $notice = ''; $hasShare = false;
    if ($file === '' || $file === '.' || $file === '..' || basename($file) !== $file || strpos($file, "\0") !== false) {
        http_response_code(400); exit(lng('Invalid file'));
    }
    try {
        MegaApi::load();
        $handle = MegaApi::find(trim($folder . '/' . $file, '/'));
        if (!$handle || !isset(MegaApi::$nodes[$handle]) || (int)MegaApi::$nodes[$handle]['t'] !== 0) throw new Exception(html_entity_decode(lng('File not found'), ENT_QUOTES, 'UTF-8'));
        foreach (MegaApi::sharedLinks() as $shared) {
            if (($shared['node']['h'] ?? '') === $handle) { $hasShare = true; break; }
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (FM_READONLY) throw new Exception(html_entity_decode(lng('Read-only mode'), ENT_QUOTES, 'UTF-8'));
            if (!isset($_POST['token']) || !verifyToken($_POST['token'])) throw new Exception(html_entity_decode(lng('Invalid security token'), ENT_QUOTES, 'UTF-8'));
            $action = $_POST['share_action'] ?? 'create';
            if ($action === 'stop') {
                fm_mega_revoke_public_link($handle);
                $hasShare = false;
                $notice = lng('Sharing stopped.');
            } elseif ($action === 'create') {
                fm_share_signing_key(true);
                $link = fm_share_url(MegaApi::publicFileLink($handle));
                $hasShare = true;
                $notice = lng('Link created.');
            } else { throw new Exception(html_entity_decode(lng('Invalid file'), ENT_QUOTES, 'UTF-8')); }
        }
    } catch (Throwable $e) { $error = $e->getMessage(); }
    fm_show_header(); fm_show_nav_path($folder); ?>
    <main class="container-fluid fm-page-content mega-search-page"><section class="card mega-search-card fm-form-panel mb-4" data-bs-theme="<?php echo FM_THEME; ?>">
    <div class="card-header"><i class="fa fa-link fa-fw"></i> <?php echo lng('Create MEGA Link'); ?></div><div class="card-body">
      <p class="text-secondary"><?php echo lng('File'); ?>: <strong><?php echo fm_enc($file); ?></strong></p>
      <?php if ($error): ?><div class="mega-inline-notice mega-inline-notice--error" role="alert"><?php echo fm_enc($error); ?></div><?php endif; ?>
      <?php if ($notice): ?><div class="mega-inline-notice mega-inline-notice--success" role="status"><?php echo $notice; ?></div><?php endif; ?>
      <div class="mega-create-link-controls">
      <?php if ($link): ?><label for="mega-public-link" class="form-label"><?php echo lng('Public MEGA Link'); ?></label>
      <input class="form-control mb-3" id="mega-public-link" type="text" readonly value="<?php echo fm_enc($link); ?>">
      <div class="fm-unified-actions mega-search-actions mega-shared-link-actions"><button type="button" class="btn btn-outline-primary fm-unified-button" onclick="megaCopyPublicLink();"><i class="fa fa-copy"></i> <?php echo lng('Copy Link'); ?></button>
      <?php if (!FM_READONLY): ?><button type="button" class="btn btn-outline-danger fm-unified-button" <?php if (!$hasShare): ?>disabled aria-disabled="true"<?php endif; ?> data-handle="<?php echo fm_enc($handle ?? ''); ?>" data-name="<?php echo fm_enc($file); ?>" onclick="megaAskStopSharing(this.dataset.handle,this.dataset.name)"><i class="fa fa-unlink" aria-hidden="true"></i> <?php echo lng('Stop Sharing'); ?></button><?php endif; ?></div>
      <p class="text-secondary small mt-3"><?php echo lng('Anyone with this link can access the file. Share it carefully.'); ?></p><?php endif; ?>
      <form method="post" class="mt-3" data-mega-operation="share-create"><input type="hidden" name="share_action" value="create"><input type="hidden" name="token" value="<?php echo fm_enc($_SESSION['token'] ?? ''); ?>">
      <?php if (!$link): ?>
      <div class="fm-unified-actions mega-search-actions mega-shared-link-actions"><a class="btn btn-outline-secondary fm-unified-button" href="?p=<?php echo rawurlencode($folder); ?>"><i class="fa fa-times"></i> <?php echo lng('Cancel'); ?></a>
      <?php if (!FM_READONLY): ?><button type="submit" class="btn btn-primary fm-unified-button"><i class="fa fa-link"></i> <?php echo lng('Create Link'); ?></button><?php endif; ?></div>
      <?php else: ?>
      <div class="fm-unified-actions mega-search-actions mega-rubbish-close"><a class="btn btn-outline-secondary fm-unified-button" href="?p=<?php echo rawurlencode($folder); ?>"><i class="fa fa-times"></i> <?php echo lng('Cancel'); ?></a></div>
      <?php endif; ?>
</form></div>
    </div></section></main>
<?php fm_mega_share_dialogs(); fm_show_footer();
}

/** Shared revocation checks for the file page and account-wide list. */
function fm_mega_revoke_public_link($handle) {
    fm_share_require_mega();
    if (FM_READONLY) throw new Exception(html_entity_decode(lng('Read-only mode'), ENT_QUOTES, 'UTF-8'));
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !isset($_POST['token']) || !is_string($_POST['token']) || !verifyToken($_POST['token'])) {
        throw new Exception(html_entity_decode(lng('Invalid security token'), ENT_QUOTES, 'UTF-8'));
    }
    if (!is_string($handle) || !preg_match('/\A[A-Za-z0-9_-]{8}\z/', $handle) || !MegaApi::removePublicLink($handle)) {
        throw new Exception(html_entity_decode(lng('Unable to stop sharing.'), ENT_QUOTES, 'UTF-8'));
    }
}

function fm_mega_shared_links_page() {
    fm_share_require_mega();
    $items = []; $error = ''; $notice = '';
    try {
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
            if (($_POST['share_action'] ?? '') !== 'stop') throw new Exception(html_entity_decode(lng('Invalid file'), ENT_QUOTES, 'UTF-8'));
            fm_mega_revoke_public_link($_POST['share_handle'] ?? '');
            $notice = lng('Sharing stopped.');
        }
    } catch (Throwable $e) { $error = fm_enc($e->getMessage()); }
    try {
        $items = MegaApi::sharedLinks();
        foreach ($items as &$item) {
            $node = $item['node'];
            $raw = 'https://mega.nz/' . ((int)$node['t'] === 0 ? 'file/' : 'folder/') . $item['ph'] . '#' . MegaApi::b64e($node['key']);
            $item['url'] = (int)$node['t'] === 0 ? fm_share_url($raw) : $raw;
        }
        unset($item);
    } catch (Throwable $e) { $items = []; $error = lng('Unable to load shared links.'); }
    fm_show_header(); fm_show_nav_path(FM_PATH); ?>
    <main class="container-fluid fm-page-content mega-search-page"><section class="card mega-search-card fm-form-panel mb-4" data-bs-theme="<?php echo FM_THEME; ?>">
      <div class="card-header"><i class="fa fa-link fa-fw" aria-hidden="true"></i> <?php echo lng('Shared Links'); ?></div>
      <div class="card-body">
        <?php if ($error): ?><div class="mega-inline-notice mega-inline-notice--error" role="alert"><?php echo $error; ?></div><?php endif; ?>
        <?php if ($notice): ?><div class="mega-inline-notice mega-inline-notice--success" role="status"><?php echo $notice; ?></div><?php endif; ?>
        <?php if (!$items && !$error): ?><div class="mega-search-empty"><?php echo lng('No shared links.'); ?></div><?php endif; ?>
        <div class="mega-search-results">
        <?php foreach ($items as $i => $item): $node = $item['node']; ?>
          <article class="border rounded p-3" style="min-width:0">
            <div class="mb-2 text-break"><i class="fa <?php echo (int)$node['t'] === 0 ? 'fa-file-o' : 'fa-folder-o'; ?>" aria-hidden="true"></i> <?php echo fm_enc($node['n']); ?></div>
            <label class="visually-hidden" for="shared-link-<?php echo $i; ?>"><?php echo lng('Public MEGA Link'); ?></label>
            <input class="form-control mb-2" id="shared-link-<?php echo $i; ?>" readonly value="<?php echo fm_enc($item['url']); ?>">
            <div class="fm-unified-actions mega-search-actions mega-shared-link-actions">
              <button type="button" class="btn btn-outline-primary fm-unified-button" data-copy-id="shared-link-<?php echo $i; ?>" onclick="megaCopyPublicLink(this.dataset.copyId)"><i class="fa fa-copy" aria-hidden="true"></i> <?php echo lng('Copy Link'); ?></button>
              <?php if (!FM_READONLY): ?><button type="button" class="btn btn-outline-danger fm-unified-button" data-handle="<?php echo fm_enc($node['h']); ?>" data-name="<?php echo fm_enc($node['n']); ?>" onclick="megaAskStopSharing(this.dataset.handle,this.dataset.name)"><i class="fa fa-unlink" aria-hidden="true"></i> <?php echo lng('Stop Sharing'); ?></button><?php endif; ?>
            </div>
          </article>
        <?php endforeach; ?>
        </div>
        <div class="fm-unified-actions mega-search-actions mega-rubbish-close mt-3"><a class="btn btn-outline-secondary fm-unified-button" href="?p=<?php echo rawurlencode(FM_PATH); ?>"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Close'); ?></a></div>
      </div></section></main>
    <?php fm_mega_share_dialogs(); fm_show_footer();
}

/** One common Copy Link and Stop Sharing dialog for both pages. */
function fm_mega_share_dialogs() {
    if (!fm_mega_sharing_enabled()) return;
    ?>
    <?php if (!FM_READONLY): ?>
    <div class="modal modal-alert confirmDialog" id="megaStopSharingDialog" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" role="dialog" aria-labelledby="mega-stop-title" aria-describedby="mega-stop-message" data-bs-theme="<?php echo FM_THEME; ?>">
      <div class="modal-dialog"><form method="post" class="modal-content rounded-3 shadow">
        <input type="hidden" name="token" value="<?php echo fm_enc($_SESSION['token'] ?? ''); ?>">
        <input type="hidden" name="share_action" value="stop">
        <input type="hidden" name="share_handle" id="mega-stop-handle" value="">
        <div class="modal-body p-4 text-center"><h5 id="mega-stop-title" class="mb-2"><?php echo lng('Stop sharing this item? Existing links will stop working.'); ?></h5><p id="mega-stop-message" class="mb-1 fm-confirm-filename"><span id="mega-stop-name"></span></p></div>
        <div class="modal-footer flex-nowrap p-0">
          <button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal"><i class="fa fa-times" aria-hidden="true"></i> <?php echo lng('Cancel'); ?></button>
          <button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0"><i class="fa fa-check" aria-hidden="true"></i> <strong><?php echo lng('Okay'); ?></strong></button>
        </div>
      </form></div>
    </div>
    <?php endif; ?>
    <script>
    function megaAskStopSharing(handle, name) {
        var field = document.getElementById('mega-stop-handle');
        if (!field) return;
        field.value = handle;
        document.getElementById('mega-stop-name').textContent = name || '';
        document.getElementById('mega-stop-message').title = name || '';
        window.megaDialogManager.show('megaStopSharingDialog');
    }
    </script>
    <script>
    var megaCopySourceId = 'mega-public-link';
    function megaCopyPublicLink(id) {
        megaCopySourceId = id || 'mega-public-link';
        var input = document.getElementById(megaCopySourceId);
        if (!input) return;
        var messages = <?php echo json_encode(array_map(function($text) { return html_entity_decode(lng($text), ENT_QUOTES, 'UTF-8'); }, array('Link copied', 'Unable to copy automatically. Select and copy the link manually.')), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        function result(ok) {
            if (!ok) { input.focus(); input.select(); }
            var notice = document.getElementById('mega-copy-result');
            if (!notice) {
                notice = document.createElement('div');
                notice.id = 'mega-copy-result';
            }
            if (window.megaPlaceResult) window.megaPlaceResult(notice);
            else document.getElementById('wrapper').prepend(notice);
            notice.className = 'mega-inline-notice mega-inline-notice--' + (ok ? 'success' : 'error');
            notice.setAttribute('role', ok ? 'status' : 'alert');
            notice.setAttribute('aria-live', ok ? 'polite' : 'assertive');
            notice.textContent = messages[ok ? 0 : 1];
            notice.hidden = false;
            notice.style.display = 'block';
            if (window.megaNoticeSchedule) window.megaNoticeSchedule(notice);
        }
        function fallback() {
            input.focus(); input.select();
            var copied = false;
            try { copied = document.execCommand('copy'); } catch (e) {}
            result(copied);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(input.value).then(function() { result(true); }, fallback);
        } else { fallback(); }
    }
    </script>

<?php }

/** Shared read-only renderer used by the live-file and Rubbish Bin details pages. */
function fm_render_readonly_preview($context) {
    extract($context, EXTR_SKIP);
    ?>
            <div class="row mt-3 mega-preview-content">
                <?php
                if ($ext === 'pdf' && strpos($path, 'mega://') === 0) {
                    ?>
                    <div id="mega-pdf-viewer" style="width:100%;max-width:100%;border:1px solid #dce2e8;border-radius:12px;overflow:hidden;background:#f3f5f8">
                        <div style="display:flex;gap:8px;align-items:center;justify-content:center;flex-wrap:wrap;padding:12px;background:#fff;border-bottom:1px solid #dce2e8">
                            <button type="button" class="btn btn-outline-secondary" id="mega-pdf-prev" aria-label="<?php echo fm_enc(lng('Previous page')); ?>">&#8592;</button>
                            <span id="mega-pdf-counter" aria-live="polite"><?php echo lng('Loading PDF...'); ?></span>
                            <button type="button" class="btn btn-outline-secondary" id="mega-pdf-next" aria-label="<?php echo fm_enc(lng('Next page')); ?>">&#8594;</button>
                            <button type="button" class="btn btn-outline-secondary" id="mega-pdf-zoomout" aria-label="<?php echo fm_enc(lng('Zoom out')); ?>">&#8722;</button>
                            <button type="button" class="btn btn-outline-secondary" id="mega-pdf-zoomin" aria-label="<?php echo fm_enc(lng('Zoom in')); ?>">+</button>
                        </div>
                        <div id="mega-pdf-status" role="status" style="padding:12px;text-align:center"><?php echo lng('Loading PDF...'); ?></div>
                        <div id="mega-pdf-pages" style="overflow:auto;text-align:center;padding:12px;max-height:78vh"></div>
                    </div>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
                    <script>
                    (function () {
                        "use strict";
                        var pdfUrl = <?php echo json_encode($file_url, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
                        var status = document.getElementById('mega-pdf-status');
                        var pages = document.getElementById('mega-pdf-pages');
                        var counter = document.getElementById('mega-pdf-counter');
                        var previous = document.getElementById('mega-pdf-prev');
                        var next = document.getElementById('mega-pdf-next');
                        var zoomIn = document.getElementById('mega-pdf-zoomin');
                        var zoomOut = document.getElementById('mega-pdf-zoomout');
                        var documentPdf = null, currentPage = 1, zoom = 1, busy = false, generation = 0;
                        function fail(message) { status.style.display = 'block'; status.textContent = message; counter.textContent = <?php echo json_encode(lng('PDF unavailable')); ?>; }
                        function update() {
                            counter.textContent = currentPage + ' / ' + documentPdf.numPages;
                            previous.disabled = busy || currentPage <= 1;
                            next.disabled = busy || currentPage >= documentPdf.numPages;
                        }
                        async function render() {
                            if (!documentPdf) return;
                            var id = ++generation;
                            busy = true; update();
                            try {
                                var page = await documentPdf.getPage(currentPage);
                                if (id !== generation) return;
                                var base = page.getViewport({scale:1});
                                var width = Math.max(200, pages.clientWidth - 24);
                                var scale = Math.min(width / base.width, 2.5) * zoom;
                                var viewport = page.getViewport({scale:scale});
                                var ratio = Math.min(window.devicePixelRatio || 1, 2);
                                var canvas = document.createElement('canvas');
                                canvas.width = Math.ceil(viewport.width * ratio);
                                canvas.height = Math.ceil(viewport.height * ratio);
                                canvas.style.width = viewport.width + 'px';
                                canvas.style.height = viewport.height + 'px';
                                canvas.style.maxWidth = 'none';
                                var ctx = canvas.getContext('2d');
                                await page.render({canvasContext:ctx, viewport:viewport, transform:ratio === 1 ? null : [ratio,0,0,ratio,0,0]}).promise;
                                if (id !== generation) return;
                                pages.replaceChildren(canvas);
                                status.style.display = 'none';
                            } catch (e) { fail('Could not render PDF: ' + e.message); }
                            finally { busy = false; update(); }
                        }
                        previous.addEventListener('click', function () { if (!busy && currentPage > 1) { currentPage--; render(); } });
                        next.addEventListener('click', function () { if (!busy && documentPdf && currentPage < documentPdf.numPages) { currentPage++; render(); } });
                        zoomIn.addEventListener('click', function () { if (!busy) { zoom = Math.min(zoom * 1.25, 4); render(); } });
                        zoomOut.addEventListener('click', function () { if (!busy) { zoom = Math.max(zoom / 1.25, .5); render(); } });
                        async function start() {
                            if (!window.pdfjsLib) { fail('PDF.js could not load. Check your internet connection or CDN access.'); return; }
                            pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
                            try {
                                var response = await fetch(pdfUrl, {credentials:'same-origin', cache:'no-store', redirect:'error'});
                                if (!response.ok) throw new Error('PDF request failed (HTTP ' + response.status + '). Check your MEGA session.');
                                var bytes = new Uint8Array(await response.arrayBuffer());
                                if (bytes.length < 5 || String.fromCharCode.apply(null, bytes.subarray(0,5)) !== '%PDF-') throw new Error('Server did not return a PDF. Please sign in again if your session expired.');
                                documentPdf = await pdfjsLib.getDocument({data:bytes}).promise;
                                render();
                            } catch (e) { fail(e.message || 'Unable to load PDF'); }
                        }
                        start();
                    })();
                    </script>
                    <?php
                } elseif (in_array($ext, array('doc', 'ppt'), true) && strpos($path, 'mega://') === 0) {
                    $legacy = mega_legacy_office_preview($file_path, $ext, $filesize_raw);
                    ?>
                    <section class="mega-legacy-preview" style="border:1px solid #596674;border-radius:10px;overflow:hidden">
                      <div style="padding:10px 14px;background:#293138;color:#f1f5f9;font-weight:600">
                        <?php echo strtoupper($ext); ?> — Legacy Office preview
                      </div>
                      <?php if ($legacy[0]): ?>
                        <div style="padding:10px 14px;font-size:12px">Read-only text preview. Original layout, images and animations are not shown.</div>
                        <pre style="padding:14px;margin:0;max-height:75vh;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere"><?php echo htmlspecialchars($legacy[1], ENT_QUOTES, 'UTF-8'); ?></pre>
                      <?php else: ?>
                        <div role="alert" style="padding:16px"><?php echo htmlspecialchars($legacy[1], ENT_QUOTES, 'UTF-8'); ?></div>
                      <?php endif; ?>
                    </section>
                    <style>
                      body.theme-dark .mega-legacy-preview {background:#1d252c;color:#f1f5f9}
                      body.theme-dark .mega-legacy-preview pre {background:#1d252c;color:#f1f5f9}
                    </style>
                    <?php
                } elseif ($ext === 'pptx' && strpos($path, 'mega://') === 0) {
                    ?>
                    <div id="mega-pptx-viewer" style="width:100%;border:1px solid #dce2e8;border-radius:12px;overflow:hidden;background:#fff">
                        <div style="display:flex;gap:8px;align-items:center;justify-content:center;flex-wrap:wrap;padding:12px;background:#f8fafc">
                            <button type="button" id="pptx-prev" class="btn btn-outline-secondary" aria-label="<?php echo lng('Previous slide') ?>">&#8249;</button>
                            <span id="pptx-count" aria-live="polite"> <?php echo lng('Loading...') ?></span>
                            <button type="button" id="pptx-next" class="btn btn-outline-secondary" aria-label="<?php echo lng('Next slide') ?>">&#8250;</button>
                            <button type="button" id="pptx-minus" class="btn btn-outline-secondary" aria-label="<?php echo fm_enc(lng('Zoom out')); ?>">&minus;</button>
                            <span id="pptx-zoom-label">100%</span>
                            <button type="button" id="pptx-plus" class="btn btn-outline-secondary" aria-label="<?php echo fm_enc(lng('Zoom in')); ?>">+</button>
                            <button type="button" id="pptx-reset" class="btn btn-outline-secondary"><i class="fa fa-refresh" aria-hidden="true"></i> <?php echo lng('Reset'); ?></button>
                        </div>
                        <div id="pptx-status" role="status" style="padding:12px;text-align:center"><?php echo lng('Loading PowerPoint...'); ?></div>
                        <div style="overflow:auto;max-height:78vh;background:#edf1f5;padding:16px">
                            <div id="pptx-slide" style="box-sizing:border-box;transform-origin:top left;background:white;border:1px solid #cbd5e1;box-shadow:0 2px 12px #0002;padding:5%;min-height:240px;width:100%;overflow-wrap:anywhere"></div>
                        </div>
                        <p style="margin:0;padding:12px;font-size:13px;color:#64748b;background:#fff">Basic PPTX slide text preview. Images, charts, layouts, animations and embedded objects may not appear. Download the original for accurate formatting.</p>
                    </div>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
                    <script>
                    (function(){
                        'use strict';
                        var url=<?php echo json_encode($file_url, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
                        var slides=[],current=0,scale=1;
                        var el=function(id){return document.getElementById(id);};
                        var box=el('pptx-slide'),status=el('pptx-status');
                        function draw(){
                            if(!slides.length)return;
                            var slide=slides[current];
                            box.replaceChildren();
                            var title=document.createElement('h3');
                            title.textContent='Slide '+(current+1);
                            title.style.cssText='font-size:16px;color:#64748b;margin-bottom:20px';
                            box.appendChild(title);
                            slide.forEach(function(line){
                                var para=document.createElement('p');
                                para.textContent=line;
                                para.style.cssText='font-size:18px;line-height:1.5;margin:0 0 12px;white-space:pre-wrap';
                                box.appendChild(para);
                            });
                            if(!slide.length){var empty=document.createElement('p');empty.textContent='No extractable slide text';box.appendChild(empty);}
                            box.style.zoom=String(scale);
                            el('pptx-count').textContent=(current+1)+' / '+slides.length;
                            el('pptx-zoom-label').textContent=Math.round(scale*100)+'%';
                            el('pptx-prev').disabled=current===0;
                            el('pptx-next').disabled=current===slides.length-1;
                        }
                        el('pptx-prev').onclick=function(){if(current>0){current--;draw();}};
                        el('pptx-next').onclick=function(){if(current+1<slides.length){current++;draw();}};
                        el('pptx-minus').onclick=function(){scale=Math.max(.5,Math.round((scale-.1)*10)/10);draw();};
                        el('pptx-plus').onclick=function(){scale=Math.min(2,Math.round((scale+.1)*10)/10);draw();};
                        el('pptx-reset').onclick=function(){scale=1;draw();};
                        (async function(){
                            try{
                                if(!window.JSZip)throw new Error('PPTX library unavailable');
                                var response=await fetch(url,{credentials:'same-origin',cache:'no-store',redirect:'error'});
                                if(!response.ok)throw new Error('MEGA request failed (HTTP '+response.status+')');
                                var buffer=await response.arrayBuffer();
                                if(buffer.byteLength>64*1024*1024)throw new Error('PPTX exceeds the 64 MiB preview limit');
                                var zip=await JSZip.loadAsync(buffer);
                                var names=Object.keys(zip.files).filter(function(name){return /^ppt\/slides\/slide[0-9]+\.xml$/.test(name);});
                                names.sort(function(a,b){return Number(a.match(/slide(\d+)/)[1])-Number(b.match(/slide(\d+)/)[1]);});
                                if(!names.length)throw new Error('No PowerPoint slides found');
                                if(names.length>500)throw new Error('Too many slides to preview');
                                for(var i=0;i<names.length;i++){
                                    var xml=await zip.file(names[i]).async('string');
                                    var doc=new DOMParser().parseFromString(xml,'application/xml');
                                    if(doc.getElementsByTagName('parsererror').length)throw new Error('Invalid slide XML');
                                    var paras=Array.from(doc.getElementsByTagNameNS('http://schemas.openxmlformats.org/drawingml/2006/main','p'));
                                    var lines=paras.map(function(para){return Array.from(para.getElementsByTagNameNS('http://schemas.openxmlformats.org/drawingml/2006/main','t')).map(function(n){return n.textContent;}).join('');}).filter(Boolean);
                                    slides.push(lines);
                                }
                                status.style.display='none';draw();
                            }catch(e){status.textContent='Could not preview PPTX: '+(e.message||e);}
                        })();
                    })();
                    </script>
                    <?php
                } elseif ($ext === 'docx' && strpos($path, 'mega://') === 0) {
                    ?>
                    <style id="mega-docx-selected-theme">
                    /* The DOCX viewer inherits the same theme class as the file manager.
                       Limit these rules to the preview; the DOCX itself is never modified. */
                    body.theme-dark #mega-docx-viewer,
                    html[data-bs-theme="dark"] #mega-docx-viewer {
                        background:#242b31 !important;
                        color:#f1f5f9 !important;
                        border-color:#475569 !important;
                    }
                    body.theme-dark #mega-docx-toolbar,
                    html[data-bs-theme="dark"] #mega-docx-toolbar {
                        background:#303a44 !important;
                        color:#f1f5f9 !important;
                        border-color:#475569 !important;
                    }
                    body.theme-dark #mega-docx-toolbar .btn,
                    html[data-bs-theme="dark"] #mega-docx-toolbar .btn {
                        color:#f1f5f9 !important;
                        border-color:#718096 !important;
                        background:#303a44 !important;
                    }
                    body.theme-dark #mega-docx-toolbar .btn:hover,
                    html[data-bs-theme="dark"] #mega-docx-toolbar .btn:hover {
                        background:#455362 !important;
                    }
                    body.theme-dark #mega-docx-pages,
                    html[data-bs-theme="dark"] #mega-docx-pages,
                    body.theme-dark #mega-docx-document .docx-wrapper,
                    html[data-bs-theme="dark"] #mega-docx-document .docx-wrapper {
                        background:#1b2229 !important;
                    }
                    body.theme-dark #mega-docx-document .docx-wrapper > section.docx,
                    html[data-bs-theme="dark"] #mega-docx-document .docx-wrapper > section.docx {
                        /* Invert page luminance while largely retaining text/ink contrast.
                           This also alters colors of embedded images, as with PDF dark mode. */
                        filter:invert(.88) hue-rotate(180deg);
                        box-shadow:0 2px 14px rgba(0,0,0,.55) !important;
                    }
                    body.theme-dark #mega-docx-status,
                    html[data-bs-theme="dark"] #mega-docx-status {
                        color:#e2e8f0 !important;
                        background:#242b31 !important;
                    }
                    </style>
                    <div id="mega-docx-viewer" style="width:100%;max-width:100%;border:1px solid #dce2e8;border-radius:12px;background:#fff;overflow:hidden">
                        <div id="mega-docx-toolbar" style="display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;padding:12px;border-bottom:1px solid #dce2e8">
                            <button type="button" id="mega-docx-zoom-out" class="btn btn-outline-secondary" aria-label="<?php echo fm_enc(lng('Zoom out')); ?>">&minus;</button>
                            <span id="mega-docx-zoom-label" style="min-width:54px;text-align:center;font-weight:600" aria-live="polite">100%</span>
                            <button type="button" id="mega-docx-zoom-in" class="btn btn-outline-secondary" aria-label="<?php echo fm_enc(lng('Zoom in')); ?>">+</button>
                            <button type="button" id="mega-docx-zoom-reset" class="btn btn-outline-secondary"><i class="fa fa-refresh" aria-hidden="true"></i> <?php echo lng('Reset'); ?></button>
                        </div>
                        <div id="mega-docx-status" role="status" style="padding:14px;text-align:center"><?php echo lng('Loading DOCX...'); ?></div>
                        <div id="mega-docx-pages" style="overflow:auto;max-height:80vh;padding:12px;background:#f1f3f6">
                            <div id="mega-docx-document" style="display:flow-root;width:max-content;min-width:100%;transform-origin:top left"></div>
                        </div>
                    </div>
                    <script src="https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/docx-preview@0.3.6/dist/docx-preview.min.js"></script>
                    <script>
                    (async function () {
                        'use strict';
                        var status = document.getElementById('mega-docx-status');
                        var target = document.getElementById('mega-docx-document');
                        var zoomLabel = document.getElementById('mega-docx-zoom-label');
                        var zoomOut = document.getElementById('mega-docx-zoom-out');
                        var zoomIn = document.getElementById('mega-docx-zoom-in');
                        var zoomReset = document.getElementById('mega-docx-zoom-reset');
                        var zoom = 100;
                        function setZoom(value) {
                            zoom = Math.max(50, Math.min(200, value));
                            // CSS zoom changes layout dimensions, so scrolling stays correct.
                            target.style.zoom = (zoom / 100).toString();
                            zoomLabel.textContent = zoom + '%';
                            zoomOut.disabled = zoom <= 50;
                            zoomIn.disabled = zoom >= 200;
                        }
                        zoomOut.addEventListener('click', function () { setZoom(zoom - 10); });
                        zoomIn.addEventListener('click', function () { setZoom(zoom + 10); });
                        zoomReset.addEventListener('click', function () { setZoom(100); });
                        setZoom(100);
                        var url = <?php echo json_encode($file_url, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
                        try {
                            if (!window.docx || typeof window.docx.renderAsync !== 'function') throw new Error('DOCX renderer could not load. Check CDN access.');
                            var response = await fetch(url, {credentials:'same-origin',cache:'no-store',redirect:'error'});
                            if (!response.ok) throw new Error('DOCX request failed (HTTP ' + response.status + '). Check your MEGA session.');
                            var bytes = await response.arrayBuffer();
                            var signature = new Uint8Array(bytes, 0, Math.min(bytes.byteLength, 4));
                            if (signature.length < 4 || signature[0] !== 80 || signature[1] !== 75 || signature[2] !== 3 || signature[3] !== 4) throw new Error('The server did not return DOCX data.');
                            await window.docx.renderAsync(bytes, target, null, {inWrapper:true,breakPages:true,ignoreWidth:false,ignoreHeight:false});
                            status.style.display = 'none';
                        } catch (error) {
                            status.textContent = 'Could not preview DOCX: ' + (error.message || error);
                        }
                    })();
                    </script>
                    <?php
                } elseif (in_array($ext, array('xls', 'xlsx', 'xlsm'), true) && strpos($path, 'mega://') === 0) {
                    ?>
                    <div id="mega-excel-viewer" style="width:100%;max-width:100%;border:1px solid #dce2e8;border-radius:12px;overflow:hidden;background:white">
                      <div style="display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap;padding:10px;background:#f8fafc;border-bottom:1px solid #dce2e8">
                        <label for="mega-excel-sheet" style="font-weight:600;margin:0"><?php echo lng('Sheet'); ?></label>
                        <select id="mega-excel-sheet" class="form-select" aria-label="<?php echo lng('Sheet'); ?>" style="min-width:110px;max-width:45%;width:auto"></select>
                        <button type="button" class="btn btn-outline-secondary" id="mega-excel-minus" aria-label="<?php echo fm_enc(lng('Zoom out')); ?>">&minus;</button>
                        <span id="mega-excel-percent" style="min-width:48px;text-align:center;font-weight:600">100%</span>
                        <button type="button" class="btn btn-outline-secondary" id="mega-excel-plus" aria-label="<?php echo fm_enc(lng('Zoom in')); ?>">+</button>
                        <button type="button" class="btn btn-outline-secondary" id="mega-excel-reset"><i class="fa fa-refresh" aria-hidden="true"></i> <?php echo lng('Reset'); ?></button>
                      </div>
                      <div id="mega-excel-status" role="status" style="padding:12px;text-align:center"><?php echo lng('Loading spreadsheet...'); ?></div>
                      <div id="mega-excel-scroll" style="overflow:auto;max-height:75vh;background:#fff">
                        <div id="mega-excel-grid" style="width:max-content;min-width:100%;transform-origin:top left"></div>
                      </div>
                      <div style="padding:7px 12px;font-size:12px;color:#64748b;background:#f8fafc">Read-only Excel preview. VBA macros are never executed. Advanced Excel formatting, charts and pivot tables may not display.</div>
                    </div>
                    <style>
                      #mega-excel-grid table{border-collapse:separate;border-spacing:0;font-size:13px;table-layout:auto;width:max-content;min-width:100%}
                      #mega-excel-grid td,#mega-excel-grid th{border-right:1px solid #dfe5ed;border-bottom:1px solid #dfe5ed;padding:5px 9px;min-width:75px;max-width:400px;white-space:pre-wrap;overflow-wrap:anywhere;vertical-align:middle;color:#172033}
                      #mega-excel-grid thead th{position:sticky;top:0;z-index:2;background:#e9eef5;text-align:center;color:#475569;font-weight:600}
                      #mega-excel-grid tbody th{position:sticky;left:0;z-index:1;background:#f1f5f9;text-align:center;color:#64748b;font-weight:500;min-width:44px}
                      #mega-excel-grid thead th:first-child{position:sticky;left:0;z-index:3;min-width:44px}
                      /* Excel grid colors must override the light-only base table rules.
                         The workbook renderer does not currently import cell styling. */
                      body.theme-dark #mega-excel-viewer #mega-excel-grid table,
                      body.theme-dark #mega-excel-viewer #mega-excel-grid tbody,
                      body.theme-dark #mega-excel-viewer #mega-excel-grid tr {
                        background:#1f2831!important;
                        color:#f1f5f9!important;
                      }
                      body.theme-dark #mega-excel-viewer #mega-excel-grid td {
                        background:#1f2831!important;
                        color:#f1f5f9!important;
                        border-right:1px solid #4a5866!important;
                        border-bottom:1px solid #4a5866!important;
                      }
                      body.theme-dark #mega-excel-viewer #mega-excel-grid thead th {
                        background:#34414d!important;
                        color:#f1f5f9!important;
                        border-color:#596674!important;
                      }
                      body.theme-dark #mega-excel-viewer #mega-excel-grid tbody th {
                        background:#2b3742!important;
                        color:#dbe5ef!important;
                        border-color:#596674!important;
                      }
                      body.theme-dark #mega-excel-viewer #mega-excel-grid td a {
                        color:#b9d8ff!important;
                      }

                    </style>
                    <script src="https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js"></script>
                    <script>
                    (async function(){
                      'use strict';
                      var byId=function(id){return document.getElementById(id);};
                      var select=byId('mega-excel-sheet'),grid=byId('mega-excel-grid'),status=byId('mega-excel-status');
                      var zoom=100,workbook=null;
                      function colName(n){var out='';for(n++;n>0;n=Math.floor((n-1)/26))out=String.fromCharCode(65+(n-1)%26)+out;return out;}
                      function setZoom(value){zoom=Math.max(50,Math.min(200,value));grid.style.zoom=String(zoom/100);byId('mega-excel-percent').textContent=zoom+'%';byId('mega-excel-minus').disabled=zoom<=50;byId('mega-excel-plus').disabled=zoom>=200;}
                      byId('mega-excel-minus').onclick=function(){setZoom(zoom-10);};
                      byId('mega-excel-plus').onclick=function(){setZoom(zoom+10);};
                      byId('mega-excel-reset').onclick=function(){setZoom(100);};
                      function render(){
                        var ws=workbook.Sheets[select.value],range=ws['!ref']?XLSX.utils.decode_range(ws['!ref']):{s:{r:0,c:0},e:{r:0,c:0}};
                        var rows=range.e.r-range.s.r+1,cols=range.e.c-range.s.c+1;
                        if(rows>10000||cols>250||rows*cols>300000)throw new Error('This worksheet is too large for an in-browser table preview ('+rows+' rows × '+cols+' columns).');
                        var table=document.createElement('table'),head=document.createElement('thead'),hrow=document.createElement('tr');
                        hrow.appendChild(document.createElement('th'));
                        for(var c=range.s.c;c<=range.e.c;c++){var th=document.createElement('th');th.textContent=colName(c);hrow.appendChild(th);}head.appendChild(hrow);table.appendChild(head);
                        var body=document.createElement('tbody'),merges=ws['!merges']||[],covered=Object.create(null),starts=Object.create(null);
                        merges.forEach(function(m){if(m.s.r<range.s.r||m.s.c<range.s.c||m.e.r>range.e.r||m.e.c>range.e.c)return;starts[m.s.r+':'+m.s.c]=m;for(var r=m.s.r;r<=m.e.r;r++)for(var c=m.s.c;c<=m.e.c;c++)if(r!==m.s.r||c!==m.s.c)covered[r+':'+c]=true;});
                        for(var r=range.s.r;r<=range.e.r;r++){
                          var tr=document.createElement('tr'),rowHead=document.createElement('th');rowHead.textContent=r+1;tr.appendChild(rowHead);
                          for(var c=range.s.c;c<=range.e.c;c++){
                            var key=r+':'+c;if(covered[key])continue;
                            var td=document.createElement('td'),merge=starts[key];if(merge){td.rowSpan=merge.e.r-merge.s.r+1;td.colSpan=merge.e.c-merge.s.c+1;}
                            var cell=ws[XLSX.utils.encode_cell({r:r,c:c})];
                            if(cell){td.textContent=cell.w!=null?String(cell.w):(cell.v==null?'':String(cell.v));if(cell.f)td.title='Formula: ='+cell.f;}
                            tr.appendChild(td);
                          }
                          body.appendChild(tr);
                        }
                        table.appendChild(body);grid.replaceChildren(table);
                      }
                      select.onchange=function(){try{render();}catch(e){status.style.display='block';status.textContent=e.message||String(e);grid.replaceChildren();}};
                      setZoom(100);
                      try{
                        if(!window.XLSX)throw new Error('SheetJS renderer could not load. Check CDN access.');
                        var response=await fetch(<?php echo json_encode($file_url, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>,{credentials:'same-origin',cache:'no-store',redirect:'error'});
                        if(!response.ok)throw new Error('Excel request failed (HTTP '+response.status+'). Check your MEGA session.');
                        var bytes=new Uint8Array(await response.arrayBuffer());
                        var isZip=bytes.length>=4&&bytes[0]===80&&bytes[1]===75&&bytes[2]===3&&bytes[3]===4;
                        var isOle=bytes.length>=8&&bytes[0]===208&&bytes[1]===207&&bytes[2]===17&&bytes[3]===224&&bytes[4]===161&&bytes[5]===177&&bytes[6]===26&&bytes[7]===225;
                        if(!isZip&&!isOle)throw new Error('Server did not return a supported Excel file (.xls/.xlsx/.xlsm).');
                        workbook=XLSX.read(bytes,{type:'array',cellText:true,cellDates:true,cellStyles:false,bookVBA:false});
                        if(!workbook.SheetNames.length)throw new Error('No worksheets found.');
                        workbook.SheetNames.forEach(function(name){var opt=document.createElement('option');opt.value=name;opt.textContent=name;select.appendChild(opt);});
                        render();status.style.display='none';
                      }catch(e){status.style.display='block';status.textContent='Could not preview Excel: '+(e.message||e);}
                    })();
                    </script>
                    <?php
                } elseif ($ext === 'vsdx' && strpos($path, 'mega://') === 0) {
                    ?>
                    <div id="mega-vsdx-viewer" style="width:100%;max-width:100%;border:1px solid #dce2e8;border-radius:12px;overflow:hidden">
                      <div style="display:flex;gap:8px;align-items:center;justify-content:center;flex-wrap:wrap;padding:10px;background:#f8fafc;border-bottom:1px solid #dce2e8">
                        <button type="button" class="btn btn-outline-secondary" id="mega-vsdx-prev" aria-label="<?php echo fm_enc(lng('Previous page')); ?>">&#8249;</button>
                        <select id="mega-vsdx-page" aria-label="<?php echo lng('Visio page') ?>" class="form-select" style="width:auto;max-width:45%;min-width:110px"></select>
                        <button type="button" class="btn btn-outline-secondary" id="mega-vsdx-next" aria-label="<?php echo fm_enc(lng('Next page')); ?>">&#8250;</button>
                        <button type="button" class="btn btn-outline-secondary" id="mega-vsdx-minus" aria-label="<?php echo fm_enc(lng('Zoom out')); ?>">&minus;</button>
                        <span id="mega-vsdx-percent" style="min-width:48px;text-align:center">100%</span>
                        <button type="button" class="btn btn-outline-secondary" id="mega-vsdx-plus" aria-label="<?php echo fm_enc(lng('Zoom in')); ?>">+</button>
                        <button type="button" class="btn btn-outline-secondary" id="mega-vsdx-fit"><i class="fa fa-arrows-alt" aria-hidden="true"></i> <?php echo lng('Fit') ?></button>
                      </div>
                      <div id="mega-vsdx-status" role="status" style="padding:12px;text-align:center"><?php echo lng('Loading Visio diagram...'); ?></div>
                      <div id="mega-vsdx-scroll" style="max-height:80vh;overflow:auto;background:#e9edf2;padding:12px">
                        <div id="mega-vsdx-sheet" style="width:max-content;margin:auto"></div>
                      </div>
                      <div style="padding:7px 12px;font-size:12px;color:#64748b;background:#f8fafc">Basic Visio preview: complex master shapes, OLE objects and advanced formatting may differ from Microsoft Visio.</div>
                    </div>
                    <script src="https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js"></script>
                    <script>
                    (async function () {
                      'use strict';
                      var url = <?php echo json_encode($file_url, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
                      var $ = function (id) { return document.getElementById(id); };
                      var status=$('mega-vsdx-status'), select=$('mega-vsdx-page'), sheet=$('mega-vsdx-sheet'), scroll=$('mega-vsdx-scroll');
                      var pages=[], archive, scale=1, baseWidth=800, baseHeight=1100, active=0;
                      var NS='http://www.w3.org/2000/svg';
                      function children(node, name) { return Array.from(node ? node.children : []).filter(function(n){return n.localName===name;}); }
                      function child(node,name) { return children(node,name)[0] || null; }
                      function cell(node,name,def) { var c=children(node,'Cell').find(function(x){return x.getAttribute('N')===name;}); var v=c ? c.getAttribute('V') : null; return v===null ? def : v; }
                      function num(node,name,def) { var v=parseFloat(cell(node,name,def)); return isFinite(v)?v:def; }
                      function parse(xml) { var doc=new DOMParser().parseFromString(xml,'application/xml'); if(doc.getElementsByTagName('parsererror').length) throw new Error('Invalid Visio XML'); return doc.documentElement; }
                      function svgEl(name,attrs,parent) { var n=document.createElementNS(NS,name); Object.keys(attrs||{}).forEach(function(k){n.setAttribute(k,attrs[k]);}); if(parent)parent.appendChild(n); return n; }
                      function textOf(shape) { var t=child(shape,'Text'); return t ? (t.textContent||'').replace(/\s+/g,' ').trim() : ''; }
                      function drawShape(shape,group,ph,depth) {
                        if(depth>8)return;
                        var w=num(shape,'Width',0), h=num(shape,'Height',0), pinX=num(shape,'PinX',0), pinY=num(shape,'PinY',0);
                        var locX=num(shape,'LocPinX',w/2),locY=num(shape,'LocPinY',h/2),angle=num(shape,'Angle',0);
                        var x=(pinX-locX)*96, y=(ph-pinY-(h-locY))*96, sw=w*96, sh=h*96;
                        if(sw<0 || sh<0)return;
                        var g=svgEl('g',{},group);
                        if(angle)g.setAttribute('transform','rotate('+(-angle*180/Math.PI)+' '+(pinX*96)+' '+((ph-pinY)*96)+')');
                        var fill=cell(shape,'FillForegnd','#ffffff'),stroke=cell(shape,'LineColor','#555555');
                        if(!/^#[0-9a-f]{3,8}$/i.test(fill))fill='#ffffff';
                        if(!/^#[0-9a-f]{3,8}$/i.test(stroke))stroke='#555555';
                        if(cell(shape,'FillPattern','1')==='0')fill='none';
                        if(cell(shape,'LinePattern','1')==='0')stroke='none';
                        var geos=children(shape,'Section').filter(function(n){return n.getAttribute('N')==='Geometry';});
                        var drew=false;
                        geos.forEach(function(geo){
                          var d='',cx=0,cy=0;
                          children(geo,'Row').forEach(function(row){
                            var type=row.getAttribute('T')||'', vx=num(row,'X',0),vy=num(row,'Y',0);
                            var rel=type.indexOf('Rel')===0,px=x+(rel?vx*w:vx)*96,py=y+sh-(rel?vy*h:vy)*96;
                            if(type==='MoveTo'||type==='RelMoveTo'){d+='M'+px+','+py+' ';cx=px;cy=py;}
                            else if(type==='LineTo'||type==='RelLineTo'){d+='L'+px+','+py+' ';cx=px;cy=py;}
                            else if(type==='Ellipse'){svgEl('ellipse',{cx:x+sw/2,cy:y+sh/2,rx:sw/2,ry:sh/2,fill:fill,stroke:stroke},g);drew=true;}
                          });
                          if(d){svgEl('path',{d:d,fill:fill,stroke:stroke,'stroke-width':Math.max(.5,num(shape,'LineWeight',.01)*96),'stroke-linejoin':'round'},g);drew=true;}
                        });
                        if(!drew && w>0 && h>0 && !children(shape,'Shapes').length)svgEl('rect',{x:x,y:y,width:sw,height:sh,fill:fill,stroke:stroke,'stroke-width':.8},g);
                        var label=textOf(shape);
                        if(label && w>0 && h>0){
                          var fontSize=Math.max(8,Math.min(18,sh/Math.max(1,Math.ceil(label.length/24))*0.65));
                          var t=svgEl('text',{x:x+sw/2,y:y+sh/2,'text-anchor':'middle','dominant-baseline':'middle','font-family':'Arial,sans-serif','font-size':fontSize,fill:'#1f2937'},g);
                          var lines=label.match(/.{1,38}(?:\s|$)|.{1,38}/g)||[label];
                          lines.slice(0,12).forEach(function(line,i){var sp=svgEl('tspan',{x:x+sw/2,dy:i===0?(-((Math.min(lines.length,12)-1)*fontSize*.55)):fontSize*1.1},t);sp.textContent=line.trim();});
                        }
                        var nested=child(shape,'Shapes'); children(nested,'Shape').forEach(function(s){drawShape(s,g,ph,depth+1);});
                      }
                      function updateZoom(){
                        var svg=sheet.querySelector('svg');if(!svg)return;
                        svg.style.width=Math.round(baseWidth*scale)+'px';svg.style.height=Math.round(baseHeight*scale)+'px';
                        $('mega-vsdx-percent').textContent=Math.round(scale*100)+'%';
                        $('mega-vsdx-minus').disabled=scale<=.5;$('mega-vsdx-plus').disabled=scale>=2;
                      }
                      async function render(index){
                        active=index;var page=pages[index];if(!page)return;
                        status.style.display='block';status.textContent='Rendering page '+(index+1)+'...';
                        try{
                          var xml=await archive.file(page.file).async('string'),root=parse(xml);
                          var pw=page.width||8.5,ph=page.height||11;
                          baseWidth=Math.round(pw*96);baseHeight=Math.round(ph*96);
                          var svg=svgEl('svg',{xmlns:NS,viewBox:'0 0 '+baseWidth+' '+baseHeight,width:baseWidth,height:baseHeight,role:'img','aria-label':page.name},null);
                          svg.style.background='#ffffff';svg.style.boxShadow='0 2px 8px #0002';
                          children(child(root,'Shapes'),'Shape').forEach(function(shape){drawShape(shape,svg,ph,0);});
                          sheet.replaceChildren(svg);select.value=String(index);
                          $('mega-vsdx-prev').disabled=index===0;$('mega-vsdx-next').disabled=index===pages.length-1;
                          updateZoom();status.style.display='none';scroll.scrollTop=0;scroll.scrollLeft=0;
                        }catch(e){status.textContent='Could not render page: '+(e.message||e);}
                      }
                      $('mega-vsdx-prev').onclick=function(){if(active>0)render(active-1);};
                      $('mega-vsdx-next').onclick=function(){if(active<pages.length-1)render(active+1);};
                      select.onchange=function(){render(Number(select.value));};
                      $('mega-vsdx-minus').onclick=function(){scale=Math.max(.5,Math.round((scale-.1)*10)/10);updateZoom();};
                      $('mega-vsdx-plus').onclick=function(){scale=Math.min(2,Math.round((scale+.1)*10)/10);updateZoom();};
                      $('mega-vsdx-fit').onclick=function(){scale=Math.min(2,Math.max(.5,(scroll.clientWidth-28)/baseWidth));updateZoom();};
                      try{
                        if(!window.JSZip)throw new Error('ZIP renderer failed to load. Check CDN access.');
                        var response=await fetch(url,{credentials:'same-origin',cache:'no-store',redirect:'error'});
                        if(!response.ok)throw new Error('MEGA request failed (HTTP '+response.status+').');
                        var data=await response.arrayBuffer(),sig=new Uint8Array(data,0,Math.min(4,data.byteLength));
                        if(sig.length<4||sig[0]!==80||sig[1]!==75||sig[2]!==3||sig[3]!==4)throw new Error('Server did not return a VSDX file.');
                        archive=await JSZip.loadAsync(data);
                        if(!archive.file('visio/pages/pages.xml'))throw new Error('Not a supported Visio VSDX package.');
                        var manifest=parse(await archive.file('visio/pages/pages.xml').async('string'));
                        var rels=parse(await archive.file('visio/pages/_rels/pages.xml.rels').async('string'));
                        var targets={};children(rels,'Relationship').forEach(function(r){targets[r.getAttribute('Id')]=r.getAttribute('Target');});
                        children(manifest,'Page').forEach(function(p){
                          var rel=child(p,'Rel'),rid=rel&&(rel.getAttribute('r:id')||rel.getAttributeNS('http://schemas.openxmlformats.org/officeDocument/2006/relationships','id'));
                          var target=targets[rid]||'',file='visio/pages/'+target.replace(/^\.\.\//,'').replace(/^\//,'');
                          if(!archive.file(file))return;
                          var ps=child(p,'PageSheet');pages.push({file:file,name:p.getAttribute('Name')||('Page '+(pages.length+1)),width:num(ps,'PageWidth',8.5),height:num(ps,'PageHeight',11)});
                        });
                        if(!pages.length)throw new Error('No Visio pages found.');
                        pages.forEach(function(p,i){var o=document.createElement('option');o.value=i;o.textContent=(i+1)+' / '+pages.length+' — '+p.name;select.appendChild(o);});
                        await render(0);
                      }catch(e){status.style.display='block';status.textContent='Could not preview VSDX: '+(e.message||e);}
                    })();
                    </script>
                    <?php
                } elseif ($is_onlineViewer) {
                    if ($online_viewer == 'google') {
                        echo '<iframe src="https://docs.google.com/viewer?embedded=true&hl=en&url=' . fm_enc($file_url) . '" frameborder="no" style="width:100%;min-height:460px"></iframe>';
                    } else if ($online_viewer == 'microsoft') {
                        echo '<iframe src="https://view.officeapps.live.com/op/embed.aspx?src=' . fm_enc($file_url) . '" frameborder="no" style="width:100%;min-height:460px"></iframe>';
                    }
                } elseif ($is_zip) {
                    // ZIP content
                    if ($filenames !== false) {
                        echo '<code class="maxheight">';
                        foreach ($filenames as $fn) {
                            if ($fn['folder']) {
                                echo '<b>' . fm_enc($fn['name']) . '</b><br>';
                            } else {
                                echo fm_enc($fn['name']) . ' (' . fm_get_filesize($fn['filesize']) . ')<br>';
                            }
                        }
                        echo '</code>';
                    } else {
                        echo '<p>' . lng('Error while fetching archive info') . '</p>';
                    }
                } elseif ($is_image) {
                    // Image content
                    if (in_array($ext, array('gif', 'jpg', 'jpeg', 'png', 'bmp', 'ico', 'svg', 'webp', 'avif'))) {
                        echo '<p><input type="checkbox" id="preview-img-zoomCheck"><label for="preview-img-zoomCheck"><img src="' . fm_enc($file_url) . '" alt="image" class="preview-img"></label></p>';
                    }
                } elseif ($is_audio) {
                    // Audio content
                    echo '<p><audio src="' . fm_enc($file_url) . '" controls preload="metadata"></audio></p>';
                } elseif ($is_video) {
                    // Video content
                    echo '<div class="preview-video"><video src="' . fm_enc($file_url) . '" width="640" height="360" controls preload="metadata"></video></div>';
                } elseif ($is_text) {
                    if (FM_USE_HIGHLIGHTJS) {
                        // highlight
                        $hljs_classes = array(
                            'shtml' => 'xml',
                            'htaccess' => 'apache',
                            'phtml' => 'php',
                            'lock' => 'json',
                            'svg' => 'xml',
                        );
                        $hljs_class = isset($hljs_classes[$ext]) ? 'lang-' . $hljs_classes[$ext] : 'lang-' . $ext;
                        if (empty($ext) || in_array(strtolower($file), fm_get_text_names()) || preg_match('#\.min\.(css|js)$#i', $file)) {
                            $hljs_class = 'nohighlight';
                        }
                        $content = '<pre class="with-hljs"><code class="' . $hljs_class . '">' . fm_enc($content) . '</code></pre>';
                    } elseif (in_array($ext, array('php', 'php4', 'php5', 'phtml', 'phps'))) {
                        // php highlight
                        $content = highlight_string($content, true);
                    } else {
                        $content = '<pre>' . fm_enc($content) . '</pre>';
                    }
                    echo $content;
                }
                ?>
            </div>

<?php }
