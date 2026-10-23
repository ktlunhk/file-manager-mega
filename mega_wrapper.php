<?php
/**
 * mega_wrapper.php - pure-PHP MEGA client exposed as a mega:// stream wrapper for Tiny File Manager.
 * Needs PHP 7.1+ with: curl and openssl. No shell access / extra software required.
 * Everything is end-to-end decrypted/encrypted inside PHP, like MEGA's own web client.
 */

class MegaApi
{
    public static $master, $sid, $uid, $root, $trash;
    public static $nodes = [], $kids = [], $publicLinks = [];
    private static $loaded = false;
    /** Batch mode: writes do not wipe the metadata cache; new nodes are registered locally. */
    public static $batch = false;

    /* ---------- crypto helpers ---------- */

    static function b64e($s) { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
    static function b64d($s)
    {
        $s = strtr($s, '-_,', '+/ ');
        $s = trim($s);
        return base64_decode($s . str_repeat('=', (4 - strlen($s) % 4) % 4));
    }
    static function ecbE($d, $k) { return openssl_encrypt($d, 'aes-128-ecb', $k, 3); }
    static function ecbD($d, $k) { return openssl_decrypt($d, 'aes-128-ecb', $k, 3); }
    static function cbcE($d, $k, $iv = null) { return openssl_encrypt($d, 'aes-128-cbc', $k, 3, $iv ?: str_repeat("\0", 16)); }
    static function cbcD($d, $k) { return openssl_decrypt($d, 'aes-128-cbc', $k, 3, str_repeat("\0", 16)); }
    static function ctr($d, $k, $nonce, $off)
    {
        return openssl_encrypt($d, 'aes-128-ctr', $k, OPENSSL_RAW_DATA, $nonce . pack('J', $off >> 4));
    }

    /* ---------- RSA session id (pure PHP, see MegaBig) ---------- */

    static function mpi(&$s)
    {
        $bits = unpack('n', substr($s, 0, 2))[1];
        $len = intdiv($bits + 7, 8);
        $d = substr($s, 2, $len);
        $s = substr($s, 2 + $len);
        return $d;
    }

    /* ---------- HTTP / API ---------- */

    static function api($req, $sid = null)
    {
        static $id = 0;
        if (!$id) $id = mt_rand(1, 0x7FFFFFF);
        for ($try = 0, $maxTries = in_array(($req['a'] ?? ''), ['us0', 'us'], true) ? 1 : 5; $try < $maxTries; $try++) {
            $ch = curl_init('https://g.api.mega.co.nz/cs?id=' . (++$id) . ($sid ? '&sid=' . $sid : ''));
            curl_setopt_array($ch, [CURLOPT_POST => 1, CURLOPT_POSTFIELDS => json_encode([$req]),
                CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_RETURNTRANSFER => 1,
                CURLOPT_TIMEOUT => 60]);
            $r = curl_exec($ch);
            curl_close($ch);
            $j = json_decode((string)$r, true);
            $res = is_array($j) ? $j[0] : (is_int($j) ? $j : -3);
            if ($res === -3) { usleep(250000 * (1 << $try)); continue; }   // EAGAIN
            return $res;
        }
        return -3;
    }

    static function post($url, $body)
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_POST => 1, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_TIMEOUT => 110, CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_HTTPHEADER => ['Content-Type:']]);
        $r = curl_exec($ch);
        curl_close($ch);
        return $r === false ? '-3' : trim($r);
    }

    /* ---------- login ---------- */

    static function prepKeyV1($pw)
    {
        $pkey = pack('N*', 0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56);
        $keys = [];
        for ($i = 0; $i < strlen($pw); $i += 16) $keys[] = str_pad(substr($pw, $i, 16), 16, "\0");
        for ($r = 0; $r < 65536; $r++) foreach ($keys as $k) $pkey = self::ecbE($pkey, $k);
        return $pkey;
    }

    static function stringHash($email, $pk)
    {
        $h = str_repeat("\0", 16);
        for ($i = 0, $l = strlen($email); $i < $l; $i++) $h[$i % 16] = chr(ord($h[$i % 16]) ^ ord($email[$i]));
        for ($r = 0; $r < 16384; $r++) $h = self::ecbE($h, $pk);
        return self::b64e(substr($h, 0, 4) . substr($h, 8, 4));
    }

    /** Keep OTPs as strings: leading zeroes are significant. */
    static function normalizeMfa($mfa)
    {
        if (!is_string($mfa)) throw new InvalidArgumentException('Invalid two-factor code');
        $mfa = preg_replace('/[\s\x{00a0}\x{202f}]+/u', '', $mfa);
        if ($mfa === null || ($mfa !== '' && !preg_match('/\A[0-9]{6}\z/', $mfa))) {
            throw new InvalidArgumentException('Invalid two-factor code');
        }
        return $mfa;
    }

    /** Returns ['sid'=>..., 'master'=>binary]. Throws Exception with a readable message. */
    static function login($email, $pw, $mfa = '')
    {
        $mfa = self::normalizeMfa($mfa);
        $email = strtolower(trim($email));
        $r = self::api(['a' => 'us0', 'user' => $email]);
        if (!is_array($r) || !isset($r['v']) || !in_array((int)$r['v'], [1, 2], true)) {
            throw new Exception('MEGA authentication version lookup failed; login was not attempted');
        }
        $v = (int)$r['v'];
        if ($v === 2 && (empty($r['s']) || self::b64d($r['s']) === '')) throw new Exception('Invalid MEGA authentication salt');
        if ($v == 2) {
            $d = hash_pbkdf2('sha512', $pw, self::b64d($r['s']), 100000, 32, true);
            $pk = substr($d, 0, 16);
            $uh = self::b64e(substr($d, 16, 16));
        } else {
            $pk = self::prepKeyV1($pw);
            $uh = self::stringHash($email, $pk);
        }
        $req = ['a' => 'us', 'user' => $email, 'uh' => $uh];
        if ($mfa !== '') $req['mfa'] = $mfa;
        $r = self::api($req);
        if (is_int($r)) {
            if ($r === -26) throw new Exception($mfa === '' ? 'Two-factor code required' : 'Invalid two-factor code', $r);
            if ($r === -5 && $mfa !== '') throw new Exception('Invalid two-factor code', $r);
            throw new Exception($r === -9 || $r === -2 ? 'Wrong email or password' : 'MEGA error ' . $r);
        }
        $master = self::ecbD(self::b64d($r['k']), $pk);
        if (!empty($r['csid']) && !empty($r['privk'])) {
            $priv = self::ecbD(self::b64d($r['privk']), $master);
            $p = self::mpi($priv); $q = self::mpi($priv); $d = self::mpi($priv); $u = self::mpi($priv);
            $csid = self::b64d($r['csid']);
            $c = self::mpi($csid);
            $sid = self::b64e(substr(MegaBig::rsaDecrypt($c, $p, $q, $d, $u), 0, 43));
        } elseif (!empty($r['tsid'])) {
            $sid = $r['tsid'];
        } else {
            throw new Exception('Unexpected login response');
        }
        return ['sid' => $sid, 'master' => $master];
    }

    /* ---------- node tree ---------- */

    static function cacheFile() { return sys_get_temp_dir() . '/megafm_' . md5(self::$sid) . '.cache'; }

    static function invalidate()
    {
        @unlink(self::cacheFile());
        clearstatcache(true);
        // Invalidate destination picker listings after any successful MEGA write.
        if (isset($_SESSION) && is_array($_SESSION)) {
            unset($_SESSION['mega_folder_picker_cache']);
            $_SESSION['mega_folder_cache_revision'] = bin2hex(random_bytes(8));
        }
        self::$loaded = false;
    }

    /** Throws Exception (code -15 = session expired). */
    static function load()
    {
        if (self::$loaded) return;
        $cf = self::cacheFile();
        $ttl = 60; // Metadata cache TTL; writes still invalidate immediately.
        $d = (is_file($cf) && time() - filemtime($cf) < $ttl) ? json_decode((string)@file_get_contents($cf), true) : false;
        if (!is_array($d) || !isset($d['root'], $d['nodes'], $d['trash'], $d['public_links']) || !is_array($d['nodes']) || !is_array($d['public_links'])) $d = false;
        if (!is_array($d)) {
            $r = self::api(['a' => 'f', 'c' => 1, 'r' => 1], self::$sid);
            if (!is_array($r) || !isset($r['f'])) throw new Exception('Could not load MEGA file list', is_int($r) ? $r : 0);
            $d = self::parse($r['f']);
            $d['public_links'] = isset($r['ph']) && is_array($r['ph']) ? $r['ph'] : array();
            // Atomic cache publication prevents readers seeing partial JSON.
            $tmpCache = $cf . '.' . bin2hex(random_bytes(5));
            if (@file_put_contents($tmpCache, json_encode($d), LOCK_EX) !== false) {
                @chmod($tmpCache, 0600);
                if (!@rename($tmpCache, $cf)) @unlink($tmpCache);
            }
        }
        self::$root = $d['root'];
        self::$trash = $d['trash'] ?? null;
        self::$nodes = $d['nodes'];
        self::$publicLinks = $d['public_links'];
        self::$kids = [];
        foreach (self::$nodes as $h => $n) if ($h !== self::$root) self::$kids[$n['p']][$n['n']] = $h;
        self::$loaded = true;
    }

    static function parse($list)
    {
        $root = null;
        foreach ($list as $n) if ((int)$n['t'] === 2) { $root = $n['h']; self::$uid = $n['u']; }
        if ($root === null) throw new Exception('MEGA root not found');
        self::$trash = null;
        foreach ($list as $n) if ((int)$n['t'] === 4) self::$trash = $n['h'];
        $nodes = [$root => ['h' => $root, 'p' => '', 'n' => 'root', 't' => 2, 's' => 0, 'ts' => time()]];
        foreach ($list as $n) {
            $t = (int)$n['t'];
            if (($t !== 0 && $t !== 1) || empty($n['k']) || empty($n['a'])) continue;
            $ks = null;
            foreach (explode('/', $n['k']) as $part) {          // "owner:key/owner2:key2"
                $pp = explode(':', $part, 2);
                if (count($pp) === 2 && $pp[0] === self::$uid) { $ks = $pp[1]; break; }
            }
            if ($ks === null) continue;
            $kb = self::b64d($ks);
            if (strlen($kb) !== 16 && strlen($kb) !== 32) continue;
            $key = self::ecbD($kb, self::$master);
            if ($t === 0 && strlen($key) === 32) { $aes = substr($key, 0, 16) ^ substr($key, 16, 16); $nonce = substr($key, 16, 8); }
            elseif ($t === 1 && strlen($key) === 16) { $aes = $key; $nonce = ''; }
            else continue;
            $a = self::cbcD(self::b64d($n['a']), $aes);
            if ($a === false || substr($a, 0, 4) !== 'MEGA') continue;
            $j = json_decode(rtrim(substr($a, 4), "\0"), true);
            if (!is_array($j) || !isset($j['n'])) continue;
            $nodes[$n['h']] = ['h' => $n['h'], 'p' => $n['p'], 'n' => str_replace('/', '_', (string)$j['n']), 't' => $t,
                's' => (int)($n['s'] ?? 0), 'ts' => (int)($n['ts'] ?? time()), 'key' => $key, 'aes' => $aes, 'nonce' => $nonce, 'rr' => (string)($j['rr'] ?? $n['rr'] ?? ''), 'attrs' => $j];
        }
        return ['root' => $root, 'trash' => self::$trash, 'nodes' => $nodes];
    }

    /** Create or retrieve a public link for a file, using MEGA's export API. */
    static function publicFileLink($handle)
    {
        self::load();
        $node = self::$nodes[$handle] ?? null;
        if (!$node || (int)$node['t'] !== 0 || strlen($node['key'] ?? '') !== 32) {
            throw new Exception('File not found or encryption key unavailable');
        }
        $r = self::api(['a' => 'l', 'n' => $handle], self::$sid);
        if (!is_string($r) || $r === '') throw new Exception('MEGA link creation failed (API error ' . (is_int($r) ? $r : 'unknown') . ')');
        return 'https://mega.nz/file/' . rawurlencode($r) . '#' . self::b64e($node['key']);
    }

    /** Read the account's existing exports; never creates a link. */
    static function sharedLinks()
    {
        self::invalidate(); self::load();
        $items = [];
        foreach (self::$publicLinks as $link) {
            if (!is_array($link) || !isset($link['h'], $link['ph']) || !is_string($link['h']) || !preg_match('/\A[A-Za-z0-9_-]{8}\z/', $link['h']) || !is_string($link['ph']) || !preg_match('/\A[A-Za-z0-9_-]{8}\z/', $link['ph'])) continue;
            $node = self::$nodes[$link['h']] ?? null;
            if (!$node || !in_array((int)$node['t'], [0, 1], true) || strlen($node['key'] ?? '') !== ((int)$node['t'] === 0 ? 32 : 16)) continue;
            $items[$link['h']] = ['node' => $node, 'ph' => $link['ph']];
        }
        $items = array_values($items);
        usort($items, function($a, $b) { return strcasecmp($a['node']['n'], $b['node']['n']); });
        return $items;
    }

    /** Remove the public export, never the file/folder itself. */
    static function removePublicLink($handle)
    {
        self::load();
        $node = self::$nodes[$handle] ?? null;
        if (!$node || !in_array((int)$node['t'], [0, 1], true)) return false;
        $result = self::api(['a' => 'l', 'n' => $handle, 'd' => 1], self::$sid);
        if ($result !== 0) return false;
        self::invalidate();
        return true;
    }

    static function find($rem)
    {
        $h = self::$root;
        if ($rem === '') return $h;
        foreach (explode('/', $rem) as $s) {
            if (!isset(self::$kids[$h][$s])) return null;
            $h = self::$kids[$h][$s];
        }
        return $h;
    }

    /* ---------- operations ---------- */

    static function attr($name, $aes)
    {
        $j = 'MEGA' . json_encode(['n' => $name], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (strlen($j) % 16) $j .= str_repeat("\0", 16 - strlen($j) % 16);
        return self::b64e(self::cbcE($j, $aes));
    }

    // MEGA returns numeric 0 for successful rename/move operations.
    // Treating only arrays as success made completed renames show an error.
    static function ok($r)
    {
        $success = ($r === 0 || (is_array($r) && !isset($r['e'])));
        if ($success && !self::$batch) self::invalidate();
        return $success;
    }

    static function mkdir($parent, $name)
    {
        $key = random_bytes(16);
        $r = self::api(['a' => 'p', 't' => $parent, 'n' => [['h' => 'xxxxxxxx', 't' => 1,
            'a' => self::attr($name, $key), 'k' => self::b64e(self::ecbE($key, self::$master))]]], self::$sid);
        $ok = self::ok($r);
        if ($ok && self::$batch) self::registerNode($r, $parent, $name, 1, $key, $key, '', 0);
        return $ok;
    }

    static function quota()
    {
        $r = self::api(['a' => 'uq', 'strg' => 1, 'xfer' => 1], self::$sid);
        if (!is_array($r)) throw new Exception('MEGA quota request failed');
        return ['used' => isset($r['cstrg']) ? (float)$r['cstrg'] : null,
                'total' => isset($r['mstrg']) ? (float)$r['mstrg'] : null];
    }

    /** Recoverable explicit deletion; preserve attributes and original parent. */
    static function trash($h)
    {
        self::invalidate();self::load();$n=self::$nodes[$h] ?? null;
        if (!$n || !self::$trash || !in_array((int)$n['t'],[0,1],true)) return false;
        $a=$n['attrs'] ?? ['n'=>$n['n']];$a['rr']=$n['p'];
        $json='MEGA'.json_encode($a,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        if(strlen($json)%16)$json.=str_repeat("\0",16-strlen($json)%16);
        $attr=self::b64e(self::cbcE($json,$n['aes']));
        if(!self::ok(self::api(['a'=>'a','n'=>$h,'attr'=>$attr],self::$sid))) return false;
        return self::ok(self::api(['a'=>'m','n'=>$h,'t'=>self::$trash],self::$sid));
    }

    static function delete($h)
    {
        // MEGA's delete action returns integer 0 on success (not an array).
        // The old self::ok() check rejected this valid response, showing a
        // deletion error even when the remote item had been removed.
        $result = self::api(['a' => 'd', 'n' => $h], self::$sid);
        if ($result === 0 || (is_array($result) && !isset($result['e']))) {
            self::invalidate();
            return true;
        }
        return false;
    }

    static function move($h, $newParent, $newName)
    {
        $n = self::$nodes[$h];
        $ok = true;
        if ($newParent !== $n['p']) $ok = (function($r){return $r === 0 || self::ok($r);})(self::api(['a' => 'm', 'n' => $h, 't' => $newParent], self::$sid));
        if ($ok && $newName !== $n['n']) {
            $ok = self::ok(self::api(['a' => 'a', 'n' => $h, 'attr' => self::attr($newName, $n['aes']),
                'key' => self::b64e(self::ecbE($n['key'], self::$master)), 'i' => self::b64e(random_bytes(8))], self::$sid));
        }
        return $ok;
    }

    static function download($h, $dest)
    {
        $n = self::$nodes[$h];
        $fh = fopen($dest, 'wb');
        if ($n['s'] > 0) {
            $r = self::api(['a' => 'g', 'g' => 1, 'n' => $h], self::$sid);
            if (!is_array($r) || empty($r['g'])) { fclose($fh); return false; }
            $buf = ''; $blk = 0;
            $ch = curl_init($r['g']);
            curl_setopt_array($ch, [CURLOPT_FOLLOWLOCATION => 1, CURLOPT_TIMEOUT => 0,
                CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 110, CURLOPT_WRITEFUNCTION => function ($c, $d) use (&$buf, &$blk, $n, $fh) {
                    $buf .= $d;
                    $len = strlen($buf) & ~15;
                    if ($len) {
                        fwrite($fh, self::ctr(substr($buf, 0, $len), $n['aes'], $n['nonce'], $blk << 4));
                        $blk += $len >> 4;
                        $buf = substr($buf, $len);
                    }
                    return strlen($d);
                }]);
            $ok = curl_exec($ch) !== false && curl_getinfo($ch, CURLINFO_HTTP_CODE) == 200;
            curl_close($ch);
            if ($ok && $buf !== '') fwrite($fh, self::ctr($buf, $n['aes'], $n['nonce'], $blk << 4));
            fclose($fh);
            return $ok;
        }
        fclose($fh);
        return true;
    }

    static function chunks($size)
    {
        $o = 0; $i = 1; $r = [];
        while ($o < $size) {
            $l = min($i <= 8 ? $i * 131072 : 1048576, $size - $o);
            $r[] = [$o, $l];
            $o += $l; $i++;
        }
        return $r ?: [[0, 0]];
    }

    static function upload($file, $parent, $name)
    {
        $size = filesize($file);
        $aes = random_bytes(16);
        $nonce = random_bytes(8);
        $r = self::api(['a' => 'u', 's' => $size], self::$sid);
        if (!is_array($r) || empty($r['p'])) return false;
        $fh = fopen($file, 'rb');
        $fm = str_repeat("\0", 16);
        $handle = null;
        foreach (self::chunks($size) as $c) {
            list($off, $len) = $c;
            $plain = $len ? fread($fh, $len) : '';
            if ($len) {
                $pad = strlen($plain) % 16 ? $plain . str_repeat("\0", 16 - strlen($plain) % 16) : $plain;
                $cm = substr(self::cbcE($pad, $aes, $nonce . $nonce), -16);      // chunk CBC-MAC
                $fm = self::ecbE($fm ^ $cm, $aes);
            }
            $resp = self::post($r['p'] . '/' . $off, $len ? self::ctr($plain, $aes, $nonce, $off) : '');
            if ($resp === '-3' || preg_match('/^-\d+$/', $resp)) { fclose($fh); return false; }
            if ($resp !== '') {
                if ($off + $len !== $size || !preg_match('/^[A-Za-z0-9_-]{6,}$/', $resp)) { fclose($fh); return false; }
                $handle = $resp;
            }
        }
        fclose($fh);
        if ($handle === null) return false;
        $meta = (substr($fm, 0, 4) ^ substr($fm, 4, 4)) . (substr($fm, 8, 4) ^ substr($fm, 12, 4));
        $nm = $nonce . $meta;
        $key = ($aes ^ $nm) . $nm;
        $r = self::api(['a' => 'p', 't' => $parent, 'n' => [['h' => $handle, 't' => 0,
            'a' => self::attr($name, $aes), 'k' => self::b64e(self::ecbE($key, self::$master))]]], self::$sid);
        $ok = self::ok($r);
        if ($ok && self::$batch) self::registerNode($r, $parent, $name, 0, $key, $aes, $nonce, $size);
        return $ok;
    }

    /** Batch mode only: add a just-created node to the in-memory tree (avoids a full reload). */
    static function registerNode($r, $parent, $name, $t, $key, $aes, $nonce, $size)
    {
        $h = (is_array($r) && isset($r['f'][0]['h'])) ? (string)$r['f'][0]['h'] : '';
        if ($h === '') { self::invalidate(); return; }   // cannot track it: fall back to a safe reload
        $name = str_replace('/', '_', (string)$name);
        self::$nodes[$h] = ['h' => $h, 'p' => $parent, 'n' => $name, 't' => $t, 's' => (int)$size, 'ts' => time(),
            'key' => $key, 'aes' => $aes, 'nonce' => $nonce, 'rr' => '', 'attrs' => ['n' => $name]];
        self::$kids[$parent][$name] = $h;
    }
}

/** Minimal big-integer maths (base 2^24 limbs) so RSA works without gmp/bcmath. */
class MegaBig
{
    const M = 0xFFFFFF;

    static function trim($a) { while (count($a) > 1 && end($a) === 0) array_pop($a); return $a ?: [0]; }

    static function fromBin($s)
    {
        $s = str_pad($s, (int)(ceil(strlen($s) / 3) * 3), "\0", STR_PAD_LEFT);
        $r = [];
        for ($i = strlen($s) - 3; $i >= 0; $i -= 3) $r[] = (ord($s[$i]) << 16) | (ord($s[$i + 1]) << 8) | ord($s[$i + 2]);
        return self::trim($r);
    }

    static function toBin($a)
    {
        $s = '';
        for ($i = count($a) - 1; $i >= 0; $i--) $s .= chr(($a[$i] >> 16) & 255) . chr(($a[$i] >> 8) & 255) . chr($a[$i] & 255);
        return ltrim($s, "\0");
    }

    static function cmp($a, $b)
    {
        $a = self::trim($a); $b = self::trim($b);
        if (count($a) !== count($b)) return count($a) > count($b) ? 1 : -1;
        for ($i = count($a) - 1; $i >= 0; $i--) if ($a[$i] !== $b[$i]) return $a[$i] > $b[$i] ? 1 : -1;
        return 0;
    }

    static function add($a, $b)
    {
        $n = max(count($a), count($b)); $r = []; $c = 0;
        for ($i = 0; $i < $n; $i++) {
            $v = ($a[$i] ?? 0) + ($b[$i] ?? 0) + $c;
            $r[] = $v & self::M; $c = $v >> 24;
        }
        if ($c) $r[] = $c;
        return self::trim($r);
    }

    /** a - b, requires a >= b */
    static function sub($a, $b)
    {
        $r = []; $br = 0;
        foreach ($a as $i => $x) {
            $v = $x - ($b[$i] ?? 0) - $br;
            if ($v < 0) { $v += 0x1000000; $br = 1; } else $br = 0;
            $r[] = $v;
        }
        return self::trim($r);
    }

    static function mul($a, $b)
    {
        $na = count($a); $nb = count($b); $r = array_fill(0, $na + $nb, 0);
        for ($i = 0; $i < $na; $i++) {
            $c = 0; $ai = $a[$i];
            for ($j = 0; $j < $nb; $j++) {
                $v = $r[$i + $j] + $ai * $b[$j] + $c;
                $r[$i + $j] = $v & self::M; $c = $v >> 24;
            }
            $r[$i + $nb] = $c;
        }
        return self::trim($r);
    }

    /** a mod m by bitwise long division (only used a few times, so simplicity wins). */
    static function mod($a, $m)
    {
        $nm = count($m); $r = array_fill(0, $nm + 1, 0);
        for ($i = count($a) - 1; $i >= 0; $i--) {
            $w = $a[$i];
            for ($b = 23; $b >= 0; $b--) {
                $c = ($w >> $b) & 1;
                for ($j = 0; $j <= $nm; $j++) { $v = ($r[$j] << 1) | $c; $r[$j] = $v & self::M; $c = $v >> 24; }
                $ge = $r[$nm] > 0;
                if (!$ge) {
                    $ge = true;
                    for ($j = $nm - 1; $j >= 0; $j--) if ($r[$j] !== $m[$j]) { $ge = $r[$j] > $m[$j]; break; }
                }
                if ($ge) {
                    $br = 0;
                    for ($j = 0; $j <= $nm; $j++) {
                        $v = $r[$j] - ($j < $nm ? $m[$j] : 0) - $br;
                        if ($v < 0) { $v += 0x1000000; $br = 1; } else $br = 0;
                        $r[$j] = $v;
                    }
                }
            }
        }
        return self::trim($r);
    }

    static function pad($a, $L) { return array_pad($a, $L, 0); }

    /** Montgomery product (CIOS). a, b, n are L-limb arrays; ni = -n^-1 mod 2^24. */
    static function mm($a, $b, $n, $L, $ni)
    {
        $M = self::M;
        $t = array_fill(0, $L + 2, 0);
        for ($i = 0; $i < $L; $i++) {
            $ai = $a[$i]; $c = 0;
            for ($j = 0; $j < $L; $j++) { $v = $t[$j] + $ai * $b[$j] + $c; $t[$j] = $v & $M; $c = $v >> 24; }
            $v = $t[$L] + $c; $t[$L] = $v & $M; $t[$L + 1] = $v >> 24;
            $m = ($t[0] * $ni) & $M;
            $v = $t[0] + $m * $n[0]; $c = $v >> 24;
            for ($j = 1; $j < $L; $j++) { $v = $t[$j] + $m * $n[$j] + $c; $t[$j - 1] = $v & $M; $c = $v >> 24; }
            $v = $t[$L] + $c; $t[$L - 1] = $v & $M; $t[$L] = $t[$L + 1] + ($v >> 24); $t[$L + 1] = 0;
        }
        $ge = $t[$L] > 0;
        if (!$ge) {
            for ($j = $L - 1; $j >= 0; $j--) {
                if ($t[$j] !== $n[$j]) { $ge = $t[$j] > $n[$j]; break; }
                if ($j === 0) $ge = true;
            }
        }
        if ($ge) {
            $br = 0;
            for ($j = 0; $j < $L; $j++) {
                $v = $t[$j] - $n[$j] - $br;
                if ($v < 0) { $v += 0x1000000; $br = 1; } else $br = 0;
                $t[$j] = $v;
            }
        }
        return array_slice($t, 0, $L);
    }

    /** c^e mod n, n odd. */
    static function powMod($c, $e, $n)
    {
        $M = self::M; $L = count($n); $x = $n[0]; $inv = $x;
        for ($k = 0; $k < 5; $k++) { $t = ($x * $inv) & $M; $inv = ($inv * ((2 - $t) & $M)) & $M; }
        $ni = (0x1000000 - $inv) & $M;
        $r2 = self::pad(self::mod(array_merge(array_fill(0, 2 * $L, 0), [1]), $n), $L);
        $acc = self::pad(self::mod(array_merge(array_fill(0, $L, 0), [1]), $n), $L);
        $cm = self::mm(self::pad(self::mod($c, $n), $L), $r2, $n, $L, $ni);
        for ($i = count($e) - 1; $i >= 0; $i--) {
            for ($b = 23; $b >= 0; $b--) {
                $acc = self::mm($acc, $acc, $n, $L, $ni);
                if (($e[$i] >> $b) & 1) $acc = self::mm($acc, $cm, $n, $L, $ni);
            }
        }
        return self::trim(self::mm($acc, self::pad([1], $L), $n, $L, $ni));
    }

    /** RSA private-key decryption (CRT) on big-endian byte strings; returns big-endian bytes. */
    static function rsaDecrypt($cBin, $pBin, $qBin, $dBin, $uBin)
    {
        $c = self::fromBin($cBin); $p = self::fromBin($pBin); $q = self::fromBin($qBin);
        $d = self::fromBin($dBin); $u = self::fromBin($uBin);
        $mp = self::powMod($c, self::mod($d, self::sub($p, [1])), $p);
        $mq = self::powMod($c, self::mod($d, self::sub($q, [1])), $q);
        $mpq = self::mod($mp, $q);
        $diff = self::cmp($mq, $mpq) >= 0 ? self::sub($mq, $mpq) : self::sub(self::add($mq, $q), $mpq);
        $h = self::mod(self::mul($diff, $u), $q);
        return self::toBin(self::add($mp, self::mul($p, $h)));
    }
}

class MegaFS
{
    public $context;
    private $fh, $tmp, $up, $flushed, $list, $pos;

    static function remote($url)
    {
        $parts = [];
        foreach (explode('/', trim(substr($url, 7), '/')) as $s) {
            if ($s === '..') return false;
            if ($s !== '' && $s !== '.') $parts[] = $s;
        }
        if (!$parts || $parts[0] !== 'root') return false;
        array_shift($parts);
        return implode('/', $parts);
    }

    static function isPart($url) { return substr($url, -5) === '.part'; }

    /** Chunked-upload ".part" files stay local so appends are cheap. */
    static function partPath($url)
    {
        $d = sys_get_temp_dir() . '/megafm_' . md5(MegaApi::$sid);
        if (!is_dir($d)) @mkdir($d, 0700, true);
        return $d . '/' . md5($url) . '.part';
    }

    static function sb($dir, $size, $mtime)
    {
        return ['dev' => 0, 'ino' => 0, 'mode' => $dir ? 040777 : 0100666, 'nlink' => 1, 'uid' => 0, 'gid' => 0,
            'rdev' => 0, 'size' => $size, 'atime' => $mtime, 'mtime' => $mtime, 'ctime' => $mtime,
            'blksize' => -1, 'blocks' => -1];
    }

    static function node($url)
    {
        $rem = self::remote($url);
        if ($rem === false) return null;
        try { MegaApi::load(); } catch (Exception $e) { return null; }
        $h = MegaApi::find($rem);
        return $h === null ? null : MegaApi::$nodes[$h];
    }

    /** [parentHandle, name] for a not-yet-existing path, or null. */
    static function parentOf($url)
    {
        $rem = self::remote($url);
        if ($rem === false || $rem === '') return null;
        try { MegaApi::load(); } catch (Exception $e) { return null; }
        $d = dirname($rem);
        $p = MegaApi::find($d === '.' ? '' : $d);
        if ($p === null || MegaApi::$nodes[$p]['t'] === 0) return null;
        return [$p, basename($rem)];
    }

    /** Fast one-level directory snapshot; uses the already-loaded MEGA metadata tree. */
    static function directorySnapshot($url)
    {
        $n = self::node($url);
        if (!$n || (int)$n['t'] === 0) return false;
        $result = array('folders' => array(), 'files' => array());
        foreach ((MegaApi::$kids[$n['h']] ?? array()) as $name => $handle) {
            if (!isset(MegaApi::$nodes[$handle])) continue;
            $entry = MegaApi::$nodes[$handle];
            $result[((int)$entry['t'] === 0) ? 'files' : 'folders'][] = (string)$name;
        }
        return $result;
    }

    /* ---------- stat / directories ---------- */

    function url_stat($path, $flags)
    {
        if (self::isPart($path)) return @stat(self::partPath($path)) ?: false;
        $n = self::node($path);
        return $n ? self::sb($n['t'] !== 0, $n['s'], $n['ts']) : false;
    }

    function dir_opendir($path, $opts)
    {
        $n = self::node($path);
        if (!$n || $n['t'] === 0) return false;
        $this->list = array_merge(['.', '..'], array_map('strval', array_keys(MegaApi::$kids[$n['h']] ?? [])));
        $this->pos = 0;
        return true;
    }
    function dir_readdir() { return $this->pos < count($this->list) ? $this->list[$this->pos++] : false; }
    function dir_rewinddir() { $this->pos = 0; return true; }
    function dir_closedir() { return true; }

    function mkdir($path, $mode, $opts)
    {
        $rem = self::remote($path);
        if ($rem === false || $rem === '') return false;
        $cur = 'mega://root';
        $segs = explode('/', $rem);
        foreach ($segs as $i => $s) {
            $cur .= '/' . $s;
            if (self::node($cur)) continue;
            if ($i < count($segs) - 1 && !($opts & STREAM_MKDIR_RECURSIVE)) return false;
            $po = self::parentOf($cur);
            if (!$po || !MegaApi::mkdir($po[0], $po[1])) return false;
        }
        return true;
    }

    function rmdir($path, $opts)
    {
        $n = self::node($path);
        return $n && $n['t'] === 1 && MegaApi::delete($n['h']);
    }

    function unlink($path)
    {
        if (self::isPart($path)) return @unlink(self::partPath($path));
        $n = self::node($path);
        return $n && $n['t'] === 0 && MegaApi::delete($n['h']);
    }

    function rename($from, $to)
    {
        $dst = self::parentOf($to);
        if (!$dst) return false;
        if (self::isPart($from)) {
            $local = self::partPath($from);
            if (self::isPart($to)) return @rename($local, self::partPath($to));
            $old = self::node($to);
            if (!MegaApi::upload($local, $dst[0], $dst[1])) return false;
            @unlink($local);
            if ($old && $old['t'] === 0 && !MegaApi::delete($old['h'])) return false;
            return true;
        }
        $n = self::node($from);
        if (!$n || $n['t'] === 2) return false;
        $old = self::node($to);
        // Never destroy the destination before the source move is confirmed.
        // Refuse replacement here; caller can explicitly handle conflicts.
        if ($old && $old['h'] !== $n['h']) return false;
        if ($old && $old['h'] === $n['h']) return true;
        MegaApi::load();
        return MegaApi::move($n['h'], $dst[0], $dst[1]);
    }

    function stream_metadata($path, $option, $value) { return false; } // MEGA does not implement local chmod/touch

    /* ---------- file streams (downloaded/buffered via local temp files) ---------- */

    function stream_open($path, $mode, $opts, &$opened)
    {
        $this->fh = $this->tmp = $this->up = null;
        $this->flushed = false;

        if (self::isPart($path)) {
            $this->fh = @fopen(self::partPath($path), $mode[0] === 'a' ? 'ab' : ($mode[0] === 'r' ? 'rb' : 'wb'));
            return (bool)$this->fh;
        }

        $n = self::node($path);
        if ($n && $n['t'] !== 0) return false;
        $readOnly = $mode[0] === 'r' && strpos($mode, '+') === false;
        if (($readOnly || $mode[0] === 'r') && !$n) return false;
        if ($mode[0] === 'x' && $n) return false;

        $this->tmp = tempnam(sys_get_temp_dir(), 'megafm');
        $keep = $n && ($mode[0] === 'a' || $mode[0] === 'r');
        if ($keep || $readOnly) {
            if (!MegaApi::download($n['h'], $this->tmp)) { @unlink($this->tmp); return false; }
        }
        if ($readOnly) {
            $this->fh = fopen($this->tmp, 'rb');
            return (bool)$this->fh;
        }
        if (!self::parentOf($path)) { @unlink($this->tmp); return false; }
        $this->fh = fopen($this->tmp, $keep ? 'r+b' : 'wb');
        if ($keep && $mode[0] === 'a') fseek($this->fh, 0, SEEK_END);
        $this->up = $path;
        return (bool)$this->fh;
    }

    function stream_read($n) { return fread($this->fh, $n); }
    function stream_write($d) { return fwrite($this->fh, $d); }
    function stream_eof() { return feof($this->fh); }
    function stream_seek($o, $w) { return fseek($this->fh, $o, $w) === 0; }
    function stream_tell() { return ftell($this->fh); }
    function stream_set_option($o, $a, $b) { return false; }
    function stream_stat() { return fstat($this->fh); }

    function stream_flush()
    {
        if ($this->up === null || $this->flushed) return true;
        fflush($this->fh);
        $old = self::node($this->up);
        $po = self::parentOf($this->up);
        if (!$po || !MegaApi::upload($this->tmp, $po[0], $po[1])) return false;
        if ($old && $old['t'] === 0 && !MegaApi::delete($old['h'])) return false;
        $this->flushed = true;
        return true;
    }

    function stream_close()
    {
        if (!$this->stream_flush()) error_log('MEGA file upload failed during stream_close');
        if ($this->fh) fclose($this->fh);
        if ($this->tmp) @unlink($this->tmp);
    }
}

/* ---------- login page / session ---------- */

function mega_login_form($err = '')
{
    $loginStorage = defined('FM_STORAGE_TYPE') ? FM_STORAGE_TYPE : ($GLOBALS['storage_type'] ?? 'local');
    $intro = $loginStorage === 'mega' ? 'Sign in to your MEGA account' : 'Sign in to your account';
    $error = $err ? '<div class="notice" role="alert">' . htmlspecialchars($err, ENT_QUOTES, 'UTF-8') . '</div>' : '';
    echo <<<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>MEGA File Manager — Login</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100dvh;background:#f5f7fa;color:#202b36;display:flex;align-items:center;justify-content:center;padding:22px}
.login-card{width:100%;max-width:410px;background:#fff;border:1px solid #e0e6ed;border-radius:14px;box-shadow:0 12px 36px rgba(24,45,66,.09);overflow:hidden}
.login-heading{padding:21px 25px;background:#f8fafc;border-bottom:1px solid #e0e6ed;display:flex;gap:12px;align-items:center;font-size:20px;font-weight:650}
.login-heading svg{width:28px;height:28px;flex-shrink:0;color:#2185ca}
.login-body{padding:24px 25px 26px}.intro{font-size:14px;color:#697786;margin:0 0 20px}
.field{margin-bottom:18px}label{display:block;font-size:14px;font-weight:550;margin-bottom:8px}input{width:100%;height:46px;padding:10px 13px;border:1px solid #cdd6e0;border-radius:8px;background:#fff;color:#202b36;font:inherit;font-size:16px;outline:none}input:focus{border-color:#2185ca;box-shadow:0 0 0 3px rgba(33,133,202,.14)}
.password-wrap{position:relative}.password-wrap input{padding-right:54px}.eye-button{position:absolute;right:3px;top:2px;height:42px;width:46px;display:flex;align-items:center;justify-content:center;border:0;background:transparent;color:#6c7885;border-radius:7px;cursor:pointer;touch-action:manipulation}.eye-button svg{height:22px;width:22px}
.login-submit{width:100%;min-height:46px;border:1px solid #16804c;background:#198754;color:#fff;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;margin-top:5px}.login-submit:active{background:#146c43}.notice{padding:11px 13px;border-radius:8px;background:#fff1f0;border:1px solid #ffd0cb;color:#a52c25;font-size:14px;margin-bottom:17px;overflow-wrap:anywhere}
@media(max-width:430px){body{padding:15px}.login-body{padding:20px}.login-heading{padding:18px 20px}}
@media(prefers-color-scheme:dark){body{background:#171b20;color:#e7edf3}.login-card{background:#232a31;border-color:#3c4855}.login-heading{background:#2b333c;border-color:#3c4855}.intro{color:#b0bac5}input{background:#1c232a;color:#fff;border-color:#54606c}.eye-button{color:#bbc5cf}.notice{background:#442824;border-color:#71443e;color:#ffd4ce}}
</style></head><body>
<main class="login-card"><div class="login-heading"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 4h16v16H4z"/><path d="M8 8h8M8 12h8M8 16h5"/></svg><span>File Manager</span></div><div class="login-body">
HTML;
    echo '<p class="intro">' . htmlspecialchars($intro, ENT_QUOTES, 'UTF-8') . '</p>';
    echo $error;
    echo <<<'HTML'
<form method="post" autocomplete="on"><div class="field"><label for="mega_user">Email</label><input id="mega_user" name="mega_user" type="email" autocomplete="username" placeholder="Email address" required autofocus></div>
<div class="field"><label for="mega_pass">Password</label><div class="password-wrap"><input id="mega_pass" name="mega_pass" type="password" autocomplete="current-password" placeholder="Password" required><button id="toggle-pass" class="eye-button" type="button" aria-label="Show password" title="Show password" aria-pressed="false"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z"/><circle cx="12" cy="12" r="3"/><path id="eye-slash" d="M3 3l18 18" style="display:none"/></svg></button></div></div>
<div class="field"><label for="mega_mfa">Two-factor authentication code <span style="font-weight:400;color:#84909b">(optional)</span></label><input id="mega_mfa" name="mega_mfa" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code"></div>
<button type="submit" class="login-submit">Log in</button></form></div></main>
<script>(function(){var b=document.getElementById('toggle-pass'),p=document.getElementById('mega_pass'),s=document.getElementById('eye-slash');b.addEventListener('click',function(){var show=p.type==='password';p.type=show?'text':'password';s.style.display=show?'':'none';b.setAttribute('aria-label',show?'Hide password':'Show password');b.setAttribute('title',show?'Hide password':'Show password');b.setAttribute('aria-pressed',show?'true':'false');});}());</script>
</body></html>
HTML;
    exit;
}

/** Call from config.php. Shows the MEGA login form until credentials are verified. */
function mega_require_login()
{
    // config.php has selected the backend before calling this function. Public
    // website links require MEGA mode, but never require a visitor to log in.
    if (isset($_GET['share']) && function_exists('fm_serve_public_share')) {
        fm_share_require_mega();
        fm_serve_public_share($_GET['share']);
    }
    $missing = [];
    foreach (['curl', 'openssl'] as $x) if (!extension_loaded($x)) $missing[] = $x;
    if (PHP_VERSION_ID < 70100) $missing[] = 'PHP 7.1+';
    if ($missing) die('Missing on this server: ' . implode(', ', $missing));

    session_name('megafm');
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty($_SERVER['HTTPS'])]);
    session_start();

    if (isset($_GET['mega_logout'])) {
        if (!empty($_SESSION['mega'])) { MegaApi::$sid = $_SESSION['mega']['sid']; MegaApi::invalidate(); }
        session_destroy();
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    // Conservative per-browser login cooldown: never automatically repeat a failed login.
    $err = '';
    $cooldownEnabled = ($GLOBALS['mega_login_cooldown_enabled'] ?? true) !== false;
    $maxFailures = $GLOBALS['mega_login_max_failures'] ?? 3;
    if (!is_int($maxFailures) || $maxFailures < 1 || $maxFailures > 100) $maxFailures = 3;
    if (!$cooldownEnabled || (isset($_SESSION['mega_login_block_until']) && time() >= (int)$_SESSION['mega_login_block_until'])) {
        unset($_SESSION['mega_login_block_until'], $_SESSION['mega_login_failures']);
    }
    if ($cooldownEnabled && empty($_SESSION['mega']) && isset($_SESSION['mega_login_block_until']) && time() < $_SESSION['mega_login_block_until']) {
        if (isset($_POST['mega_user'], $_POST['mega_pass']) && function_exists('fm_log_user_login')) fm_log_user_login($_POST['mega_user'], false, 'login_cooldown');
        mega_login_form('Login temporarily disabled after a failed attempt. Wait before retrying.');
    }
    if (empty($_SESSION['mega']) && isset($_POST['mega_user'], $_POST['mega_pass'])) {
        try {
            if (!is_string($_POST['mega_user']) || !is_string($_POST['mega_pass']) || (isset($_POST['mega_mfa']) && !is_string($_POST['mega_mfa']))) {
                throw new InvalidArgumentException('Invalid login request');
            }
            // One explicit user submission, at most one authentication request.
            $s = MegaApi::login($_POST['mega_user'], $_POST['mega_pass'], trim($_POST['mega_mfa'] ?? ''));
            unset($_SESSION['mega_login_block_until'], $_SESSION['mega_login_failures']);
            session_regenerate_id(true);
            $_SESSION['mega'] = ['sid' => $s['sid'], 'master' => base64_encode($s['master']), 'prefs_id' => hash('sha256', strtolower(trim($_POST['mega_user'])))];
            if (function_exists('fm_log_user_login')) fm_log_user_login($_POST['mega_user'], true);
            header('Location: ' . $_SERVER['REQUEST_URI']);
            exit;
        } catch (Throwable $e) {
            if (function_exists('fm_log_user_login')) fm_log_user_login($_POST['mega_user'] ?? '', false, fm_login_failure_category($e));
            $blocked = false;
            // A missing-code challenge is the next authentication step, not an
            // incorrect code. Preserve existing failures without adding one.
            if ($cooldownEnabled && $e->getMessage() !== 'Two-factor code required') {
                $failures = $_SESSION['mega_login_failures'] ?? 0;
                $failures = is_int($failures) ? max(0, $failures) : 0;
                $_SESSION['mega_login_failures'] = min($maxFailures, $failures + 1);
                if ($_SESSION['mega_login_failures'] >= $maxFailures) {
                    $_SESSION['mega_login_block_until'] = time() + 300;
                    $blocked = true;
                }
            } elseif (!$cooldownEnabled) unset($_SESSION['mega_login_block_until'], $_SESSION['mega_login_failures']);
            error_log('[megafm] Login attempt failed; reason=' . preg_replace('/[^a-zA-Z0-9 _.-]/', '', $e->getMessage()));
            $loginMessage = $e->getMessage() === 'MEGA error -3' ? 'Login fail' : $e->getMessage();
            $err = $loginMessage . ($blocked ? '. Please wait 5 minutes before another attempt.' : '');
        }
    }
    if (empty($_SESSION['mega'])) mega_login_form($err);

    MegaApi::$sid = $_SESSION['mega']['sid'];
    MegaApi::$master = base64_decode($_SESSION['mega']['master']);
    try {
        MegaApi::load();                 // also verifies the session is still valid
    } catch (Exception $e) {
        unset($_SESSION['mega']);
        mega_login_form($e->getCode() === -15 ? 'Session expired, please log in again' : $e->getMessage());
    }
    // Preserve MEGA account identity before Tiny File Manager switches PHP sessions.
    $GLOBALS['mega_authenticated_pref_id'] = isset($_SESSION['mega']['prefs_id']) ? $_SESSION['mega']['prefs_id'] : null;
    session_write_close();               // let Tiny File Manager open its own session
    stream_wrapper_register('mega', 'MegaFS');
}

/** Drop-in for move_uploaded_file() that also works for mega:// targets. */
function mega_move_uploaded($tmp, $dest)
{
    if (strpos($dest, 'mega://') === 0) return is_uploaded_file($tmp) && copy($tmp, $dest) && @unlink($tmp);
    return move_uploaded_file($tmp, $dest);
}
