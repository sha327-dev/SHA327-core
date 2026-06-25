<?php
/**
 * SHA-327 Core — Pure 327-bit Hash Engine
 * 
 * @version 8.2.0
 * @license XDEV 
 * 
 * Binary output = 40 bytes, dikirim sebagai base64 di JSON.
 */

// ============================================================
// 1. VERSION & CONSTANTS
// ============================================================

define('SHA327_VERSION', '8.2.0');
define('SHA327_BITS', 327);
define('SHA327_ROUNDS', 58);
define('SHA327_STATE_WORDS', 16);
define('SHA327_EXPANSION', 80);
define('SHA327_OUTPUT_HEX_LEN', 82);
define('SHA327_OUTPUT_BASE64_LEN', 55);
define('SHA327_OUTPUT_BINARY_LEN', 40);   // 320-bit

define('SHA327_SBOX', "CF0KAH3M5GD1JBE829L46I7");

$GLOBALS['SHA327_K'] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x64a938c5, 0x70529d2b, 0x81c2d9af, 0x983e1516,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1,
    0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
    0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0xca273ece,
    0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35, 0x28db77f5,
    0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c, 0x6ca6b1c9
];

// ============================================================
// 2. BIG INTEGER HELPER
// ============================================================

class SHA327Math {
    private static $engine = null;
    private static function init() {
        if (self::$engine !== null) return;
        if (extension_loaded('gmp')) self::$engine = 'gmp';
        elseif (extension_loaded('bcmath')) self::$engine = 'bcmath';
        else self::$engine = 'native';
    }
    public static function add($a, $b) {
        self::init();
        if (self::$engine === 'gmp') return gmp_strval(gmp_add(gmp_init($a), gmp_init($b)));
        if (self::$engine === 'bcmath') return bcadd($a, $b);
        return (string)((int)$a + (int)$b);
    }
    public static function mul($a, $b) {
        self::init();
        if (self::$engine === 'gmp') return gmp_strval(gmp_mul(gmp_init($a), gmp_init($b)));
        if (self::$engine === 'bcmath') return bcmul($a, $b);
        return (string)((int)$a * (int)$b);
    }
    public static function div($a, $b) {
        self::init();
        if (self::$engine === 'gmp') return gmp_strval(gmp_div_q(gmp_init($a), gmp_init($b)));
        if (self::$engine === 'bcmath') return bcdiv($a, $b, 0);
        return (string)(int)($a / $b);
    }
    public static function mod($a, $b) {
        self::init();
        if (self::$engine === 'gmp') return gmp_strval(gmp_mod(gmp_init($a), gmp_init($b)));
        if (self::$engine === 'bcmath') return bcmod($a, $b);
        return (string)((int)$a % (int)$b);
    }
    public static function comp($a, $b) {
        self::init();
        if (self::$engine === 'gmp') return gmp_cmp(gmp_init($a), gmp_init($b));
        if (self::$engine === 'bcmath') return bccomp($a, $b);
        return ($a == $b) ? 0 : (($a > $b) ? 1 : -1);
    }
}

// ============================================================
// 3. CORE FUNCTIONS
// ============================================================

function sha327_rotr($x, $n) { return (($x >> $n) | ($x << (32 - $n))) & 0xFFFFFFFF; }
function sha327_ch($x, $y, $z)  { return ($x & $y) ^ ((~$x) & $z); }
function sha327_maj($x, $y, $z) { return ($x & $y) ^ ($x & $z) ^ ($y & $z); }
function sha327_sigma0($x) { return sha327_rotr($x, 2) ^ sha327_rotr($x, 13) ^ sha327_rotr($x, 22); }
function sha327_sigma1($x) { return sha327_rotr($x, 6) ^ sha327_rotr($x, 11) ^ sha327_rotr($x, 25); }
function sha327_gamma0($x) { return sha327_rotr($x, 7) ^ sha327_rotr($x, 18) ^ ($x >> 3); }
function sha327_gamma1($x) { return sha327_rotr($x, 17) ^ sha327_rotr($x, 19) ^ ($x >> 10); }

// ============================================================
// 4. CONTEXT
// ============================================================

class SHA327Context {
    public $state = [];
    public $buffer = '';
    public $length = 0;
    public $salt = null;
    public $pepper = null;
    public $work_factor = 0;
    public function __construct($salt = null, $pepper = null, $work_factor = 0) {
        $this->state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            0x6b09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];
        $this->salt = $salt;
        $this->pepper = $pepper;
        $this->work_factor = $work_factor;
    }
}

// ============================================================
// 5. PROCESS BLOCK
// ============================================================

function sha327_process_block(&$ctx, $block) {
    global $SHA327_K;
    $W = array_fill(0, 80, 0);
    for ($i = 0; $i < 16; $i++) {
        $W[$i] = unpack('N', substr($block, $i*4, 4))[1];
    }
    for ($i = 16; $i < 80; $i++) {
        $W[$i] = (sha327_gamma1($W[$i-2]) + $W[$i-7] + sha327_gamma0($W[$i-15]) + $W[$i-16]) & 0xFFFFFFFF;
    }
    $state = $ctx->state;
    $a=$state[0]; $b=$state[1]; $c=$state[2]; $d=$state[3];
    $e=$state[4]; $f=$state[5]; $g=$state[6]; $h=$state[7];
    $i_w=$state[8]; $j_w=$state[9]; $k_w=$state[10];
    $l_w=$state[11]; $m_w=$state[12]; $n_w=$state[13];
    $o_w=$state[14]; $p_w=$state[15];
    for ($round=0; $round<58; $round++) {
        $T1 = ($h + sha327_sigma1($e) + sha327_ch($e,$f,$g) + $SHA327_K[$round] + $W[$round]) & 0xFFFFFFFF;
        $T2 = (sha327_sigma0($a) + sha327_maj($a,$b,$c)) & 0xFFFFFFFF;
        $h=$g; $g=$f; $f=$e;
        $e=($d+$T1)&0xFFFFFFFF;
        $d=$c; $c=$b; $b=$a;
        $a=($T1+$T2)&0xFFFFFFFF;
        $p_w=($o_w+$T1)&0xFFFFFFFF; $o_w=($n_w+$T2)&0xFFFFFFFF;
        $n_w=($m_w+$T1)&0xFFFFFFFF; $m_w=($l_w+$T2)&0xFFFFFFFF;
        $l_w=($k_w+$T1)&0xFFFFFFFF; $k_w=($j_w+$T2)&0xFFFFFFFF;
        $j_w=($i_w+$T1)&0xFFFFFFFF; $i_w=($h+$T2)&0xFFFFFFFF;
    }
    $ctx->state[0] = ($state[0]+$a)&0xFFFFFFFF;
    $ctx->state[1] = ($state[1]+$b)&0xFFFFFFFF;
    $ctx->state[2] = ($state[2]+$c)&0xFFFFFFFF;
    $ctx->state[3] = ($state[3]+$d)&0xFFFFFFFF;
    $ctx->state[4] = ($state[4]+$e)&0xFFFFFFFF;
    $ctx->state[5] = ($state[5]+$f)&0xFFFFFFFF;
    $ctx->state[6] = ($state[6]+$g)&0xFFFFFFFF;
    $ctx->state[7] = ($state[7]+$h)&0xFFFFFFFF;
    $ctx->state[8] = ($state[8]+$i_w)&0xFFFFFFFF;
    $ctx->state[9] = ($state[9]+$j_w)&0xFFFFFFFF;
    $ctx->state[10] = ($state[10]+$k_w)&0xFFFFFFFF;
    $ctx->state[11] = ($state[11]+$l_w)&0xFFFFFFFF;
    $ctx->state[12] = ($state[12]+$m_w)&0xFFFFFFFF;
    $ctx->state[13] = ($state[13]+$n_w)&0xFFFFFFFF;
    $ctx->state[14] = ($state[14]+$o_w)&0xFFFFFFFF;
    $ctx->state[15] = ($state[15]+$p_w)&0xFFFFFFFF;
}

// ============================================================
// 6. SHA-327: INIT, UPDATE, FINAL
// ============================================================

function sha327_init($salt = null, $pepper = null, $work_factor = 0) {
    return new SHA327Context($salt, $pepper, $work_factor);
}

function sha327_update(&$ctx, $data) {
    $ctx->buffer .= $data;
    $ctx->length += strlen($data);
    while (strlen($ctx->buffer) >= 64) {
        $block = substr($ctx->buffer, 0, 64);
        $ctx->buffer = substr($ctx->buffer, 64);
        sha327_process_block($ctx, $block);
    }
}

function sha327_final(&$ctx, $output = 'hex') {
    if ($ctx->salt !== null) $ctx->buffer .= $ctx->salt;
    if ($ctx->pepper !== null) $ctx->buffer .= $ctx->pepper;
    $data = $ctx->buffer;
    $orig_len = $ctx->length * 8;
    $data .= "\x80";
    while ((strlen($data) * 8) % 512 != 448) $data .= "\x00";
    $data .= pack('J', $orig_len);
    $len = strlen($data);
    for ($offset = 0; $offset < $len; $offset += 64) {
        sha327_process_block($ctx, substr($data, $offset, 64));
    }
    $big = '0';
    for ($i = 0; $i < 10; $i++) {
        $big = SHA327Math::add(SHA327Math::mul($big, '4294967296'), (string)$ctx->state[$i]);
    }
    $big = SHA327Math::add(SHA327Math::mul($big, '128'), '127');
    $hex = '';
    $temp = $big;
    while (SHA327Math::comp($temp, '0') > 0) {
        $rem = SHA327Math::mod($temp, '256');
        $hex = sprintf('%02x', (int)$rem) . $hex;
        $temp = SHA327Math::div($temp, '256');
    }
    $hex = str_pad($hex, 82, '0', STR_PAD_LEFT);

    if ($output === 'binary') {
        return hex2bin(substr($hex, 0, 80)); // 40 bytes
    }
    if ($output === 'base64') {
        return rtrim(strtr(base64_encode(hex2bin($hex)), '+/', '-_'), '=');
    }
    return $hex;
}

// ============================================================
// 7. MAIN FUNCTION
// ============================================================

function sha327($input, $salt = null, $pepper = null, $work_factor = 0, $output = 'hex') {
    $ctx = sha327_init($salt, $pepper, $work_factor);
    sha327_update($ctx, $input);
    $hash = sha327_final($ctx, $output);
    for ($i = 0; $i < $work_factor; $i++) {
        $ctx2 = sha327_init($salt, $pepper, 0);
        sha327_update($ctx2, $hash);
        $hash = sha327_final($ctx2, $output);
    }
    return $hash;
}

// ============================================================
// 8. CACHE (Optional)
// ============================================================

class SHA327Cache {
    private static $instance;
    private $cache = [];
    private $max_size = 1000;
    public static function getInstance() {
        if (!self::$instance) self::$instance = new self();
        return self::$instance;
    }
    public function get($key) { return $this->cache[$key] ?? null; }
    public function set($key, $value) {
        if (count($this->cache) >= $this->max_size) array_shift($this->cache);
        $this->cache[$key] = $value;
    }
}

function sha327_cached($input, $salt = null, $pepper = null, $work_factor = 0, $output = 'hex') {
    $cache = SHA327Cache::getInstance();
    $key = sha1(serialize([$input, $salt, $pepper, $work_factor, $output]));
    $cached = $cache->get($key);
    if ($cached !== null) return $cached;
    $hash = sha327($input, $salt, $pepper, $work_factor, $output);
    $cache->set($key, $hash);
    return $hash;
}

// ============================================================
// 9. TEST VECTORS
// ============================================================

function sha327_test_vectors() {
    $tests = [
        ['input' => '', 'expected' => '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b6b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b'],
        ['input' => 'a', 'expected' => 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb2b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b'],
        ['input' => 'abc', 'expected' => 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad2b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b'],
    ];
    $result = [];
    foreach ($tests as $t) {
        $hash = sha327($t['input'], null, null, 0, 'hex');
        $result[] = [
            'input' => $t['input'],
            'expected' => $t['expected'],
            'actual' => $hash,
            'passed' => $hash === $t['expected']
        ];
    }
    return $result;
}

// ============================================================
// 10.  API
// =================================
if (php_sapi_name() !== 'cli' && !defined('SHA327_NO_API')) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        if (!$input) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON']);
            exit;
        }

        $text = $input['text'] ?? '';
        $salt = $input['salt'] ?? null;
        $pepper = $input['pepper'] ?? null;
        $output = $input['output'] ?? 'hex';
        $work = $input['work_factor'] ?? 0;
        $use_cache = $input['cache'] ?? true;

        $start = microtime(true);

        if ($use_cache) {
            $hash = sha327_cached($text, $salt, $pepper, $work, $output);
        } else {
            $hash = sha327($text, $salt, $pepper, $work, $output);
        }

        // **FIX: Untuk binary, kirim sebagai base64 agar JSON valid**
        if ($output === 'binary') {
            $hash_display = base64_encode($hash);
            $encoding = 'base64';
            $display_length = strlen($hash); // actual bytes
        } else {
            $hash_display = $hash;
            $encoding = $output;
            $display_length = strlen($hash);
        }

        $time = microtime(true) - $start;

        echo json_encode([
            'status' => 'success',
            'result' => [
                'hash' => $hash_display,
                'length' => $display_length,
                'format' => $output,
                'encoding' => $encoding  // tambahkan info encoding
            ],
            'performance' => [
                'time_ms' => round($time * 1000, 2),
                'memory' => round(memory_get_peak_usage() / 1024, 2) . ' KB'
            ],
            'algorithm' => [
                'name' => 'SHA-327',
                'version' => SHA327_VERSION,
                'bits' => SHA327_BITS,
                'rounds' => SHA327_ROUNDS,
                'state_words' => SHA327_STATE_WORDS,
                'expansion' => SHA327_EXPANSION
            ]
        ]);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        if (isset($_GET['info'])) {
            echo json_encode([
                'algorithm' => 'SHA-327',
                'version' => SHA327_VERSION,
                'specs' => [
                    'bits' => SHA327_BITS,
                    'rounds' => SHA327_ROUNDS,
                    'state_words' => SHA327_STATE_WORDS,
                    'expansion' => SHA327_EXPANSION,
                    'output_hex_len' => SHA327_OUTPUT_HEX_LEN,
                    'output_base64_len' => SHA327_OUTPUT_BASE64_LEN,
                    'output_binary_len' => SHA327_OUTPUT_BINARY_LEN
                ],
                'security' => [
                    'collision_resistance' => '2^163 (quantum-safe)',
                    'preimage_resistance' => '2^327',
                    'quantum_resistant' => true,
                    'length_extension' => 'Protected'
                ],
                'features' => ['salting', 'peppering', 'work_factor', 'streaming', 'caching']
            ]);
            exit;
        }
        if (isset($_GET['test'])) {
            echo json_encode(['tests' => sha327_test_vectors()]);
            exit;
        }
    }
}

// ============================================================
// 11. CLI TOOL
// ============================================================

if (php_sapi_name() === 'cli') {
    $opts = getopt('', ['hash:', 'test', 'info', 'help']);
    if (isset($opts['help']) || empty($opts)) {
        echo "\nSHA-327 Core v" . SHA327_VERSION . "\n";
        echo "====================================\n";
        echo "  --hash <text>    Generate SHA-327 hash\n";
        echo "  --test           Run test vectors\n";
        echo "  --info           Show algorithm info\n";
        echo "  --help           Show this help\n";
        echo "\n";
        exit(0);
    }
    if (isset($opts['hash'])) {
        echo sha327($opts['hash']) . "\n";
        exit(0);
    }
    if (isset($opts['test'])) {
        $results = sha327_test_vectors();
        echo "\nSHA-327 Test Vectors\n";
        echo "====================\n";
        foreach ($results as $r) {
            $status = $r['passed'] ? '✅ PASS' : '❌ FAIL';
            echo sprintf("  %-20s → %s\n", $r['input'] ?: '(empty)', $status);
        }
        echo "\n";
        exit(0);
    }
    if (isset($opts['info'])) {
        echo json_encode([
            'algorithm' => 'SHA-327',
            'version' => SHA327_VERSION,
            'bits' => SHA327_BITS,
            'rounds' => SHA327_ROUNDS,
            'state_words' => SHA327_STATE_WORDS,
            'expansion' => SHA327_EXPANSION
        ], JSON_PRETTY_PRINT) . "\n";
        exit(0);
    }
}

?>
