<?php
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/'));
}

function uuid_v4() {
    $data = openssl_random_pseudo_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function jwt_encode($payload, $secret) {
    $header = base64url_encode(json_encode(array('typ' => 'JWT', 'alg' => 'HS256')));
    $payload['iat'] = isset($payload['iat']) ? $payload['iat'] : time();
    $payload['exp'] = isset($payload['exp']) ? $payload['exp'] : time() + 30 * 24 * 3600;
    $payloadEncoded = base64url_encode(json_encode($payload));
    $signature = base64url_encode(hash_hmac('sha256', "$header.$payloadEncoded", $secret, true));
    return "$header.$payloadEncoded.$signature";
}

function jwt_decode($token, $secret) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    list($header, $payload, $signature) = $parts;
    $expected = base64url_encode(hash_hmac('sha256', "$header.$payload", $secret, true));
    if (!hash_equals($expected, $signature)) return null;
    $data = json_decode(base64url_decode($payload), true);
    if (!$data) return null;
    $exp = isset($data['exp']) ? $data['exp'] : 0;
    if ($exp < time()) return null;
    return $data;
}

function json_success($data = null, $code = 200) {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function json_error($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(array('error' => $msg), JSON_UNESCAPED_UNICODE);
    exit;
}

function get_body() {
    $raw = file_get_contents('php://input');
    return json_decode($raw, true) ?: array();
}

function get_auth_header() {
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) return $_SERVER['HTTP_AUTHORIZATION'];
    if (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) return $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    if (isset($_SERVER['Authorization'])) return $_SERVER['Authorization'];
    if (function_exists('apache_request_headers')) {
        $h = apache_request_headers();
        if (isset($h['Authorization'])) return $h['Authorization'];
    }
    return '';
}

function authenticate($db, $secret) {
    $header = get_auth_header();
    if (!preg_match('/^Bearer\s+(.+)$/', $header, $m)) {
        json_error('Требуется авторизация', 401);
    }
    $payload = jwt_decode($m[1], $secret);
    if (!$payload || !isset($payload['userId'])) {
        json_error('Недействительный токен', 401);
    }
    $stmt = $db->prepare('SELECT id, email, name, role, blocked_until FROM users WHERE id = ?');
    $stmt->execute(array($payload['userId']));
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) json_error('Пользователь не найден', 401);
    $now = new DateTime();
    if ($user['blocked_until'] && new DateTime($user['blocked_until']) > $now) {
        json_error('Аккаунт заблокирован', 403);
    }
    return $user;
}

function require_admin($user) {
    if ($user['role'] !== 'admin') {
        json_error('Доступ запрещён. Требуются права администратора.', 403);
    }
}

function val($rows, $key, $default) {
    return isset($rows[$key]) ? (int)$rows[$key] : $default;
}

function get_plans($db) {
    $stmt = $db->prepare("SELECT key, value FROM settings WHERE key LIKE 'plan_%' OR key LIKE 'discount_%'");
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
    return array(
        'trial'    => array('max_teams' => val($rows, 'plan_trial_max_teams', 9999), 'duration_days' => val($rows, 'plan_trial_duration_days', 7), 'price' => val($rows, 'plan_trial_price', 0)),
        'basic'    => array('max_teams' => val($rows, 'plan_basic_max_teams', 10), 'duration_days' => val($rows, 'plan_basic_duration_days', 30), 'price' => val($rows, 'plan_basic_price', 22)),
        'standard' => array('max_teams' => val($rows, 'plan_standard_max_teams', 30), 'duration_days' => val($rows, 'plan_standard_duration_days', 30), 'price' => val($rows, 'plan_standard_price', 33)),
        'premium'  => array('max_teams' => val($rows, 'plan_premium_max_teams', -1), 'duration_days' => val($rows, 'plan_premium_duration_days', 30), 'price' => val($rows, 'plan_premium_price', 44)),
    );
}

function get_discounts($db) {
    $stmt = $db->prepare("SELECT key, value FROM settings WHERE key LIKE 'discount_%'");
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
    return array(
        3  => array('pct' => val($rows, 'discount_3_pct', 15), 'label' => '3 месяца'),
        6  => array('pct' => val($rows, 'discount_6_pct', 25), 'label' => '6 месяцев'),
        12 => array('pct' => val($rows, 'discount_12_pct', 35), 'label' => '12 месяцев'),
    );
}

function admin_sub() {
    return array('plan' => 'premium', 'status' => 'active', 'max_teams' => 999999, 'expires_at' => '2099-12-31T23:59:59', 'period_months' => 12, 'discount' => 0);
}
