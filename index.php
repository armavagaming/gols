<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once __DIR__ . '/utils.php';
require_once __DIR__ . '/config.php';

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

function b($arr, $key, $default = '') {
    return isset($arr[$key]) ? $arr[$key] : $default;
}

function bi($arr, $key, $default = 0) {
    return isset($arr[$key]) ? (int)$arr[$key] : $default;
}

try {
    // ── Auth Register ──
    if ($uri === '/api/auth/register' && $method === 'POST') {
        $body = get_body();
        $email = trim(b($body, 'email'));
        $password = b($body, 'password');
        $name = trim(b($body, 'name'));
        if (!$email || !$password) json_error('Email и пароль обязательны');
        if (strlen($password) < 6) json_error('Пароль минимум 6 символов');

        $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute(array($email));
        if ($stmt->fetch()) json_error('Email уже зарегистрирован', 409);

        $id = uuid_v4();
        $hash = password_hash($password, PASSWORD_BCRYPT, array('cost' => 10));
        $db->prepare('INSERT INTO users (id, email, password, name) VALUES (?, ?, ?, ?)')->execute(array($id, $email, $hash, $name));

        $subId = uuid_v4();
        $plans = get_plans($db);
        $expiresAt = date('c', time() + 7 * 24 * 3600);
        $db->prepare("INSERT INTO subscriptions (id, user_id, plan, status, expires_at, max_teams) VALUES (?, ?, 'trial', 'active', ?, ?)")
            ->execute(array($subId, $id, $expiresAt, $plans['trial']['max_teams']));

        $token = jwt_encode(array('userId' => $id), JWT_SECRET);
        json_success(array('token' => $token, 'user' => array('id' => $id, 'email' => $email, 'name' => $name, 'role' => 'user'), 'subscription' => array('plan' => 'trial', 'expires_at' => $expiresAt)), 201);
    }

    // ── Auth Login ──
    elseif ($uri === '/api/auth/login' && $method === 'POST') {
        $body = get_body();
        $email = trim(b($body, 'email'));
        $password = b($body, 'password');
        if (!$email || !$password) json_error('Email и пароль обязательны');

        $stmt = $db->prepare('SELECT * FROM users WHERE email = ?');
        $stmt->execute(array($email));
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || !password_verify($password, $user['password'])) {
            json_error('Неверный email или пароль', 401);
        }

        $now = new DateTime();
        if ($user['blocked_until'] && new DateTime($user['blocked_until']) > $now) {
            json_error('Аккаунт заблокирован. Оформите подписку.', 403);
        }

        $sub = null;
        if ($user['role'] !== 'admin') {
            $stmt = $db->prepare("SELECT * FROM subscriptions WHERE user_id = ? AND status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now'))");
            $stmt->execute(array($user['id']));
            $sub = $stmt->fetch(PDO::FETCH_ASSOC);
        }

        $token = jwt_encode(array('userId' => $user['id']), JWT_SECRET);
        $respSub = $user['role'] === 'admin' ? admin_sub() : ($sub ?: null);
        json_success(array('token' => $token, 'user' => array('id' => $user['id'], 'email' => $user['email'], 'name' => $user['name'], 'role' => $user['role']), 'subscription' => $respSub));
    }

    // ── Auth Me ──
    elseif ($uri === '/api/auth/me' && $method === 'GET') {
        $user = authenticate($db, JWT_SECRET);
        if ($user['role'] === 'admin') {
            $sub = admin_sub();
        } else {
            $stmt = $db->prepare("SELECT * FROM subscriptions WHERE user_id = ? AND status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now'))");
            $stmt->execute(array($user['id']));
            $sub = $stmt->fetch(PDO::FETCH_ASSOC);
        }
        json_success(array('user' => $user, 'subscription' => $sub ?: null));
    }

    // ── Change Password ──
    elseif ($uri === '/api/auth/change-password' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        $body = get_body();
        $currentPassword = b($body, 'currentPassword');
        $newPassword = b($body, 'newPassword');
        if (!$currentPassword || !$newPassword) json_error('Заполните все поля');
        if (strlen($newPassword) < 6) json_error('Пароль минимум 6 символов');

        $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute(array($user['id']));
        $dbUser = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!password_verify($currentPassword, $dbUser['password'])) {
            json_error('Неверный текущий пароль');
        }
        $hash = password_hash($newPassword, PASSWORD_BCRYPT, array('cost' => 10));
        $db->prepare("UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?")->execute(array($hash, $user['id']));
        json_success(array('success' => true));
    }

    // ── Forgot Password ──
    elseif ($uri === '/api/auth/check-email' && $method === 'POST') {
        $body = get_body();
        $email = trim(b($body, 'email'));
        if (!$email) json_error('Email обязателен');
        $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute(array($email));
        json_success(array('exists' => (bool)$stmt->fetch()));
    }

    // ── Forgot Password ──
    elseif ($uri === '/api/auth/forgot-password' && $method === 'POST') {
        $body = get_body();
        $email = trim(b($body, 'email'));
        if (!$email) json_error('Email обязателен');

        $stmt = $db->prepare('SELECT id, email FROM users WHERE email = ?');
        $stmt->execute(array($email));
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) json_success(array('message' => 'Если email зарегистрирован, вы получите ссылку для сброса пароля'));

        $token = bin2hex(random_bytes(32));
        $id = uuid_v4();
        $expiresAt = date('Y-m-d H:i:s', time() + 3600);

        $stmt = $db->prepare("INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)");
        $stmt->execute(array($id, $user['id'], $token, $expiresAt));

        json_success(array('message' => 'Если email зарегистрирован, вы получите ссылку для сброса пароля', 'token' => $token));
    }

    // ── Reset Password ──
    elseif ($uri === '/api/auth/reset-password' && $method === 'POST') {
        $body = get_body();
        $token = trim(b($body, 'token'));
        $newPassword = b($body, 'password');
        if (!$token || !$newPassword) json_error('Токен и пароль обязательны');
        if (strlen($newPassword) < 6) json_error('Пароль минимум 6 символов');

        $stmt = $db->prepare("SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > datetime('now')");
        $stmt->execute(array($token));
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) json_error('Неверный или просроченный токен', 400);

        $hash = password_hash($newPassword, PASSWORD_BCRYPT, array('cost' => 10));
        $db->prepare("UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?")->execute(array($hash, $row['user_id']));
        $db->prepare("UPDATE password_reset_tokens SET used = 1 WHERE id = ?")->execute(array($row['id']));

        json_success(array('message' => 'Пароль успешно изменён'));
    }

    // ── Subscribe ──
    elseif ($uri === '/api/subscribe' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        $body = get_body();
        $plan = b($body, 'plan');
        $periodMonths = bi($body, 'period_months', 1);
        $plans = get_plans($db);
        $discounts = get_discounts($db);

        if (!isset($plans[$plan])) json_error('Неверный тариф');

        $months = isset($discounts[$periodMonths]) ? $periodMonths : 1;
        $discount = $months > 1 ? $discounts[$months]['pct'] : 0;

        $stmt = $db->prepare("SELECT * FROM subscriptions WHERE user_id = ? AND status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now'))");
        $stmt->execute(array($user['id']));
        $currentSub = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($currentSub) {
            $db->prepare("UPDATE subscriptions SET status = 'cancelled' WHERE id = ?")->execute(array($currentSub['id']));
        }

        $subId = uuid_v4();
        $days = $plans[$plan]['duration_days'] * $months;
        $expiresAt = date('c', time() + $days * 24 * 3600);
        $maxTeams = $plans[$plan]['max_teams'] === -1 ? 999999 : $plans[$plan]['max_teams'];

        $db->prepare('INSERT INTO subscriptions (id, user_id, plan, status, started_at, expires_at, max_teams, period_months, discount) VALUES (?, ?, ?, ?, datetime(\'now\'), ?, ?, ?, ?)')
            ->execute(array($subId, $user['id'], $plan, 'active', $expiresAt, $maxTeams, $months, $discount));

        if ($plans[$plan]['price'] > 0) {
            $monthlyPrice = $plans[$plan]['price'];
            $fullAmount = $monthlyPrice * $months;
            $discountedAmount = round($fullAmount * (100 - $discount) / 100);
            $db->prepare('INSERT INTO payment_history (id, user_id, amount, currency, plan, period_months, discount) VALUES (?, ?, ?, ?, ?, ?, ?)')
                ->execute(array(uuid_v4(), $user['id'], $discountedAmount, 'BYN', $plan, $months, $discount));
        }

        if ($user['blocked_until']) {
            $db->prepare("UPDATE users SET blocked_until = NULL, updated_at = datetime('now') WHERE id = ?")->execute(array($user['id']));
        }

        json_success(array('success' => true, 'subscription' => array('id' => $subId, 'plan' => $plan, 'expires_at' => $expiresAt, 'max_teams' => $maxTeams, 'period_months' => $months, 'discount' => $discount)));
    }

    // ── Get Subscription ──
    elseif ($uri === '/api/subscription' && $method === 'GET') {
        $user = authenticate($db, JWT_SECRET);
        if ($user['role'] === 'admin') {
            $sub = admin_sub();
        } else {
            $stmt = $db->prepare("SELECT * FROM subscriptions WHERE user_id = ? AND status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now'))");
            $stmt->execute(array($user['id']));
            $sub = $stmt->fetch(PDO::FETCH_ASSOC);
        }
        $stmt = $db->prepare('SELECT * FROM payment_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 20');
        $stmt->execute(array($user['id']));
        $history = $stmt->fetchAll(PDO::FETCH_ASSOC);
        json_success(array('subscription' => $sub ?: null, 'history' => $history));
    }

    // ── Get Players ──
    elseif ($uri === '/api/players' && $method === 'GET') {
        $user = authenticate($db, JWT_SECRET);
        $stmt = $db->prepare('SELECT * FROM players WHERE user_id = ? ORDER BY name ASC');
        $stmt->execute(array($user['id']));
        json_success($stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    // ── Create Player ──
    elseif ($uri === '/api/players' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        $body = get_body();
        $name = trim(b($body, 'name'));
        if (!$name) json_error('Имя игрока обязательно');
        $id = uuid_v4();
        $db->prepare('INSERT INTO players (id, user_id, name, team_id, position, birth_year, number, photo_path) VALUES (?,?,?,?,?,?,?,?)')
            ->execute(array($id, $user['id'], $name, b($body, 'team_id'), b($body, 'position'), bi($body, 'birth_year'), bi($body, 'number'), b($body, 'photo_path')));
        json_success(array('success' => true, 'player' => array('id' => $id, 'name' => $name, 'team_id' => b($body, 'team_id'), 'position' => b($body, 'position'), 'birth_year' => bi($body, 'birth_year'), 'number' => bi($body, 'number'), 'photo_path' => b($body, 'photo_path'))), 201);
    }

    // ── Update Player ──
    elseif (preg_match('#^/api/players/([a-f0-9-]+)$#', $uri, $m) && $method === 'PUT') {
        $user = authenticate($db, JWT_SECRET);
        $playerId = $m[1];
        $stmt = $db->prepare('SELECT * FROM players WHERE id = ? AND user_id = ?');
        $stmt->execute(array($playerId, $user['id']));
        $p = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$p) json_error('Игрок не найден', 404);
        $body = get_body();
        $db->prepare('UPDATE players SET name=?, team_id=?, position=?, birth_year=?, number=?, photo_path=? WHERE id=?')
            ->execute(array(b($body, 'name', $p['name']), b($body, 'team_id', $p['team_id']), b($body, 'position', $p['position']), bi($body, 'birth_year', $p['birth_year']), bi($body, 'number', $p['number']), b($body, 'photo_path', $p['photo_path']), $playerId));
        json_success(array('success' => true));
    }

    // ── Delete Player ──
    elseif (preg_match('#^/api/players/([a-f0-9-]+)$#', $uri, $m) && $method === 'DELETE') {
        $user = authenticate($db, JWT_SECRET);
        $db->prepare('DELETE FROM players WHERE id = ? AND user_id = ?')->execute(array($m[1], $user['id']));
        json_success(array('success' => true));
    }

    // ── Upload Photo ──
    elseif ($uri === '/api/upload-photo' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        $body = get_body();
        $image = b($body, 'image');
        if (!$image) json_error('Нет изображения');
        if (!preg_match('#^data:image/(png|jpeg|jpg|gif|webp);base64,(.+)$#', $image, $matches)) {
            json_error('Неверный формат изображения');
        }
        $ext = $matches[1] === 'jpeg' ? 'jpg' : $matches[1];
        $data = base64_decode($matches[2], true);
        if ($data === false || strlen($data) > 200 * 1024) json_error('Фото больше 200 КБ');
        $uploadDir = __DIR__ . '/uploads';
        if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
        $filename = uuid_v4() . '.' . $ext;
        file_put_contents($uploadDir . '/' . $filename, $data);
        json_success(array('url' => '/uploads/' . $filename));
    }

    // ── Plans ──
    elseif ($uri === '/api/plans' && $method === 'GET') {
        $p = get_plans($db);
        $d = get_discounts($db);
        json_success(array(
            'trial'    => array('name' => 'Пробный',     'max_teams' => $p['trial']['max_teams'] === 9999 ? 'все функции' : 'до ' . $p['trial']['max_teams'], 'duration' => $p['trial']['duration_days'] . ' дней',    'price' => $p['trial']['price'],  'description' => 'Полный доступ на 7 дней'),
            'basic'    => array('name' => 'Базовый',     'max_teams' => $p['basic']['max_teams'] === -1 ? 'безлимит' : 'до ' . $p['basic']['max_teams'],       'duration' => $p['basic']['duration_days'] . ' дней',  'price' => $p['basic']['price'],  'description' => 'До ' . $p['basic']['max_teams'] . ' команд', 'monthly_price' => $p['basic']['price']),
            'standard' => array('name' => 'Стандартный', 'max_teams' => $p['standard']['max_teams'] === -1 ? 'безлимит' : 'до ' . $p['standard']['max_teams'], 'duration' => $p['standard']['duration_days'] . ' дней', 'price' => $p['standard']['price'], 'description' => 'До ' . $p['standard']['max_teams'] . ' команд', 'monthly_price' => $p['standard']['price']),
            'premium'  => array('name' => 'Премиум',    'max_teams' => $p['premium']['max_teams'] === -1 ? 'безлимит' : 'до ' . $p['premium']['max_teams'],    'duration' => $p['premium']['duration_days'] . ' дней', 'price' => $p['premium']['price'],  'description' => 'Неограниченное количество команд', 'monthly_price' => $p['premium']['price']),
            'discounts' => array(
                3  => array('pct' => $d[3]['pct'], 'label' => '3 месяца'),
                6  => array('pct' => $d[6]['pct'], 'label' => '6 месяцев'),
                12 => array('pct' => $d[12]['pct'], 'label' => '12 месяцев'),
            ),
        ));
    }

    // ── Admin Settings GET ──
    elseif ($uri === '/api/admin/settings' && $method === 'GET') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $stmt = $db->prepare("SELECT key, value FROM settings WHERE key LIKE 'plan_%' OR key LIKE 'discount_%' ORDER BY key");
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
        json_success($rows);
    }

    // ── Admin Settings PUT ──
    elseif ($uri === '/api/admin/settings' && $method === 'PUT') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $body = get_body();
        $allowed = array(
            'plan_trial_max_teams', 'plan_trial_duration_days', 'plan_trial_price',
            'plan_basic_max_teams', 'plan_basic_duration_days', 'plan_basic_price',
            'plan_standard_max_teams', 'plan_standard_duration_days', 'plan_standard_price',
            'plan_premium_max_teams', 'plan_premium_duration_days', 'plan_premium_price',
            'discount_3_pct', 'discount_6_pct', 'discount_12_pct',
        );
        $upsert = $db->prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
        foreach ($body as $k => $v) {
            if (in_array($k, $allowed)) $upsert->execute(array($k, (string)$v));
        }
        json_success(array('success' => true));
    }

    // ── Admin Users ──
    elseif ($uri === '/api/admin/users' && $method === 'GET') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $rows = $db->query("
            SELECT u.id, u.email, u.name, u.role, u.created_at, u.blocked_until,
                s.plan, s.status as sub_status, s.expires_at, s.max_teams
            FROM users u
            LEFT JOIN subscriptions s ON s.id = (
                SELECT id FROM subscriptions WHERE user_id = u.id AND status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now')) LIMIT 1
            )
            ORDER BY u.created_at DESC
        ")->fetchAll(PDO::FETCH_ASSOC);
        json_success($rows);
    }

    // ── Admin Stats ──
    elseif ($uri === '/api/admin/stats' && $method === 'GET') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $totalUsers  = $db->query("SELECT COUNT(*) as c FROM users")->fetch(PDO::FETCH_ASSOC)['c'];
        $activeSubs  = $db->query("SELECT COUNT(*) as c FROM subscriptions WHERE status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now'))")->fetch(PDO::FETCH_ASSOC)['c'];
        $trialUsers  = $db->query("SELECT COUNT(*) as c FROM subscriptions WHERE plan = 'trial' AND status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now'))")->fetch(PDO::FETCH_ASSOC)['c'];
        $paidUsers   = $db->query("SELECT COUNT(*) as c FROM subscriptions WHERE plan != 'trial' AND status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now'))")->fetch(PDO::FETCH_ASSOC)['c'];
        $blockedUsers = $db->query("SELECT COUNT(*) as c FROM users WHERE blocked_until IS NOT NULL AND blocked_until >= datetime('now')")->fetch(PDO::FETCH_ASSOC)['c'];
        $totalRevenue = $db->query("SELECT COALESCE(SUM(amount),0) as c FROM payment_history WHERE status = 'completed'")->fetch(PDO::FETCH_ASSOC)['c'];
        $revenueMonth = $db->query("SELECT COALESCE(SUM(amount),0) as c FROM payment_history WHERE status = 'completed' AND created_at >= datetime('now', '-30 days')")->fetch(PDO::FETCH_ASSOC)['c'];
        $planStats   = $db->query("SELECT plan, COUNT(*) as count FROM subscriptions WHERE status = 'active' AND (expires_at IS NULL OR expires_at >= datetime('now')) GROUP BY plan")->fetchAll(PDO::FETCH_ASSOC);
        json_success(array('totalUsers' => $totalUsers, 'activeSubs' => $activeSubs, 'trialUsers' => $trialUsers, 'paidUsers' => $paidUsers, 'blockedUsers' => $blockedUsers, 'totalRevenue' => $totalRevenue, 'revenueMonth' => $revenueMonth, 'planStats' => $planStats));
    }

    // ── Admin Block User ──
    elseif ($uri === '/api/admin/block-user' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $body = get_body();
        $userId = b($body, 'userId');
        $block = !empty($body['block']);
        if (!$userId) json_error('userId обязателен');
        $stmt = $db->prepare('SELECT id, role FROM users WHERE id = ?');
        $stmt->execute(array($userId));
        $target = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$target) json_error('Пользователь не найден', 404);
        if ($target['role'] === 'admin') json_error('Нельзя заблокировать администратора', 403);

        if ($block) {
            $until = date('c', time() + 365 * 24 * 3600);
            $db->prepare('UPDATE users SET blocked_until = ?, updated_at = datetime(\'now\') WHERE id = ?')->execute(array($until, $userId));
            $db->prepare("UPDATE subscriptions SET status = 'expired' WHERE user_id = ? AND status = 'active'")->execute(array($userId));
        } else {
            $db->prepare('UPDATE users SET blocked_until = NULL, updated_at = datetime(\'now\') WHERE id = ?')->execute(array($userId));
        }
        json_success(array('success' => true, 'blocked' => $block));
    }

    // ── Admin Set Plan ──
    elseif ($uri === '/api/admin/set-plan' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $body = get_body();
        $userId = b($body, 'userId');
        $plan = b($body, 'plan');
        if (!$userId || !$plan) json_error('userId и plan обязательны');
        $plans = get_plans($db);
        $discounts = get_discounts($db);
        if (!isset($plans[$plan])) json_error('Неверный план');

        $db->prepare("UPDATE subscriptions SET status = 'cancelled' WHERE user_id = ? AND status = 'active'")->execute(array($userId));

        $subId = uuid_v4();
        $pm = bi($body, 'period_months', 1);
        $months = isset($discounts[$pm]) ? $pm : 1;
        $days = $plans[$plan]['duration_days'] * $months;
        $expiresAt = date('c', time() + $days * 24 * 3600);
        $maxTeams = $plans[$plan]['max_teams'] === -1 ? 999999 : $plans[$plan]['max_teams'];

        $db->prepare('INSERT INTO subscriptions (id, user_id, plan, status, started_at, expires_at, max_teams, period_months) VALUES (?, ?, ?, ?, datetime(\'now\'), ?, ?, ?)')
            ->execute(array($subId, $userId, $plan, 'active', $expiresAt, $maxTeams, $months));

        $db->prepare('UPDATE users SET blocked_until = NULL, updated_at = datetime(\'now\') WHERE id = ?')->execute(array($userId));
        json_success(array('success' => true, 'subscription' => array('plan' => $plan, 'expires_at' => $expiresAt, 'max_teams' => $maxTeams)));
    }

    // ── Admin Set Role ──
    elseif ($uri === '/api/admin/set-role' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $body = get_body();
        $userId = b($body, 'userId');
        $role = b($body, 'role');
        if (!$userId || !$role) json_error('userId и role обязательны');
        if (!in_array($role, array('user', 'admin'))) json_error('Неверная роль');
        $stmt = $db->prepare('SELECT id, role FROM users WHERE id = ?');
        $stmt->execute(array($userId));
        $target = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$target) json_error('Пользователь не найден', 404);
        if ($target['role'] === $role) json_success(array('success' => true));
        if ($target['role'] === 'admin' && $role === 'user') {
            $count = $db->query("SELECT COUNT(*) as c FROM users WHERE role = 'admin'")->fetch(PDO::FETCH_ASSOC)['c'];
            if ($count <= 1) json_error('Нельзя удалить последнего администратора');
        }
        $db->prepare('UPDATE users SET role = ?, updated_at = datetime(\'now\') WHERE id = ?')->execute(array($role, $userId));
        json_success(array('success' => true, 'newRole' => $role));
    }

    // ── Admin Create User ──
    elseif ($uri === '/api/admin/create-user' && $method === 'POST') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $body = get_body();
        $email = trim(b($body, 'email'));
        $password = b($body, 'password');
        $name = trim(b($body, 'name'));
        if (!$email || !$password) json_error('Email и пароль обязательны');
        if (strlen($password) < 6) json_error('Пароль минимум 6 символов');
        $plans = get_plans($db);
        $discounts = get_discounts($db);
        if (isset($body['plan']) && !isset($plans[$body['plan']])) json_error('Неверный план');

        $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute(array($email));
        if ($stmt->fetch()) json_error('Email уже существует', 409);

        $userId = uuid_v4();
        $hash = password_hash($password, PASSWORD_BCRYPT, array('cost' => 10));
        $db->prepare('INSERT INTO users (id, email, password, name, role) VALUES (?, ?, ?, ?, ?)')->execute(array($userId, $email, $hash, $name, 'user'));

        $targetPlan = b($body, 'plan', 'trial');
        $pm = bi($body, 'period_months', 1);
        $months = $targetPlan === 'trial' ? 1 : (isset($discounts[$pm]) ? $pm : 1);
        $days = $plans[$targetPlan]['duration_days'] * $months;
        $expiresAt = date('c', time() + $days * 24 * 3600);
        $maxTeams = $plans[$targetPlan]['max_teams'] === -1 ? 999999 : $plans[$targetPlan]['max_teams'];

        $db->prepare("INSERT INTO subscriptions (id, user_id, plan, status, started_at, expires_at, max_teams, period_months) VALUES (?, ?, ?, 'active', datetime('now'), ?, ?, ?)")
            ->execute(array(uuid_v4(), $userId, $targetPlan, $expiresAt, $maxTeams, $months));

        json_success(array('success' => true, 'user' => array('id' => $userId, 'email' => $email, 'name' => $name), 'plan' => $targetPlan), 201);
    }

    // ── Admin User Detail ──
    elseif (preg_match('#^/api/admin/users/([a-f0-9-]+)$#', $uri, $m) && $method === 'GET') {
        $user = authenticate($db, JWT_SECRET);
        require_admin($user);
        $stmt = $db->prepare('SELECT u.id, u.email, u.name, u.role, u.created_at, u.blocked_until FROM users u WHERE u.id = ?');
        $stmt->execute(array($m[1]));
        $target = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$target) json_error('Пользователь не найден', 404);
        $stmt = $db->prepare('SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute(array($m[1]));
        $subs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $stmt = $db->prepare('SELECT * FROM payment_history WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute(array($m[1]));
        $payments = $stmt->fetchAll(PDO::FETCH_ASSOC);
        json_success(array('user' => $target, 'subscriptions' => $subs, 'payments' => $payments));
    }

    // ── 404 ──
    else {
        http_response_code(404);
        echo json_encode(array('error' => 'Not found'));
    }

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(array('error' => 'Ошибка базы данных', 'detail' => $e->getMessage()));
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(array('error' => 'Ошибка сервера', 'detail' => $e->getMessage()));
}
