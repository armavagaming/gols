<?php
require_once __DIR__ . '/utils.php';

define('DB_PATH', __DIR__ . '/sboard.db');

$db = new PDO('sqlite:' . DB_PATH);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('PRAGMA journal_mode = WAL');
$db->exec('PRAGMA foreign_keys = ON');

$db->exec("
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    blocked_until TEXT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    plan TEXT NOT NULL CHECK(plan IN ('trial','basic','standard','premium')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','expired','cancelled')),
    started_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT NULL,
    max_teams INTEGER DEFAULT 0,
    period_months INTEGER DEFAULT 1,
    discount REAL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS players (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    team_id TEXT DEFAULT '',
    position TEXT DEFAULT '',
    birth_year INTEGER DEFAULT 0,
    number INTEGER DEFAULT 0,
    photo_path TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payment_history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'BYN',
    plan TEXT NOT NULL,
    period_months INTEGER DEFAULT 1,
    discount REAL DEFAULT 0,
    status TEXT DEFAULT 'completed',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
");

// Default settings
$default_settings = [
    'plan_trial_max_teams' => '9999', 'plan_trial_duration_days' => '7', 'plan_trial_price' => '0',
    'plan_basic_max_teams' => '10', 'plan_basic_duration_days' => '30', 'plan_basic_price' => '22',
    'plan_standard_max_teams' => '30', 'plan_standard_duration_days' => '30', 'plan_standard_price' => '33',
    'plan_premium_max_teams' => '-1', 'plan_premium_duration_days' => '30', 'plan_premium_price' => '44',
    'discount_3_pct' => '15', 'discount_6_pct' => '25', 'discount_12_pct' => '35',
];
$upsert = $db->prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
foreach ($default_settings as $k => $v) $upsert->execute([$k, $v]);

// JWT_SECRET: хранится в БД для консистентности между запросами
$jwtStmt = $db->prepare("SELECT value FROM settings WHERE key = 'jwt_secret'");
$jwtStmt->execute();
$jwtRow = $jwtStmt->fetch(PDO::FETCH_ASSOC);
if ($jwtRow) {
    define('JWT_SECRET', $jwtRow['value']);
} else {
    $secret = 'sb_v2_' . bin2hex(openssl_random_pseudo_bytes(32));
    $db->prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('jwt_secret', ?)")->execute(array($secret));
    define('JWT_SECRET', $secret);
}

// Seed default admin
$adminEmail = 'admin@admin.com';
$adminPass = 'admin';

$existing = $db->prepare("SELECT id, role FROM users WHERE email = ?");
$existing->execute([$adminEmail]);
$existingAdminEmail = $existing->fetch(PDO::FETCH_ASSOC);

$adminExists = $db->prepare("SELECT id FROM users WHERE role = 'admin'");
$adminExists->execute();
$hasAdmin = $adminExists->fetch(PDO::FETCH_ASSOC);

if ($existingAdminEmail && $existingAdminEmail['role'] !== 'admin') {
    $hash = password_hash($adminPass, PASSWORD_BCRYPT, ['cost' => 10]);
    $stmt = $db->prepare("UPDATE users SET role = 'admin', password = ?, name = 'Администратор', blocked_until = NULL, updated_at = datetime('now') WHERE id = ?");
    $stmt->execute([$hash, $existingAdminEmail['id']]);
} elseif (!$existingAdminEmail && !$hasAdmin) {
    $id = uuid_v4();
    $hash = password_hash($adminPass, PASSWORD_BCRYPT, ['cost' => 10]);
    $stmt = $db->prepare('INSERT INTO users (id, email, password, name, role) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$id, $adminEmail, $hash, 'Администратор', 'admin']);
} elseif (!$hasAdmin) {
    $hash = password_hash($adminPass, PASSWORD_BCRYPT, ['cost' => 10]);
    $stmt = $db->prepare("UPDATE users SET role = 'admin', password = ?, name = 'Администратор', blocked_until = NULL, updated_at = datetime('now') WHERE email = ?");
    $stmt->execute([$hash, $adminEmail]);
}
