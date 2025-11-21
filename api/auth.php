<?php
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../lib/util.php';

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

if ($method === 'POST' && $action === 'register') {
    $body = require_json_body();
    $name = sanitize_str($body['name'] ?? '');
    $email = strtolower(sanitize_str($body['email'] ?? ''));
    $password = $body['password'] ?? '';

    if (!$name || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 6) {
        json_response(['error'=>'Invalid input'],400);
    }

    // check existing
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) json_response(['error'=>'Email already registered'],409);

    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)");
    $stmt->execute([$name,$email,$hash]);

    $_SESSION['user_id'] = (int)$pdo->lastInsertId();
    $token = generate_csrf();
    json_response(['message'=>'Registered','user'=>['id'=>$_SESSION['user_id'],'name'=>$name,'email'=>$email],'csrf'=>$token]);
}

if ($method === 'POST' && $action === 'login') {
    $body = require_json_body();
    $email = strtolower(sanitize_str($body['email'] ?? ''));
    $password = $body['password'] ?? '';

    $stmt = $pdo->prepare("SELECT id,name,password_hash FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) json_response(['error'=>'Invalid credentials'],401);

    $_SESSION['user_id'] = (int)$user['id'];
    session_regenerate_id(true);
    $token = generate_csrf();
    json_response(['message'=>'Logged in','user'=>['id'=>$_SESSION['user_id'],'name'=>$user['name'],'email'=>$email],'csrf'=>$token]);
}

if ($method === 'POST' && $action === 'logout') {
    session_unset();
    session_destroy();
    json_response(['message'=>'Logged out']);
}

if ($method === 'GET' && $action === 'me') {
    if (empty($_SESSION['user_id'])) json_response(['user'=>null]);
    $stmt = $pdo->prepare("SELECT id,name,email,role FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $u = $stmt->fetch();
    json_response(['user'=>$u ? ['id'=>(int)$u['id'],'name'=>$u['name'],'email'=>$u['email'],'role'=>$u['role']] : null, 'csrf' => $_SESSION['csrf_token'] ?? null]);
}

json_response(['error'=>'Not found'],404);
