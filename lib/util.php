<?php
// lib/util.php
session_start();
header('Content-Type: application/json');

function json_response($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data);
    exit;
}

function require_json_body(): array {
    $body = json_decode(file_get_contents('php://input'), true);
    if (!is_array($body)) json_response(['error'=>'Invalid JSON body'],400);
    return $body;
}

function sanitize_str($s) {
    return trim(strip_tags((string)$s));
}

function require_auth() {
    if (empty($_SESSION['user_id'])) json_response(['error'=>'Unauthorized'],401);
    return (int)$_SESSION['user_id'];
}

function generate_csrf() {
    if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}
function verify_csrf($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], (string)$token);
}
