<?php
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../lib/util.php';

$method = $_SERVER['REQUEST_METHOD'];
$user_id = $_SESSION['user_id'] ?? null;

// GET /api/tickets -> list tickets you created or assigned to
if ($method === 'GET') {
    if (!$user_id) json_response(['error'=>'Unauthorized'],401);
    $stmt = $pdo->prepare("SELECT t.*, u1.name AS author_name, u2.name AS assignee_name
        FROM tickets t
        LEFT JOIN users u1 ON t.created_by = u1.id
        LEFT JOIN users u2 ON t.assigned_to = u2.id
        WHERE t.deleted_at IS NULL AND (t.created_by = ? OR t.assigned_to = ?)
        ORDER BY t.created_at DESC");
    $stmt->execute([$user_id,$user_id]);
    $rows = $stmt->fetchAll();
    json_response(['tickets'=>$rows]);
}

// POST /api/tickets -> create ticket
if ($method === 'POST') {
    if (!$user_id) json_response(['error'=>'Unauthorized'],401);
    // expect multipart/form-data for file upload OR JSON without file
    $title = sanitize_str($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $assigned_to = !empty($_POST['assigned_to']) ? (int)$_POST['assigned_to'] : null;

    if (!$title) json_response(['error'=>'Title required'],400);

    // handle file upload
    $file_path = null;
    if (!empty($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        $allowed = ['image/png','image/jpeg','application/pdf','text/plain'];
        if (!in_array($_FILES['file']['type'],$allowed)) json_response(['error'=>'Invalid file type'],400);
        if ($_FILES['file']['size'] > 5*1024*1024) json_response(['error'=>'File too large'],400);
        $ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
        $safe = bin2hex(random_bytes(12)).'.'.preg_replace('/[^a-z0-9]/i','',$ext);
        $dest = __DIR__ . '/../public/uploads/' . $safe;
        if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) json_response(['error'=>'Failed store file'],500);
        $file_path = 'uploads/'.$safe;
    }

    $stmt = $pdo->prepare("INSERT INTO tickets (title,description,file_path,created_by,assigned_to,assigned_at) VALUES (?,?,?,?,?,NOW())");
    $stmt->execute([$title,$description,$file_path,$user_id,$assigned_to]);
    $ticket_id = (int)$pdo->lastInsertId();
    json_response(['message'=>'Created','id'=>$ticket_id],201);
}

// PUT /api/tickets?id=123 -> update
if ($method === 'PUT') {
    parse_str(file_get_contents("php://input"), $put_vars); // works for urlencoded; for JSON you'd decode
    $id = isset($_GET['id']) ? (int)$_GET['id'] : null;
    if (!$user_id) json_response(['error'=>'Unauthorized'],401);
    if (!$id) json_response(['error'=>'Missing id'],400);

    $stmt = $pdo->prepare("SELECT * FROM tickets WHERE id = ? AND deleted_at IS NULL");
    $stmt->execute([$id]);
    $t = $stmt->fetch();
    if (!$t) json_response(['error'=>'Not found'],404);

    // Who is requesting?
    $is_author = ((int)$t['created_by'] === (int)$user_id);
    $is_assignee = ($t['assigned_to'] !== null && (int)$t['assigned_to'] === (int)$user_id);

    // allow author to update everything; assignee only status
    $allowed_updates = [];
    if ($is_author) {
        // accept title, description, status, assigned_to
        $title = sanitize_str($put_vars['title'] ?? $t['title']);
        $desc = $put_vars['description'] ?? $t['description'];
        $status = $put_vars['status'] ?? $t['status'];
        $assigned_to = isset($put_vars['assigned_to']) ? (int)$put_vars['assigned_to'] : $t['assigned_to'];
        $completed_at = ($status === 'completed') ? date('Y-m-d H:i:s') : null;
        $stmt = $pdo->prepare("UPDATE tickets SET title=?, description=?, status=?, assigned_to=?, updated_at=NOW(), completed_at=? WHERE id=?");
        $stmt->execute([$title,$desc,$status,$assigned_to,$completed_at,$id]);
        json_response(['message'=>'Updated']);
    } elseif ($is_assignee) {
        // only status allowed
        $status = sanitize_str($put_vars['status'] ?? $t['status']);
        if (!in_array($status, ['pending','inprogress','completed','onhold'])) json_response(['error'=>'Invalid status'],400);
        $completed_at = ($status === 'completed') ? date('Y-m-d H:i:s') : null;
        $stmt = $pdo->prepare("UPDATE tickets SET status=?, updated_at=NOW(), completed_at=? WHERE id=?");
        $stmt->execute([$status,$completed_at,$id]);
        json_response(['message'=>'Status updated']);
    } else {
        json_response(['error'=>'Forbidden'],403);
    }
}

// DELETE /api/tickets?id=123 -> soft delete
if ($method === 'DELETE') {
    if (!$user_id) json_response(['error'=>'Unauthorized'],401);
    $id = isset($_GET['id']) ? (int)$_GET['id'] : null;
    if (!$id) json_response(['error'=>'Missing id'],400);
    $stmt = $pdo->prepare("SELECT created_by FROM tickets WHERE id = ? AND deleted_at IS NULL");
    $stmt->execute([$id]);
    $t = $stmt->fetch();
    if (!$t) json_response(['error'=>'Not found'],404);
    if ((int)$t['created_by'] !== (int)$user_id) {
        // only author or admin (simple admin rule omitted here) can delete
        json_response(['error'=>'Forbidden'],403);
    }
    $stmt = $pdo->prepare("UPDATE tickets SET deleted_at = NOW() WHERE id = ?");
    $stmt->execute([$id]);
    json_response(['message'=>'Deleted']);
}

json_response(['error'=>'Method not allowed'],405);
