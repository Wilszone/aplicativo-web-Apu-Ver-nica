<?php
session_start();
require_once '../config/db.php';

// Solo admin puede crear usuarios
if (($_SESSION['rol'] ?? '') !== 'admin') {
    http_response_code(403);
    exit(json_encode(['error' => 'Sin permiso']));
}

header('Content-Type: application/json');
$body   = json_decode(file_get_contents('php://input'), true);
$nombre = trim($body['nombre'] ?? '');
$email  = trim($body['email']  ?? '');
$pwd    = trim($body['pwd']    ?? '');
$rol    = in_array($body['rol'] ?? '', ['admin','staff']) ? $body['rol'] : 'staff';

if (!$nombre || !$email || !$pwd) {
    http_response_code(400);
    exit(json_encode(['error' => 'Todos los campos son requeridos']));
}

$db   = getDB();
$hash = password_hash($pwd, PASSWORD_BCRYPT);

try {
    $stmt = $db->prepare(
        'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)'
    );
    $stmt->execute([$nombre, $email, $hash, $rol]);
    exit(json_encode(['ok' => true, 'id' => $db->lastInsertId()]));
} catch (PDOException $e) {
    http_response_code(409);
    exit(json_encode(['error' => 'El correo ya está registrado']));
}