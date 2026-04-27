<?php
session_start();
header('Content-Type: application/json');
require_once 'config/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['error' => 'Método no permitido']));
}

$body = json_decode(file_get_contents('php://input'), true);
$email = trim($body['email'] ?? '');
$pwd   = trim($body['pwd']   ?? '');

if (!$email || !$pwd) {
    http_response_code(400);
    exit(json_encode(['error' => 'Campos requeridos']));
}

$db   = getDB();
$stmt = $db->prepare('SELECT id, nombre, password, rol FROM usuarios WHERE email = ? LIMIT 1');
$stmt->execute([$email]);
$user = $stmt->fetch();

if (!$user || !password_verify($pwd, $user['password'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'Credenciales incorrectas']));
}

// Sesión
$_SESSION['uid']    = $user['id'];
$_SESSION['nombre'] = $user['nombre'];
$_SESSION['rol']    = $user['rol'];

exit(json_encode(['ok' => true, 'nombre' => $user['nombre']]));