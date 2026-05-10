<?php
header('Content-Type: application/json; charset=utf-8');
require_once '../config/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['error' => 'Método no permitido']));
}

$body    = json_decode(file_get_contents('php://input'), true);
$cliente = trim($body['cliente']  ?? '');
$email   = trim($body['email']    ?? '');
$tel     = trim($body['telefono'] ?? '');
$fecha   = trim($body['fecha']    ?? '');
$hora    = trim($body['hora']     ?? '');
$personas = (int)($body['personas'] ?? 0);

// Validaciones del servidor
if (!$cliente || !$email || !$fecha || !$hora || $personas < 1) {
    http_response_code(400);
    exit(json_encode(['error' => 'Faltan campos requeridos']));
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit(json_encode(['error' => 'Correo electrónico inválido']));
}

if ($fecha < date('Y-m-d')) {
    http_response_code(400);
    exit(json_encode(['error' => 'La fecha debe ser igual o posterior a hoy']));
}

try {
    $db   = getDB();
    $stmt = $db->prepare(
        'INSERT INTO reservas (cliente, email, telefono, fecha, hora, personas)
         VALUES (?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([$cliente, $email, $tel, $fecha, $hora, $personas]);
    $id = $db->lastInsertId();

    exit(json_encode([
        'ok'      => true,
        'id'      => $id,
        'mensaje' => "Reserva registrada exitosamente. Su código es: #$id"
    ]));

} catch (PDOException $e) {
    http_response_code(500);
    exit(json_encode(['error' => 'Error al registrar la reserva']));
}