<?php
require_once '_auth_check.php';
header('Content-Type: application/json; charset=utf-8');
require_once '../config/db.php';

$body   = json_decode(file_get_contents('php://input'), true);
$accion = $body['accion'] ?? '';
$db     = getDB();

if ($accion === 'cambiar_estado') {
    $estadosValidos = ['confirmada', 'cancelada', 'pendiente'];
    if (!in_array($body['estado'], $estadosValidos, true)) {
        http_response_code(400);
        exit(json_encode(['error' => 'Estado inválido']));
    }
    $stmt = $db->prepare('UPDATE reservas SET estado=? WHERE id=?');
    $stmt->execute([$body['estado'], $body['id']]);
    echo json_encode(['ok' => true]);
} else {
    http_response_code(400);
    echo json_encode(['error' => 'Acción no reconocida']);
}