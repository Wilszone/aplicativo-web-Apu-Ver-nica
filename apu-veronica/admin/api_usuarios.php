<?php
require_once '_auth_check.php';
header('Content-Type: application/json; charset=utf-8');
require_once '../config/db.php';

$body   = json_decode(file_get_contents('php://input'), true);
$accion = $body['accion'] ?? '';
$db     = getDB();

if ($accion === 'eliminar') {
    $id = (int)($body['id'] ?? 0);

    // Restricción: no puede eliminarse a sí mismo
    if ($id === (int)$_SESSION['uid']) {
        http_response_code(403);
        exit(json_encode(['error' => 'No puede eliminar su propia cuenta']));
    }

    $stmt = $db->prepare('DELETE FROM usuarios WHERE id = ?');
    $stmt->execute([$id]);
    echo json_encode(['ok' => true]);

} else {
    http_response_code(400);
    echo json_encode(['error' => 'Acción no reconocida']);
}