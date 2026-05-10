<?php
require_once '_auth_check.php';
header('Content-Type: application/json; charset=utf-8');
require_once '../config/db.php';

$body  = json_decode(file_get_contents('php://input'), true);
$accion = $body['accion'] ?? '';
$db    = getDB();

switch ($accion) {

    case 'crear':
        $stmt = $db->prepare(
            'INSERT INTO menu (categoria, nombre, descripcion, precio, activo)
             VALUES (?,?,?,?,?)'
        );
        $stmt->execute([
            $body['categoria'], $body['nombre'],
            $body['descripcion'] ?? '', $body['precio'], $body['activo'] ?? 1
        ]);
        echo json_encode(['ok' => true, 'id' => $db->lastInsertId()]);
        break;

    case 'editar':
        $stmt = $db->prepare(
            'UPDATE menu SET categoria=?, nombre=?, descripcion=?, precio=?, activo=?
             WHERE id=?'
        );
        $stmt->execute([
            $body['categoria'], $body['nombre'],
            $body['descripcion'] ?? '', $body['precio'],
            $body['activo'] ?? 1, $body['id']
        ]);
        echo json_encode(['ok' => true]);
        break;

    case 'eliminar':
        $stmt = $db->prepare('DELETE FROM menu WHERE id=?');
        $stmt->execute([$body['id']]);
        echo json_encode(['ok' => true]);
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Acción no reconocida']);
}