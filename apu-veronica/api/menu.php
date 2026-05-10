<?php
header('Content-Type: application/json; charset=utf-8');
require_once '../config/db.php';

$db  = getDB();
$cat = $_GET['categoria'] ?? null;

if ($cat && $cat !== 'Todas') {
    $stmt = $db->prepare(
        'SELECT id, categoria, nombre, descripcion, precio, imagen
         FROM menu WHERE activo = 1 AND categoria = ?
         ORDER BY nombre'
    );
    $stmt->execute([$cat]);
} else {
    $stmt = $db->prepare(
        'SELECT id, categoria, nombre, descripcion, precio, imagen
         FROM menu WHERE activo = 1
         ORDER BY FIELD(categoria,"Entradas","Platos principales","Bebidas","Postres"), nombre'
    );
    $stmt->execute();
}

echo json_encode([
    'ok'    => true,
    'data'  => $stmt->fetchAll(),
    'total' => $stmt->rowCount()
]);