<?php
require_once '_auth_check.php';
header('Content-Type: application/json; charset=utf-8');
require_once '../config/db.php';

$db = getDB();

// ── SUBIDA DE IMAGEN (multipart/form-data) ────────────────────────────────
if (isset($_FILES['archivo'])) {
    $archivo  = $_FILES['archivo'];
    $titulo   = trim($_POST['titulo'] ?? '');

    // Validar error de subida PHP
    if ($archivo['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        exit(json_encode(['error' => 'Error en la subida del archivo']));
    }

    // Tamaño máximo: 2 MB
    if ($archivo['size'] > 2 * 1024 * 1024) {
        http_response_code(400);
        exit(json_encode(['error' => 'El archivo supera el tamaño máximo de 2 MB']));
    }

    // Verificar MIME real con finfo (no confiar en extensión del cliente)
    $finfo     = new finfo(FILEINFO_MIME_TYPE);
    $mimeReal  = $finfo->file($archivo['tmp_name']);
    $mimesPermitidos = ['image/jpeg', 'image/png', 'image/webp'];

    if (!in_array($mimeReal, $mimesPermitidos, true)) {
        http_response_code(400);
        exit(json_encode(['error' => 'Tipo de archivo no permitido (solo JPG, PNG, WebP)']));
    }

    // Generar nombre seguro con extensión real
    $extensiones = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
    ];
    $ext         = $extensiones[$mimeReal];
    $nombreFinal = uniqid('galeria_', true) . '.' . $ext;
    $destino     = __DIR__ . '/../assets/img/galeria/' . $nombreFinal;

    if (!move_uploaded_file($archivo['tmp_name'], $destino)) {
        http_response_code(500);
        exit(json_encode(['error' => 'No se pudo guardar el archivo en el servidor']));
    }

    $stmt = $db->prepare(
        'INSERT INTO galeria (titulo, archivo, activo) VALUES (?, ?, 1)'
    );
    $stmt->execute([$titulo ?: null, $nombreFinal]);

    exit(json_encode(['ok' => true, 'id' => $db->lastInsertId()]));
}

// ── OPERACIONES JSON (toggle / eliminar) ──────────────────────────────────
$body   = json_decode(file_get_contents('php://input'), true);
$accion = $body['accion'] ?? '';

switch ($accion) {

    case 'toggle':
        $stmt = $db->prepare('UPDATE galeria SET activo = ? WHERE id = ?');
        $stmt->execute([$body['activo'], $body['id']]);
        echo json_encode(['ok' => true]);
        break;

    case 'eliminar':
        // Obtener nombre de archivo antes de borrar
        $stmt = $db->prepare('SELECT archivo FROM galeria WHERE id = ?');
        $stmt->execute([$body['id']]);
        $fila = $stmt->fetch();

        if ($fila) {
            $rutaFisica = __DIR__ . '/../assets/img/galeria/' . $fila['archivo'];
            if (file_exists($rutaFisica)) {
                unlink($rutaFisica); // Eliminar archivo físico
            }
        }

        $stmt = $db->prepare('DELETE FROM galeria WHERE id = ?');
        $stmt->execute([$body['id']]);
        echo json_encode(['ok' => true]);
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'Acción no reconocida']);
}