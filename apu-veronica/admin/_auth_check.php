<?php
// Incluir al inicio de CADA archivo en /admin/
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['uid']) || empty($_SESSION['rol'])) {
    header('Location: ../login.html');
    exit();
}

// Solo admin puede acceder (staff tiene acceso limitado)
if ($_SESSION['rol'] !== 'admin') {
    http_response_code(403);
    exit('<p>Acceso denegado. Contacte al administrador.</p>');
}