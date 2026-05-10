<?php
session_start();
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    $lang = in_array($body['lang'] ?? '', ['es', 'en']) ? $body['lang'] : 'es';
    $_SESSION['lang'] = $lang;
    echo json_encode(['ok' => true, 'lang' => $lang]);
    exit();
}

$lang = $_SESSION['lang'] ?? 'es';
$file = __DIR__ . "/../lang/{$lang}.json";
echo file_exists($file) ? file_get_contents($file) : json_encode([]);