<?php
session_start();
$lang = $_SESSION['lang'] ?? 'es';
require_once 'config/db.php';

$db   = getDB();
$stmt = $db->prepare("SELECT * FROM menu WHERE activo = 1 ORDER BY RAND() LIMIT 3");
$stmt->execute();
$destacados = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description"
        content="Restaurante Apu Verónica — Gastronomía peruana y andina en Ollantaytambo, Cusco.">
  <title>Apu Verónica Restaurant — Ollantaytambo, Cusco</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
  <div class="container">
    <a class="navbar-brand fw-bold" href="index.php">🏔 Apu Verónica</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse"
            data-bs-target="#navMenu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navMenu">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="carta.php">Carta</a></li>
        <li class="nav-item"><a class="nav-link" href="galeria.php">Galería</a></li>
        <li class="nav-item"><a class="nav-link" href="nosotros.php">Nosotros</a></li>
        <li class="nav-item"><a class="nav-link" href="contacto.php">Contacto</a></li>
      </ul>
      <div class="d-flex align-items-center gap-2">
        <button class="btn btn-sm btn-outline-light"
                onclick="cambiarIdioma('es')">ES</button>
        <button class="btn btn-sm btn-outline-light"
                onclick="cambiarIdioma('en')">EN</button>
        <a href="reservas.php" class="btn btn-danger fw-bold">Reservar Mesa</a>
      </div>
    </div>
  </div>
</nav>

<!-- HERO -->
<section class="hero-section text-white text-center d-flex align-items-center"
         style="min-height:100vh;
                background:linear-gradient(rgba(0,0,0,.55),rgba(0,0,0,.55)),
                url('assets/img/hero.jpg') center/cover no-repeat;">
  <div class="container py-5">
    <h1 class="display-3 fw-bold mb-3">Sabores Auténticos del Valle Sagrado</h1>
    <p class="lead mb-4">
      Gastronomía peruana y andina en el corazón de Ollantaytambo
    </p>
    <div class="d-flex justify-content-center gap-3 flex-wrap">
      <a href="carta.php"    class="btn btn-outline-light btn-lg">Ver Carta</a>
      <a href="reservas.php" class="btn btn-danger btn-lg">Reservar Mesa</a>
    </div>
  </div>
</section>

<!-- PLATOS DESTACADOS -->
<section class="py-5 bg-light">
  <div class="container">
    <h2 class="text-center mb-4 fw-bold">Platos Destacados</h2>
    <div class="row g-4">
      <?php foreach ($destacados as $p): ?>
      <div class="col-md-4">
        <div class="card h-100 shadow-sm border-0">
          <div class="card-body">
            <span class="badge bg-danger mb-2">
              <?= htmlspecialchars($p['categoria']) ?>
            </span>
            <h5 class="card-title"><?= htmlspecialchars($p['nombre']) ?></h5>
            <p class="card-text text-muted small">
              <?= htmlspecialchars($p['descripcion']) ?>
            </p>
            <p class="fw-bold text-danger fs-5">
              S/ <?= number_format($p['precio'], 2) ?>
            </p>
          </div>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
    <div class="text-center mt-4">
      <a href="carta.php" class="btn btn-outline-danger btn-lg">Ver Carta Completa</a>
    </div>
  </div>
</section>

<!-- FOOTER -->
<footer class="bg-dark text-white py-4">
  <div class="container">
    <div class="row">
      <div class="col-md-4">
        <h6 class="fw-bold">🏔 Apu Verónica Restaurant</h6>
        <p class="small text-muted">
          Calle Ventiderio S/N, 2.° piso<br>
          A 100 m de la Plaza de Armas<br>
          Ollantaytambo, Urubamba, Cusco
        </p>
      </div>
      <div class="col-md-4">
        <h6 class="fw-bold">Horario</h6>
        <p class="small text-muted">Desayuno, Almuerzo y Cena<br>Hasta las 10:00 p.m.</p>
      </div>
      <div class="col-md-4">
        <h6 class="fw-bold">Redes Sociales</h6>
        <p class="small">
          <a href="https://instagram.com/apuveronicarestaurantgrill"
             class="text-white" target="_blank">
            📷 @apuveronicarestaurantgrill
          </a><br>
          <a href="#" class="text-white">👥 Restaurant Apu Veronica</a>
        </p>
        <a href="login.html" class="small text-muted">Admin</a>
      </div>
    </div>
    <hr class="border-secondary">
    <p class="text-center text-muted small mb-0">
      &copy; 2026 Apu Verónica Restaurant. Todos los derechos reservados.
    </p>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script src="assets/js/main.js"></script>
</body>
</html>