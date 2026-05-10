<?php
session_start();
$lang = $_SESSION['lang'] ?? 'es';
require_once 'config/db.php';

$db    = getDB();
$stmt  = $db->prepare(
    "SELECT * FROM galeria WHERE activo = 1 ORDER BY orden ASC, id DESC"
);
$stmt->execute();
$fotos = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Galería — Apu Verónica</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/css/style.css">
  <style>
    .galeria-img {
      width: 100%;
      height: 220px;
      object-fit: cover;
      border-radius: 8px;
      transition: transform .3s, box-shadow .3s;
      cursor: pointer;
    }
    .galeria-img:hover {
      transform: scale(1.04);
      box-shadow: 0 8px 24px rgba(0,0,0,.25);
    }
  </style>
</head>
<body>
<?php include 'includes/navbar.php'; ?>

<div class="container py-5 mt-5">
  <h1 class="text-center fw-bold mb-2">Galería</h1>
  <p class="text-center text-muted mb-5">
    Descubre nuestros platos, ambiente y la magia del Valle Sagrado
  </p>

  <?php if (empty($fotos)): ?>
    <p class="text-center text-muted py-5">
      La galería estará disponible próximamente.
    </p>
  <?php else: ?>
  <div class="row g-3">
    <?php foreach ($fotos as $f): ?>
    <div class="col-6 col-md-4 col-lg-3">
      <img src="assets/img/galeria/<?= htmlspecialchars($f['archivo']) ?>"
           alt="<?= htmlspecialchars($f['titulo'] ?? 'Apu Verónica') ?>"
           class="galeria-img"
           data-bs-toggle="modal"
           data-bs-target="#modalFoto"
           data-src="assets/img/galeria/<?= htmlspecialchars($f['archivo']) ?>"
           data-titulo="<?= htmlspecialchars($f['titulo'] ?? '') ?>">
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>
</div>

<!-- MODAL LIGHTBOX -->
<div class="modal fade" id="modalFoto" tabindex="-1">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content bg-dark border-0">
      <div class="modal-header border-0 pb-0">
        <h6 class="modal-title text-white" id="tituloFoto"></h6>
        <button type="button" class="btn-close btn-close-white"
                data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body text-center">
        <img id="fotoAmpliada" src="" alt="" class="img-fluid rounded">
      </div>
    </div>
  </div>
</div>

<?php include 'includes/footer.php'; ?>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script>
// Lightbox dinámico
document.querySelectorAll('.galeria-img').forEach(img => {
    img.addEventListener('click', () => {
        document.getElementById('fotoAmpliada').src    = img.dataset.src;
        document.getElementById('tituloFoto').textContent = img.dataset.titulo;
    });
});
</script>
</body>
</html>