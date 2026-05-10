<?php session_start(); $lang = $_SESSION['lang'] ?? 'es'; ?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Carta — Apu Verónica</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<?php include 'includes/navbar.php'; ?>

<div class="container py-5 mt-5">
  <h1 class="text-center fw-bold mb-2">Nuestra Carta</h1>
  <p class="text-center text-muted mb-4">
    Cocina peruana y andina elaborada con ingredientes frescos y locales
  </p>

  <!-- FILTROS -->
  <div class="d-flex justify-content-center flex-wrap gap-2 mb-4" id="filtros">
    <button class="btn btn-danger active-filter" data-cat="Todas">Todas</button>
    <button class="btn btn-outline-danger" data-cat="Entradas">Entradas</button>
    <button class="btn btn-outline-danger"
            data-cat="Platos principales">Platos principales</button>
    <button class="btn btn-outline-danger" data-cat="Bebidas">Bebidas</button>
    <button class="btn btn-outline-danger" data-cat="Postres">Postres</button>
  </div>

  <div class="row g-4" id="contenedor-platos">
    <div class="col-12 text-center py-5">
      <div class="spinner-border text-danger" role="status"></div>
      <p class="mt-2 text-muted">Cargando carta...</p>
    </div>
  </div>
</div>

<?php include 'includes/footer.php'; ?>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script src="assets/js/main.js"></script>
<script src="assets/js/carta.js"></script>
</body>
</html>