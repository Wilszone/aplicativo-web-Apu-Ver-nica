<?php session_start(); $lang = $_SESSION['lang'] ?? 'es'; ?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reservas — Apu Verónica</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<?php include 'includes/navbar.php'; ?>

<div class="container py-5 mt-5" style="max-width:640px;">
  <h1 class="text-center fw-bold mb-2">Reservar Mesa</h1>
  <p class="text-center text-muted mb-4">
    Complete el formulario y confirmaremos su reserva a la brevedad
  </p>

  <div id="alerta" class="alert d-none" role="alert"></div>

  <div class="card shadow-sm border-0 p-4">
    <div class="mb-3">
      <label class="form-label fw-semibold">Nombre completo *</label>
      <input type="text" id="r_nombre" class="form-control"
             required placeholder="Ej: María García">
    </div>
    <div class="mb-3">
      <label class="form-label fw-semibold">Correo electrónico *</label>
      <input type="email" id="r_email" class="form-control"
             required placeholder="correo@ejemplo.com">
    </div>
    <div class="mb-3">
      <label class="form-label fw-semibold">Teléfono</label>
      <input type="tel" id="r_telefono" class="form-control"
             placeholder="+51 984 000 000">
    </div>
    <div class="row">
      <div class="col-sm-6 mb-3">
        <label class="form-label fw-semibold">Fecha *</label>
        <input type="date" id="r_fecha" class="form-control" required>
      </div>
      <div class="col-sm-6 mb-3">
        <label class="form-label fw-semibold">Hora *</label>
        <select id="r_hora" class="form-select" required>
          <option value="">Seleccionar...</option>
          <option>08:00</option><option>08:30</option>
          <option>12:00</option><option>12:30</option>
          <option>13:00</option><option>13:30</option>
          <option>14:00</option><option>19:00</option>
          <option>19:30</option><option>20:00</option>
          <option>20:30</option><option>21:00</option>
        </select>
      </div>
    </div>
    <div class="mb-3">
      <label class="form-label fw-semibold">Número de personas *</label>
      <input type="number" id="r_personas" class="form-control"
             min="1" max="20" value="2" required>
    </div>
    <button type="button" id="btnReservar"
            class="btn btn-danger btn-lg w-100 fw-bold">
      Confirmar Reserva
    </button>
  </div>
</div>

<?php include 'includes/footer.php'; ?>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script src="assets/js/main.js"></script>
<script src="assets/js/reservas.js"></script>
</body>
</html>