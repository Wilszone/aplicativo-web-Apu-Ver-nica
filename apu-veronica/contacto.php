<?php
session_start();
$lang = $_SESSION['lang'] ?? 'es';
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Contacto — Apu Verónica</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<?php include 'includes/navbar.php'; ?>

<div class="container py-5 mt-5">
  <h1 class="text-center fw-bold mb-2">Contacto y Ubicación</h1>
  <p class="text-center text-muted mb-5">
    Estamos en el corazón de Ollantaytambo, a 100 m de la Plaza de Armas
  </p>

  <div class="row g-4">

    <!-- INFO DE CONTACTO -->
    <div class="col-md-4">
      <div class="card border-0 shadow-sm h-100 p-4">
        <h5 class="fw-bold mb-4" style="color:#8B1A1A;">📍 Información</h5>

        <div class="mb-4">
          <h6 class="fw-semibold text-dark">Dirección</h6>
          <p class="text-muted small mb-0">
            Calle Ventiderio S/N, 2.° piso<br>
            A 100 m de la Plaza de Armas<br>
            Ollantaytambo, Urubamba, Cusco — Perú
          </p>
        </div>

        <div class="mb-4">
          <h6 class="fw-semibold text-dark">Horario de Atención</h6>
          <p class="text-muted small mb-0">
            🌅 Desayuno: 7:00 a.m. – 10:00 a.m.<br>
            ☀️  Almuerzo: 12:00 p.m. – 3:00 p.m.<br>
            🌙 Cena: 6:00 p.m. – 10:00 p.m.
          </p>
        </div>

        <div class="mb-4">
          <h6 class="fw-semibold text-dark">Redes Sociales</h6>
          <p class="small mb-1">
            <a href="https://instagram.com/apuveronicarestaurantgrill"
               class="text-decoration-none" target="_blank"
               style="color:#8B1A1A;">
              📷 @apuveronicarestaurantgrill
            </a>
          </p>
          <p class="small mb-0">
            <a href="https://facebook.com" class="text-decoration-none text-dark"
               target="_blank">
              👥 Restaurant Apu Veronica
            </a>
          </p>
        </div>

        <div>
          <h6 class="fw-semibold text-dark">Plataformas de Reseñas</h6>
          <p class="small mb-0">
            <a href="https://www.tripadvisor.com/Restaurant_Review-g294319-d10618512"
               class="text-decoration-none" target="_blank" style="color:#00AF87;">
              🟢 TripAdvisor — Apu Veronica Restaurant
            </a>
          </p>
        </div>
      </div>
    </div>

    <!-- MAPA GOOGLE -->
    <div class="col-md-8">
      <div class="card border-0 shadow-sm h-100 overflow-hidden">
        <iframe
          src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3751.3!2d-72.2636!3d-13.2590!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x916e418b5e4c5ab1%3A0x1234567890abcdef!2sOllantaytambo%2C%20Urubamba%2C%20Cusco!5e0!3m2!1ses!2spe!4v1620000000000"
          width="100%"
          height="450"
          style="border:0;"
          allowfullscreen=""
          loading="lazy"
          referrerpolicy="no-referrer-when-downgrade"
          title="Ubicación Apu Verónica Restaurant — Ollantaytambo">
        </iframe>
      </div>
    </div>

  </div>

  <!-- CÓMO LLEGAR -->
  <div class="card border-0 shadow-sm mt-4 p-4">
    <h5 class="fw-bold mb-3" style="color:#1F3864;">🚌 ¿Cómo Llegar?</h5>
    <div class="row g-3">
      <div class="col-md-4">
        <h6 class="fw-semibold">Desde Cusco</h6>
        <p class="text-muted small">
          Bus o combi desde el Terminal Terrestre de Cusco hacia Ollantaytambo
          (aprox. 1h 30 min). Taxi desde S/ 60. Al llegar, caminamos 2 minutos
          desde la Plaza de Armas hacia la calle Ventiderio.
        </p>
      </div>
      <div class="col-md-4">
        <h6 class="fw-semibold">Desde Machu Picchu</h6>
        <p class="text-muted small">
          Tren Machu Picchu → Ollantaytambo (45 min aprox. con PeruRail o
          Inca Rail). La estación queda a 10 min a pie del restaurante.
          ¡Perfecta parada en tu viaje de regreso!
        </p>
      </div>
      <div class="col-md-4">
        <h6 class="fw-semibold">En Ollantaytambo</h6>
        <p class="text-muted small">
          Desde la Plaza de Armas, tomar la calle principal hacia el norte
          100 metros. El restaurante se encuentra en el segundo piso, con
          vista privilegiada a las ruinas.
        </p>
      </div>
    </div>
  </div>
</div>

<?php include 'includes/footer.php'; ?>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script src="assets/js/main.js"></script>
</body>
</html>