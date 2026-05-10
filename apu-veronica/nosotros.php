<?php
session_start();
$lang = $_SESSION['lang'] ?? 'es';
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nosotros — Apu Verónica</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<?php include 'includes/navbar.php'; ?>

<!-- HERO NOSOTROS -->
<section class="py-5 mt-5 text-white text-center"
         style="background: linear-gradient(135deg, #1F3864 0%, #8B1A1A 100%);">
  <div class="container py-3">
    <h1 class="display-5 fw-bold mb-2">Nuestra Historia</h1>
    <p class="lead opacity-75">
      Una familia, una pasión: la cocina andina auténtica
    </p>
  </div>
</section>

<!-- DESCRIPCIÓN -->
<section class="py-5">
  <div class="container">
    <div class="row align-items-center g-5">
      <div class="col-md-6">
        <h2 class="fw-bold mb-3" style="color:#8B1A1A;">¿Quiénes Somos?</h2>
        <p class="text-muted lh-lg">
          <strong>Apu Verónica Restaurant</strong> es un establecimiento familiar de gastronomía
          peruana y andina ubicado en la calle Ventiderio S/N, segundo piso, a 100 metros de la
          Plaza de Armas de Ollantaytambo, provincia de Urubamba, región Cusco.
        </p>
        <p class="text-muted lh-lg">
          Operamos como microempresa familiar orientada al segmento turístico nacional e
          internacional, ofreciendo una carta diversificada con platos tradicionales elaborados
          con insumos frescos, locales y orgánicos, combinando técnicas culinarias andinas con
          presentación contemporánea.
        </p>
        <p class="text-muted lh-lg">
          Entre nuestros platos emblemáticos destacan la trucha a la parrilla, anticuchos de
          alpaca, ceviche de trucha, sopas andinas y opciones vegetarianas y veganas, servidos
          en piedra volcánica como símbolo de nuestra identidad cultural.
        </p>
      </div>
      <div class="col-md-6 text-center">
        <div class="display-1 mb-3">🏔</div>
        <div class="bg-light rounded p-4">
          <h5 class="fw-bold mb-1" style="color:#1F3864;">Apu Verónica</h5>
          <p class="text-muted small mb-0">
            El Apu Verónica es uno de los nevados tutelares que custodian<br>
            el Valle Sagrado. Su nombre es nuestra inspiración y compromiso<br>
            con la tierra, la cultura y la gastronomía andina.
          </p>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- MISIÓN Y VISIÓN -->
<section class="py-5 bg-light">
  <div class="container">
    <h2 class="text-center fw-bold mb-5">Misión y Visión</h2>
    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100 border-0 shadow-sm p-4">
          <div class="fs-1 text-center mb-3">🎯</div>
          <h4 class="fw-bold text-center mb-3" style="color:#8B1A1A;">Misión</h4>
          <p class="text-muted text-center lh-lg">
            Brindar una experiencia gastronómica auténtica y memorable, ofreciendo platos de
            cocina peruana y andina elaborados con insumos frescos y locales, en un ambiente
            cálido que refleje la identidad cultural de Ollantaytambo.
          </p>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card h-100 border-0 shadow-sm p-4">
          <div class="fs-1 text-center mb-3">🚀</div>
          <h4 class="fw-bold text-center mb-3" style="color:#1F3864;">Visión</h4>
          <p class="text-muted text-center lh-lg">
            Ser reconocido como el restaurante de referencia del Valle Sagrado, destacando por
            la calidad, la innovación culinaria y el uso responsable de insumos locales,
            expandiendo su alcance mediante tecnología digital al mercado turístico nacional
            e internacional.
          </p>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- VALORES -->
<section class="py-5">
  <div class="container">
    <h2 class="text-center fw-bold mb-5">Nuestros Valores</h2>
    <div class="row g-4 text-center">
      <?php
      $valores = [
        ['🌿','Autenticidad','Recetas tradicionales transmitidas de generación en generación.'],
        ['🤝','Hospitalidad','Atención cálida y personalizada para cada visitante.'],
        ['♻️','Sostenibilidad','Uso responsable de insumos locales y orgánicos del Valle Sagrado.'],
        ['⭐','Excelencia','Estándares de calidad en cada plato y en cada servicio.'],
      ];
      foreach ($valores as $v): ?>
      <div class="col-6 col-md-3">
        <div class="p-3">
          <div class="fs-1 mb-2"><?= $v[0] ?></div>
          <h6 class="fw-bold"><?= $v[1] ?></h6>
          <p class="text-muted small"><?= $v[2] ?></p>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
</section>

<?php include 'includes/footer.php'; ?>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script src="assets/js/main.js"></script>
</body>
</html>