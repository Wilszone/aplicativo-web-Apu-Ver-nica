<?php
$paginaActual = basename($_SERVER['PHP_SELF']);
?>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
  <div class="container">
    <a class="navbar-brand fw-bold" href="/apu-veronica/index.php">
      🏔 Apu Verónica
    </a>
    <button class="navbar-toggler" type="button"
            data-bs-toggle="collapse" data-bs-target="#navMenu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navMenu">
      <ul class="navbar-nav me-auto">
        <li class="nav-item">
          <a class="nav-link <?= $paginaActual==='carta.php' ? 'active':'' ?>"
             href="/apu-veronica/carta.php">Carta</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?= $paginaActual==='galeria.php' ? 'active':'' ?>"
             href="/apu-veronica/galeria.php">Galería</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?= $paginaActual==='nosotros.php' ? 'active':'' ?>"
             href="/apu-veronica/nosotros.php">Nosotros</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?= $paginaActual==='contacto.php' ? 'active':'' ?>"
             href="/apu-veronica/contacto.php">Contacto</a>
        </li>
      </ul>
      <div class="d-flex align-items-center gap-2">
        <button class="btn btn-sm btn-outline-light"
                onclick="cambiarIdioma('es')">ES</button>
        <button class="btn btn-sm btn-outline-light"
                onclick="cambiarIdioma('en')">EN</button>
        <a href="/apu-veronica/reservas.php"
           class="btn btn-danger fw-bold">Reservar Mesa</a>
      </div>
    </div>
  </div>
</nav>