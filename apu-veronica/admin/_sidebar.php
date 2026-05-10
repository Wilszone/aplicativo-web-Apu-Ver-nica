<?php
// Determinar página activa para resaltar en el menú
$paginaActual = basename($_SERVER['PHP_SELF']);
$activo = function(string $pagina) use ($paginaActual): string {
    return str_contains($paginaActual, $pagina) ? 'text-white' : 'text-white-50';
};
?>
<nav class="sidebar bg-dark text-white p-3"
     style="min-height:100vh; width:220px; position:fixed; top:0; left:0; z-index:100;">
  <h6 class="fw-bold text-warning mb-1">🏔 Apu Verónica</h6>
  <p class="text-muted small mb-4">Panel de Administración</p>

  <ul class="nav flex-column gap-1">
    <li>
      <a href="dashboard.php"
         class="nav-link <?= $activo('dashboard') ?>">
        📊 Dashboard
      </a>
    </li>
    <li>
      <a href="menu.php"
         class="nav-link <?= $activo('menu') ?>">
        🍽️ Gestión de Menú
      </a>
    </li>
    <li>
      <a href="reservas.php"
         class="nav-link <?= $activo('reservas') ?>">
        📅 Reservas
      </a>
    </li>
    <li>
      <a href="galeria.php"
         class="nav-link <?= $activo('galeria') ?>">
        🖼️ Galería
      </a>
    </li>
    <li>
      <a href="usuarios.php"
         class="nav-link <?= $activo('usuarios') ?>">
        👥 Usuarios
      </a>
    </li>
  </ul>

  <hr class="border-secondary mt-4">

  <div class="small text-muted mb-2">
    <strong class="text-white">
      <?= htmlspecialchars($_SESSION['nombre']) ?>
    </strong><br>
    Rol: <?= ucfirst($_SESSION['rol']) ?>
  </div>

  <a href="../logout.php" class="btn btn-sm btn-outline-danger w-100">
    🚪 Cerrar Sesión
  </a>
</nav>