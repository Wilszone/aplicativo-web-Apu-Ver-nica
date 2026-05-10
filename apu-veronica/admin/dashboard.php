<?php
require_once '_auth_check.php';
require_once '../config/db.php';

$db = getDB();

// Estadísticas dinámicas
$totalPendientes = $db->query(
    "SELECT COUNT(*) FROM reservas WHERE estado='pendiente'")->fetchColumn();
$totalHoy        = $db->query(
    "SELECT COUNT(*) FROM reservas WHERE fecha=CURDATE()")->fetchColumn();
$totalPlatosAct  = $db->query(
    "SELECT COUNT(*) FROM menu WHERE activo=1")->fetchColumn();
$ultimasReservas = $db->query(
    "SELECT * FROM reservas ORDER BY created DESC LIMIT 10")->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard — Apu Verónica Admin</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="../assets/css/admin.css">
</head>
<body class="bg-light">

<div class="d-flex">
  <!-- SIDEBAR -->
  <nav class="sidebar bg-dark text-white p-3"
       style="min-height:100vh; width:220px; position:fixed;">
    <h6 class="fw-bold text-warning mb-4">🏔 Apu Verónica</h6>
    <ul class="nav flex-column gap-1">
      <li><a href="dashboard.php"
             class="nav-link text-white active">📊 Dashboard</a></li>
      <li><a href="menu.php"       class="nav-link text-white-50">🍽️ Menú</a></li>
      <li><a href="reservas.php"   class="nav-link text-white-50">📅 Reservas</a></li>
      <li><a href="galeria.php"    class="nav-link text-white-50">🖼️ Galería</a></li>
      <li><a href="usuarios.php"   class="nav-link text-white-50">👥 Usuarios</a></li>
      <li class="mt-4">
        <a href="../logout.php" class="nav-link text-danger">🚪 Cerrar Sesión</a>
      </li>
    </ul>
  </nav>

  <!-- CONTENIDO PRINCIPAL -->
  <main class="ms-auto p-4" style="margin-left:220px; width:calc(100% - 220px);">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h4 class="fw-bold mb-0">Dashboard</h4>
      <span class="text-muted small">
        Bienvenido, <strong><?= htmlspecialchars($_SESSION['nombre']) ?></strong>
      </span>
    </div>

    <!-- TARJETAS ESTADÍSTICAS -->
    <div class="row g-3 mb-4">
      <div class="col-md-4">
        <div class="card border-0 shadow-sm text-center p-3">
          <div class="fs-1">⏳</div>
          <div class="display-6 fw-bold text-warning"><?= $totalPendientes ?></div>
          <p class="text-muted small mb-0">Reservas Pendientes</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card border-0 shadow-sm text-center p-3">
          <div class="fs-1">📅</div>
          <div class="display-6 fw-bold text-primary"><?= $totalHoy ?></div>
          <p class="text-muted small mb-0">Reservas Hoy</p>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card border-0 shadow-sm text-center p-3">
          <div class="fs-1">🍽️</div>
          <div class="display-6 fw-bold text-success"><?= $totalPlatosAct ?></div>
          <p class="text-muted small mb-0">Platos Activos</p>
        </div>
      </div>
    </div>

    <!-- TABLA ÚLTIMAS RESERVAS -->
    <div class="card border-0 shadow-sm">
      <div class="card-header bg-white fw-bold border-0 pt-3">
        📋 Últimas Reservas
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-hover mb-0">
            <thead class="table-light">
              <tr>
                <th>#</th><th>Cliente</th><th>Fecha</th>
                <th>Hora</th><th>Personas</th><th>Estado</th><th>Acción</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($ultimasReservas as $r): ?>
              <tr>
                <td><?= $r['id'] ?></td>
                <td>
                  <?= htmlspecialchars($r['cliente']) ?><br>
                  <small class="text-muted"><?= htmlspecialchars($r['email']) ?></small>
                </td>
                <td><?= $r['fecha'] ?></td>
                <td><?= substr($r['hora'], 0, 5) ?></td>
                <td class="text-center"><?= $r['personas'] ?></td>
                <td>
                  <?php
                  $badges = [
                    'pendiente'  => 'warning',
                    'confirmada' => 'success',
                    'cancelada'  => 'danger',
                  ];
                  $b = $badges[$r['estado']] ?? 'secondary';
                  ?>
                  <span class="badge bg-<?= $b ?>">
                    <?= ucfirst($r['estado']) ?>
                  </span>
                </td>
                <td>
                  <?php if ($r['estado'] === 'pendiente'): ?>
                  <button class="btn btn-sm btn-success me-1"
                          onclick="cambiarEstado(<?= $r['id'] ?>,'confirmada')">✓</button>
                  <button class="btn btn-sm btn-danger"
                          onclick="cambiarEstado(<?= $r['id'] ?>,'cancelada')">✗</button>
                  <?php endif; ?>
                </td>
              </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </main>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script>
async function cambiarEstado(id, estado) {
    if (!confirm(`¿Cambiar reserva #${id} a "${estado}"?`)) return;
    const res  = await fetch('api_reservas.php', {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify({ accion: 'cambiar_estado', id, estado })
    });
    const data = await res.json();
    if (data.ok) location.reload();
    else alert('Error: ' + data.error);
}
</script>
</body>
</html>