<?php
require_once '_auth_check.php';
require_once '../config/db.php';

$db = getDB();

// Filtros GET
$filtroEstado = $_GET['estado'] ?? 'todos';
$filtroFecha  = $_GET['fecha']  ?? '';

$sql    = "SELECT * FROM reservas WHERE 1=1";
$params = [];

if ($filtroEstado !== 'todos') {
    $sql    .= " AND estado = ?";
    $params[] = $filtroEstado;
}
if ($filtroFecha) {
    $sql    .= " AND fecha = ?";
    $params[] = $filtroFecha;
}
$sql .= " ORDER BY created DESC";

$stmt = $db->prepare($sql);
$stmt->execute($params);
$reservas = $stmt->fetchAll();

// Contadores por estado
$contadores = $db->query(
    "SELECT estado, COUNT(*) as total FROM reservas GROUP BY estado"
)->fetchAll(PDO::FETCH_KEY_PAIR);
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gestión de Reservas — Admin</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="../assets/css/admin.css">
</head>
<body class="bg-light">
<?php include '_sidebar.php'; ?>

<main style="margin-left:220px;" class="p-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="fw-bold mb-0">📅 Gestión de Reservas</h4>
    <span class="text-muted small">
      Total: <strong><?= count($reservas) ?></strong> registros
    </span>
  </div>

  <!-- TARJETAS CONTEO -->
  <div class="row g-3 mb-4">
    <?php
    $badges = [
      'pendiente'  => ['warning','⏳'],
      'confirmada' => ['success','✅'],
      'cancelada'  => ['danger', '❌'],
    ];
    foreach ($badges as $estado => [$color, $icono]): ?>
    <div class="col-md-4">
      <div class="card border-0 shadow-sm text-center p-3">
        <div class="fs-2"><?= $icono ?></div>
        <div class="display-6 fw-bold text-<?= $color ?>">
          <?= $contadores[$estado] ?? 0 ?>
        </div>
        <p class="text-muted small mb-0"><?= ucfirst($estado) ?></p>
      </div>
    </div>
    <?php endforeach; ?>
  </div>

  <!-- FILTROS -->
  <div class="card border-0 shadow-sm mb-3 p-3">
    <div class="row g-2 align-items-end">
      <div class="col-md-4">
        <label class="form-label small fw-semibold">Filtrar por estado</label>
        <select id="filtroEstado" class="form-select form-select-sm"
                onchange="aplicarFiltro()">
          <option value="todos"      <?= $filtroEstado==='todos'      ?'selected':'' ?>>
            Todos
          </option>
          <option value="pendiente"  <?= $filtroEstado==='pendiente'  ?'selected':'' ?>>
            Pendientes
          </option>
          <option value="confirmada" <?= $filtroEstado==='confirmada' ?'selected':'' ?>>
            Confirmadas
          </option>
          <option value="cancelada"  <?= $filtroEstado==='cancelada'  ?'selected':'' ?>>
            Canceladas
          </option>
        </select>
      </div>
      <div class="col-md-4">
        <label class="form-label small fw-semibold">Filtrar por fecha</label>
        <input type="date" id="filtroFecha" class="form-control form-control-sm"
               value="<?= htmlspecialchars($filtroFecha) ?>"
               onchange="aplicarFiltro()">
      </div>
      <div class="col-md-2">
        <button class="btn btn-sm btn-outline-secondary w-100"
                onclick="limpiarFiltros()">
          Limpiar filtros
        </button>
      </div>
    </div>
  </div>

  <!-- TABLA -->
  <div class="card border-0 shadow-sm">
    <div class="table-responsive">
      <table class="table table-hover mb-0 align-middle">
        <thead class="table-dark">
          <tr>
            <th>#</th>
            <th>Cliente</th>
            <th>Contacto</th>
            <th>Fecha</th>
            <th>Hora</th>
            <th class="text-center">Personas</th>
            <th>Estado</th>
            <th>Registrado</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($reservas)): ?>
          <tr>
            <td colspan="9" class="text-center py-4 text-muted">
              No se encontraron reservas con los filtros aplicados.
            </td>
          </tr>
          <?php else: ?>
          <?php foreach ($reservas as $r):
            $badgeColor = ['pendiente'=>'warning','confirmada'=>'success','cancelada'=>'danger'];
            $bc = $badgeColor[$r['estado']] ?? 'secondary';
          ?>
          <tr id="fila-<?= $r['id'] ?>">
            <td class="text-muted small"><?= $r['id'] ?></td>
            <td>
              <span class="fw-semibold"><?= htmlspecialchars($r['cliente']) ?></span>
            </td>
            <td>
              <small class="text-muted d-block"><?= htmlspecialchars($r['email']) ?></small>
              <?php if ($r['telefono']): ?>
              <small class="text-muted"><?= htmlspecialchars($r['telefono']) ?></small>
              <?php endif; ?>
            </td>
            <td><?= date('d/m/Y', strtotime($r['fecha'])) ?></td>
            <td><?= substr($r['hora'], 0, 5) ?></td>
            <td class="text-center">
              <span class="badge bg-secondary"><?= $r['personas'] ?> 👤</span>
            </td>
            <td>
              <span class="badge bg-<?= $bc ?>" id="badge-<?= $r['id'] ?>">
                <?= ucfirst($r['estado']) ?>
              </span>
            </td>
            <td>
              <small class="text-muted">
                <?= date('d/m/Y H:i', strtotime($r['created'])) ?>
              </small>
            </td>
            <td>
              <?php if ($r['estado'] === 'pendiente'): ?>
              <button class="btn btn-sm btn-success me-1"
                      onclick="cambiarEstado(<?= $r['id'] ?>, 'confirmada')"
                      title="Confirmar reserva">✓</button>
              <button class="btn btn-sm btn-danger"
                      onclick="cambiarEstado(<?= $r['id'] ?>, 'cancelada')"
                      title="Cancelar reserva">✗</button>
              <?php elseif ($r['estado'] === 'confirmada'): ?>
              <button class="btn btn-sm btn-outline-danger"
                      onclick="cambiarEstado(<?= $r['id'] ?>, 'cancelada')"
                      title="Cancelar">✗</button>
              <?php else: ?>
              <span class="text-muted small">—</span>
              <?php endif; ?>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</main>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script>
function aplicarFiltro() {
    const estado = document.getElementById('filtroEstado').value;
    const fecha  = document.getElementById('filtroFecha').value;
    let url = 'reservas.php?';
    if (estado) url += `estado=${estado}&`;
    if (fecha)  url += `fecha=${fecha}`;
    window.location.href = url;
}

function limpiarFiltros() {
    window.location.href = 'reservas.php';
}

async function cambiarEstado(id, estado) {
    const etiquetas = { confirmada:'confirmar', cancelada:'cancelar' };
    if (!confirm(`¿Desea ${etiquetas[estado]} la reserva #${id}?`)) return;

    try {
        const res  = await fetch('api_reservas.php', {
            method  : 'POST',
            headers : { 'Content-Type': 'application/json' },
            body    : JSON.stringify({ accion:'cambiar_estado', id, estado })
        });
        const data = await res.json();

        if (data.ok) {
            // Actualizar badge sin recargar
            const colores = {
                pendiente:'warning', confirmada:'success', cancelada:'danger'
            };
            const badge = document.getElementById(`badge-${id}`);
            badge.className = `badge bg-${colores[estado]}`;
            badge.textContent = estado.charAt(0).toUpperCase() + estado.slice(1);

            // Ocultar botones de la fila
            const fila = document.getElementById(`fila-${id}`);
            fila.querySelector('td:last-child').innerHTML =
              '<span class="text-muted small">Actualizado</span>';
        } else {
            alert('Error: ' + (data.error || 'No se pudo actualizar'));
        }
    } catch (err) {
        alert('Error de conexión. Intente nuevamente.');
    }
}
</script>
</body>
</html>