<?php
require_once '_auth_check.php';
require_once '../config/db.php';
$db    = getDB();
$platos = $db->query(
    "SELECT * FROM menu ORDER BY categoria, nombre")->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gestión de Menú — Admin</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body class="bg-light">
<?php include '_sidebar.php'; ?>

<main style="margin-left:220px;" class="p-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h4 class="fw-bold">🍽️ Gestión de Menú</h4>
    <button class="btn btn-danger"
            data-bs-toggle="modal" data-bs-target="#modalPlato"
            onclick="abrirModal()">+ Nuevo Plato</button>
  </div>

  <div class="card border-0 shadow-sm">
    <div class="table-responsive">
      <table class="table table-hover mb-0">
        <thead class="table-dark">
          <tr>
            <th>#</th><th>Categoría</th><th>Nombre</th>
            <th>Descripción</th><th>Precio</th><th>Estado</th><th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($platos as $p): ?>
          <tr>
            <td><?= $p['id'] ?></td>
            <td><span class="badge bg-secondary"><?= htmlspecialchars($p['categoria']) ?></span></td>
            <td class="fw-semibold"><?= htmlspecialchars($p['nombre']) ?></td>
            <td class="text-muted small"><?= htmlspecialchars($p['descripcion']) ?></td>
            <td class="text-danger fw-bold">S/ <?= number_format($p['precio'],2) ?></td>
            <td>
              <span class="badge bg-<?= $p['activo'] ? 'success' : 'secondary' ?>">
                <?= $p['activo'] ? 'Activo' : 'Inactivo' ?>
              </span>
            </td>
            <td>
              <button class="btn btn-sm btn-primary me-1"
                onclick="abrirModal(<?= htmlspecialchars(json_encode($p)) ?>)">
                ✏️ Editar
              </button>
              <button class="btn btn-sm btn-danger"
                onclick="eliminarPlato(<?= $p['id'] ?>, '<?= htmlspecialchars($p['nombre']) ?>')">
                🗑️
              </button>
            </td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</main>

<!-- MODAL AGREGAR/EDITAR -->
<div class="modal fade" id="modalPlato" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title" id="tituloModal">Nuevo Plato</h5>
        <button type="button" class="btn-close btn-close-white"
                data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="m_id">
        <div class="mb-3">
          <label class="form-label">Categoría *</label>
          <select id="m_cat" class="form-select" required>
            <option value="Entradas">Entradas</option>
            <option value="Platos principales">Platos principales</option>
            <option value="Bebidas">Bebidas</option>
            <option value="Postres">Postres</option>
          </select>
        </div>
        <div class="mb-3">
          <label class="form-label">Nombre *</label>
          <input type="text" id="m_nombre" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Descripción</label>
          <textarea id="m_desc" class="form-control" rows="2"></textarea>
        </div>
        <div class="mb-3">
          <label class="form-label">Precio (S/) *</label>
          <input type="number" id="m_precio" class="form-control"
                 min="0" step="0.50" required>
        </div>
        <div class="form-check">
          <input class="form-check-input" type="checkbox"
                 id="m_activo" checked>
          <label class="form-check-label">Activo (visible en carta)</label>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary"
                data-bs-dismiss="modal">Cancelar</button>
        <button type="button" class="btn btn-danger"
                onclick="guardarPlato()">Guardar</button>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script>
function abrirModal(p = null) {
    document.getElementById('tituloModal').textContent = p ? 'Editar Plato' : 'Nuevo Plato';
    document.getElementById('m_id').value      = p?.id       ?? '';
    document.getElementById('m_cat').value     = p?.categoria ?? 'Entradas';
    document.getElementById('m_nombre').value  = p?.nombre    ?? '';
    document.getElementById('m_desc').value    = p?.descripcion ?? '';
    document.getElementById('m_precio').value  = p?.precio    ?? '';
    document.getElementById('m_activo').checked = p ? !!p.activo : true;
}

async function guardarPlato() {
    const id     = document.getElementById('m_id').value;
    const datos  = {
        id        : id || null,
        categoria : document.getElementById('m_cat').value,
        nombre    : document.getElementById('m_nombre').value.trim(),
        descripcion: document.getElementById('m_desc').value.trim(),
        precio    : parseFloat(document.getElementById('m_precio').value),
        activo    : document.getElementById('m_activo').checked ? 1 : 0,
        accion    : id ? 'editar' : 'crear',
    };

    if (!datos.nombre || isNaN(datos.precio)) {
        alert('Nombre y precio son obligatorios.');
        return;
    }

    const res  = await fetch('api_menu.php', {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify(datos),
    });
    const data = await res.json();
    if (data.ok) location.reload();
    else alert('Error: ' + data.error);
}

async function eliminarPlato(id, nombre) {
    if (!confirm(`¿Eliminar el plato "${nombre}"? Esta acción no se puede deshacer.`)) return;
    const res  = await fetch('api_menu.php', {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify({ accion: 'eliminar', id }),
    });
    const data = await res.json();
    if (data.ok) location.reload();
    else alert('Error: ' + data.error);
}
</script>
</body>
</html>