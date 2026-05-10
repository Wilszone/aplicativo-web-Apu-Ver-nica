<?php
require_once '_auth_check.php';
require_once '../config/db.php';

$db    = getDB();
$fotos = $db->query(
    "SELECT * FROM galeria ORDER BY orden ASC, id DESC"
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gestión de Galería — Admin</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="../assets/css/admin.css">
</head>
<body class="bg-light">
<?php include '_sidebar.php'; ?>

<main style="margin-left:220px;" class="p-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="fw-bold mb-0">🖼️ Gestión de Galería</h4>
    <button class="btn btn-danger"
            data-bs-toggle="modal"
            data-bs-target="#modalSubir">
      + Subir Imagen
    </button>
  </div>

  <!-- GRID DE IMÁGENES -->
  <?php if (empty($fotos)): ?>
  <div class="text-center py-5 text-muted">
    <div class="fs-1 mb-2">🖼️</div>
    <p>No hay imágenes en la galería. ¡Suba la primera!</p>
  </div>
  <?php else: ?>
  <div class="row g-3">
    <?php foreach ($fotos as $f): ?>
    <div class="col-6 col-md-4 col-lg-3" id="foto-<?= $f['id'] ?>">
      <div class="card border-0 shadow-sm overflow-hidden h-100">
        <div style="height:160px; background:#f0f0f0; overflow:hidden;">
          <img src="../assets/img/galeria/<?= htmlspecialchars($f['archivo']) ?>"
               alt="<?= htmlspecialchars($f['titulo'] ?? '') ?>"
               style="width:100%;height:100%;object-fit:cover;">
        </div>
        <div class="card-body p-2">
          <p class="small fw-semibold mb-1 text-truncate">
            <?= htmlspecialchars($f['titulo'] ?? 'Sin título') ?>
          </p>
          <div class="d-flex align-items-center justify-content-between">
            <span class="badge bg-<?= $f['activo'] ? 'success':'secondary' ?>
                         small" id="badge-foto-<?= $f['id'] ?>">
              <?= $f['activo'] ? 'Visible':'Oculta' ?>
            </span>
            <div class="d-flex gap-1">
              <button class="btn btn-sm btn-outline-secondary p-1"
                      title="<?= $f['activo'] ? 'Ocultar':'Mostrar' ?>"
                      onclick="toggleFoto(<?= $f['id'] ?>, <?= $f['activo'] ?>)">
                <?= $f['activo'] ? '👁️':'🚫' ?>
              </button>
              <button class="btn btn-sm btn-outline-danger p-1"
                      title="Eliminar"
                      onclick="eliminarFoto(<?= $f['id'] ?>,
                      '<?= htmlspecialchars($f['titulo'] ?? 'esta imagen') ?>')">
                🗑️
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>
</main>

<!-- MODAL SUBIR -->
<div class="modal fade" id="modalSubir" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title">Subir Nueva Imagen</h5>
        <button type="button" class="btn-close btn-close-white"
                data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div id="alertaSubida" class="alert d-none" role="alert"></div>
        <div class="mb-3">
          <label class="form-label fw-semibold">Imagen *</label>
          <input type="file" id="archivoInput" class="form-control"
                 accept="image/jpeg,image/png,image/webp" required>
          <div class="form-text">
            Formatos: JPG, PNG, WebP. Tamaño máximo: 2 MB.
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label fw-semibold">Título (opcional)</label>
          <input type="text" id="tituloInput" class="form-control"
                 placeholder="Ej: Trucha a la parrilla">
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary"
                data-bs-dismiss="modal">Cancelar</button>
        <button type="button" class="btn btn-danger"
                id="btnSubir" onclick="subirImagen()">
          Subir Imagen
        </button>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script>
async function subirImagen() {
    const archivo = document.getElementById('archivoInput').files[0];
    const titulo  = document.getElementById('tituloInput').value.trim();
    const alerta  = document.getElementById('alertaSubida');

    if (!archivo) {
        alerta.className = 'alert alert-warning';
        alerta.textContent = 'Seleccione una imagen.';
        alerta.classList.remove('d-none');
        return;
    }

    const formData = new FormData();
    formData.append('archivo', archivo);
    formData.append('titulo',  titulo);

    document.getElementById('btnSubir').disabled = true;

    try {
        const res  = await fetch('api_galeria.php', {
            method : 'POST',
            body   : formData
        });
        const data = await res.json();

        if (data.ok) {
            alerta.className = 'alert alert-success';
            alerta.textContent = '✅ Imagen subida exitosamente.';
            alerta.classList.remove('d-none');
            setTimeout(() => location.reload(), 1200);
        } else {
            alerta.className = 'alert alert-danger';
            alerta.textContent = '❌ ' + (data.error || 'Error al subir imagen');
            alerta.classList.remove('d-none');
        }
    } catch (err) {
        alerta.className = 'alert alert-danger';
        alerta.textContent = '❌ Error de conexión.';
        alerta.classList.remove('d-none');
    } finally {
        document.getElementById('btnSubir').disabled = false;
    }
}

async function toggleFoto(id, activo) {
    const nuevoEstado = activo ? 0 : 1;
    const res  = await fetch('api_galeria.php', {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify({ accion:'toggle', id, activo: nuevoEstado })
    });
    const data = await res.json();
    if (data.ok) location.reload();
    else alert('Error: ' + data.error);
}

async function eliminarFoto(id, titulo) {
    if (!confirm(`¿Eliminar "${titulo}"? Se borrará de la BD y del servidor.`)) return;
    const res  = await fetch('api_galeria.php', {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify({ accion:'eliminar', id })
    });
    const data = await res.json();
    if (data.ok) {
        document.getElementById(`foto-${id}`)?.remove();
    } else {
        alert('Error: ' + data.error);
    }
}
</script>
</body>
</html>