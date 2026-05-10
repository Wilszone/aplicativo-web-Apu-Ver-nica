<?php
require_once '_auth_check.php';
require_once '../config/db.php';

$db       = getDB();
$usuarios = $db->query(
    "SELECT id, nombre, email, rol, created FROM usuarios ORDER BY created DESC"
)->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gestión de Usuarios — Admin</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="../assets/css/admin.css">
</head>
<body class="bg-light">
<?php include '_sidebar.php'; ?>

<main style="margin-left:220px;" class="p-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="fw-bold mb-0">👥 Gestión de Usuarios</h4>
    <button class="btn btn-danger"
            data-bs-toggle="modal"
            data-bs-target="#modalNuevo">
      + Nuevo Usuario
    </button>
  </div>

  <div class="card border-0 shadow-sm">
    <div class="table-responsive">
      <table class="table table-hover mb-0 align-middle">
        <thead class="table-dark">
          <tr>
            <th>#</th>
            <th>Nombre</th>
            <th>Email</th>
            <th>Rol</th>
            <th>Registrado</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($usuarios as $u): ?>
          <tr id="usuario-<?= $u['id'] ?>">
            <td class="text-muted small"><?= $u['id'] ?></td>
            <td class="fw-semibold"><?= htmlspecialchars($u['nombre']) ?></td>
            <td class="text-muted"><?= htmlspecialchars($u['email']) ?></td>
            <td>
              <span class="badge bg-<?= $u['rol']==='admin' ? 'danger':'info' ?>">
                <?= ucfirst($u['rol']) ?>
              </span>
            </td>
            <td>
              <small class="text-muted">
                <?= date('d/m/Y', strtotime($u['created'])) ?>
              </small>
            </td>
            <td>
              <?php if ($u['id'] != $_SESSION['uid']): ?>
              <button class="btn btn-sm btn-outline-danger"
                      onclick="eliminarUsuario(<?= $u['id'] ?>,
                      '<?= htmlspecialchars($u['nombre']) ?>')">
                🗑️ Eliminar
              </button>
              <?php else: ?>
              <span class="text-muted small">Tu cuenta</span>
              <?php endif; ?>
            </td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</main>

<!-- MODAL NUEVO USUARIO -->
<div class="modal fade" id="modalNuevo" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title">Crear Nuevo Usuario</h5>
        <button type="button" class="btn-close btn-close-white"
                data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div id="alertaNuevo" class="alert d-none" role="alert"></div>
        <div class="mb-3">
          <label class="form-label fw-semibold">Nombre completo *</label>
          <input type="text" id="u_nombre" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label fw-semibold">Correo electrónico *</label>
          <input type="email" id="u_email" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label fw-semibold">Contraseña *</label>
          <input type="password" id="u_pwd" class="form-control" required
                 placeholder="Mínimo 8 caracteres">
          <div class="form-text">
            Use mayúsculas, minúsculas, números y símbolos.
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label fw-semibold">Rol *</label>
          <select id="u_rol" class="form-select">
            <option value="staff">Staff (acceso limitado)</option>
            <option value="admin">Admin (acceso completo)</option>
          </select>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary"
                data-bs-dismiss="modal">Cancelar</button>
        <button type="button" class="btn btn-danger"
                onclick="crearUsuario()">Crear Usuario</button>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
</script>
<script>
async function crearUsuario() {
    const nombre = document.getElementById('u_nombre').value.trim();
    const email  = document.getElementById('u_email').value.trim();
    const pwd    = document.getElementById('u_pwd').value;
    const rol    = document.getElementById('u_rol').value;
    const alerta = document.getElementById('alertaNuevo');

    if (!nombre || !email || !pwd) {
        alerta.className = 'alert alert-warning';
        alerta.textContent = 'Todos los campos son obligatorios.';
        alerta.classList.remove('d-none');
        return;
    }

    if (pwd.length < 8) {
        alerta.className = 'alert alert-warning';
        alerta.textContent = 'La contraseña debe tener al menos 8 caracteres.';
        alerta.classList.remove('d-none');
        return;
    }

    try {
        const res  = await fetch('nuevo_usuario.php', {
            method  : 'POST',
            headers : { 'Content-Type': 'application/json' },
            body    : JSON.stringify({ nombre, email, pwd, rol })
        });
        const data = await res.json();

        if (data.ok) {
            alerta.className = 'alert alert-success';
            alerta.textContent = '✅ Usuario creado exitosamente.';
            alerta.classList.remove('d-none');
            setTimeout(() => location.reload(), 1200);
        } else {
            alerta.className = 'alert alert-danger';
            alerta.textContent = '❌ ' + (data.error || 'Error al crear usuario');
            alerta.classList.remove('d-none');
        }
    } catch (err) {
        alerta.className = 'alert alert-danger';
        alerta.textContent = '❌ Error de conexión.';
        alerta.classList.remove('d-none');
    }
}

async function eliminarUsuario(id, nombre) {
    if (!confirm(`¿Eliminar al usuario "${nombre}"? Esta acción no se puede deshacer.`))
        return;

    const res  = await fetch('api_usuarios.php', {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify({ accion:'eliminar', id })
    });
    const data = await res.json();

    if (data.ok) {
        document.getElementById(`usuario-${id}`)?.remove();
    } else {
        alert('Error: ' + (data.error || 'No se pudo eliminar el usuario'));
    }
}
</script>
</body>
</html>