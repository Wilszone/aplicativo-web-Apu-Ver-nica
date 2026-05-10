// Fecha mínima = hoy
document.getElementById('r_fecha').min = new Date().toISOString().split('T')[0];

document.getElementById('btnReservar').addEventListener('click', async () => {
    const alerta   = document.getElementById('alerta');
    const nombre   = document.getElementById('r_nombre').value.trim();
    const email    = document.getElementById('r_email').value.trim();
    const telefono = document.getElementById('r_telefono').value.trim();
    const fecha    = document.getElementById('r_fecha').value;
    const hora     = document.getElementById('r_hora').value;
    const personas = parseInt(document.getElementById('r_personas').value);

    // Validación cliente
    if (!nombre || !email || !fecha || !hora || personas < 1) {
        alerta.className = 'alert alert-warning';
        alerta.textContent = 'Por favor complete todos los campos obligatorios (*)';
        return;
    }

    const btn = document.getElementById('btnReservar');
    btn.disabled = true;
    btn.textContent = 'Procesando...';

    try {
        const res  = await fetch('api/reservas.php', {
            method  : 'POST',
            headers : { 'Content-Type': 'application/json' },
            body    : JSON.stringify({ cliente: nombre, email, telefono,
                                       fecha, hora, personas })
        });
        const data = await res.json();

        if (data.ok) {
            alerta.className = 'alert alert-success';
            alerta.innerHTML = `✅ <strong>${data.mensaje}</strong>
              <br>Le confirmaremos su reserva por correo electrónico.`;
            // Limpiar formulario
            ['r_nombre','r_email','r_telefono','r_fecha','r_hora'].forEach(
                id => { document.getElementById(id).value = ''; }
            );
            document.getElementById('r_personas').value = 2;
        } else {
            alerta.className = 'alert alert-danger';
            alerta.textContent = '❌ ' + (data.error || 'Error al procesar la reserva');
        }
    } catch (err) {
        alerta.className = 'alert alert-danger';
        alerta.textContent = '❌ Error de conexión. Intente nuevamente.';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Confirmar Reserva';
        alerta.classList.remove('d-none');
        alerta.scrollIntoView({ behavior: 'smooth' });
    }
});