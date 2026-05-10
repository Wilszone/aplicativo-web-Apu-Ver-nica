const contenedor = document.getElementById('contenedor-platos');
const filtros    = document.querySelectorAll('#filtros button');

const iconos = {
    'Entradas'          : '🥗',
    'Platos principales': '🍽️',
    'Bebidas'           : '🥤',
    'Postres'           : '🍮',
};

async function cargarPlatos(categoria = 'Todas') {
    contenedor.innerHTML = `
      <div class="col-12 text-center py-5">
        <div class="spinner-border text-danger" role="status"></div>
      </div>`;

    try {
        const url  = categoria === 'Todas'
            ? 'api/menu.php'
            : `api/menu.php?categoria=${encodeURIComponent(categoria)}`;
        const res  = await fetch(url);
        const json = await res.json();

        if (!json.ok || json.data.length === 0) {
            contenedor.innerHTML =
              '<div class="col-12 text-center py-5 text-muted">No hay platos disponibles.</div>';
            return;
        }

        contenedor.innerHTML = json.data.map(plato => `
          <div class="col-sm-6 col-lg-4">
            <div class="card h-100 shadow-sm border-0">
              <div class="card-body text-center" style="font-size:3rem;">
                ${iconos[plato.categoria] || '🍴'}
              </div>
              <div class="card-body pt-0">
                <span class="badge bg-danger mb-2 small">${plato.categoria}</span>
                <h5 class="card-title fw-bold">${plato.nombre}</h5>
                <p class="card-text text-muted small">${plato.descripcion ?? ''}</p>
              </div>
              <div class="card-footer bg-transparent border-0">
                <span class="fs-4 fw-bold text-danger">
                  S/ ${parseFloat(plato.precio).toFixed(2)}
                </span>
              </div>
            </div>
          </div>`).join('');

    } catch (err) {
        contenedor.innerHTML =
          '<div class="col-12 text-center py-5 text-danger">Error al cargar la carta.</div>';
        console.error(err);
    }
}

filtros.forEach(btn => {
    btn.addEventListener('click', () => {
        filtros.forEach(b => b.classList.replace('btn-danger', 'btn-outline-danger'));
        btn.classList.replace('btn-outline-danger', 'btn-danger');
        cargarPlatos(btn.dataset.cat);
    });
});

cargarPlatos();