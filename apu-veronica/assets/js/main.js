// Cambio de idioma — almacena en sessionStorage y recarga
async function cambiarIdioma(lang) {
    await fetch('api/lang.php', {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify({ lang })
    });
    location.reload();
}

// Aplicar traducciones i18n al DOM
async function aplicarIdioma() {
    const res  = await fetch('api/lang.php');
    if (!res.ok) return;
    const t = await res.json();
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (t[key]) el.textContent = t[key];
    });
}

document.addEventListener('DOMContentLoaded', aplicarIdioma);