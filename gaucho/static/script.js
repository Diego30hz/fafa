document.getElementById('scanForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const target = document.getElementById('ip').value;
    const scanType = document.getElementById('scan-type').value;

    // Cambiar el texto y deshabilitar el botón
    const scanButton = document.querySelector('.scan-btn');
    scanButton.textContent = 'Escaneando...';
    scanButton.style.backgroundColor = '#ff4747';
    scanButton.disabled = true;

    try {
        let url = scanType === 'traceroute' ? '/traceroute/' : '/scan/';
        
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ target, scanType })
        });

        const data = await response.json();
        
        const resultsSection = document.getElementById('results');
        if (scanType === 'traceroute') {
            // Formatear y mostrar resultados de traceroute
            let tracerouteResults = data.results.map((hop, index) => 
                `<p><strong>Salto ${index + 1}:</strong> ${hop.host} (${hop.ip}) - ${hop.latency}</p>`
            ).join("");
            resultsSection.innerHTML = `<div class="traceroute-results">${tracerouteResults}</div>`;
        } else {
            // Mostrar los resultados del escaneo de puertos
            resultsSection.innerHTML = `<pre>${data.results}</pre>`;
        }

        // Volver a habilitar el botón cuando termine el escaneo
        scanButton.textContent = 'Iniciar';
        scanButton.style.backgroundColor = '#00ff00';
        scanButton.disabled = false;
        
    } catch (error) {
        console.error('Error durante el escaneo:', error);

        // Manejar el error y volver a habilitar el botón
        scanButton.textContent = 'Iniciar';
        scanButton.style.backgroundColor = '#00ff00';
        scanButton.disabled = false;
    }
});

// Obtener el token CSRF de las cookies
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Menú hamburguesa
document.getElementById('menuToggle').addEventListener('click', function() {
    const menu = document.getElementById('menu');
    menu.classList.toggle('show');
    
    const toggle = document.getElementById('menuToggle');
    toggle.classList.toggle('active');
});
