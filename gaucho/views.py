import subprocess
import platform
import re
import nmap
import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

PORT_RISK = {
    22: "Alto",  # SSH
    23: "Alto",  # Telnet
    80: "Bajo",  # HTTP
    443: "Bajo",  # HTTPS
    21: "Moderado",  # FTP
    3389: "Alto",  # RDP
    25: "Alto",  # SMTP
    3306: "Moderado",  # MySQL
    8080: "Bajo",  # HTTP Alternativo
}

def home(request):
    return render(request, 'index.html')

def classify_port_risk(port):
    """Clasifica el puerto según su riesgo y devuelve la clase de riesgo."""
    if port in [22, 23, 3389, 25]:  # Puertos con riesgo alto
        return "alto"
    elif port in [21, 3306]:  # Puertos con riesgo moderado
        return "moderado"
    else:  # Puertos considerados de bajo riesgo
        return "bajo"

def scan_ports(target, scan_type):
    nm = nmap.PortScanner()
    if scan_type == 'tcp':
        nm.scan(hosts=target, arguments='-sT')  # Escaneo TCP
    elif scan_type == 'udp':
        nm.scan(hosts=target, arguments='-sU')  # Escaneo UDP
    
    results = ""
    for host in nm.all_hosts():
        results += f"<div class='host-info'><strong>Host:</strong> {host} ({nm[host].hostname()})<br>"
        results += f"<strong>Estado:</strong> {nm[host].state()}</div>"
        
        if scan_type == 'tcp':
            protocol = 'tcp'
        else:
            protocol = 'udp'
        
        if protocol in nm[host].all_protocols():
            ports = nm[host][protocol].keys()
            for port in sorted(ports):
                state = nm[host][protocol][port]['state']
                risk_class = classify_port_risk(port)  # Obtener la clase de riesgo
                service = nm[host][protocol][port].get('name', 'Desconocido')
                results += f"<div class='port-info {risk_class}'>"
                results += f"<strong>Puerto:</strong> {port} <strong>Estado:</strong> {state} <strong>Riesgo:</strong> {risk_class} <strong>Servicio:</strong> {service}</div>"
        else:
            results += f"<div>No se encontraron puertos {protocol.upper()} abiertos.</div>"

    return results

# Vista para manejar la solicitud del escaneo
@csrf_exempt
@csrf_exempt
def port_scan(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        target = data.get('target')
        scan_type = data.get('scanType')

        if not target or not scan_type:
            return JsonResponse({'error': 'Faltan parámetros'}, status=400)

        try:
            if scan_type == 'traceroute':
                results = traceroute(target)
            else:
                results = scan_ports(target, scan_type)
            return JsonResponse({'results': results})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Método no permitido'}, status=405)


def traceroute(target):
    os_name = platform.system()
    command = ["tracert", target] if os_name == "Windows" else ["traceroute", target]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    hops = []
    if result.returncode == 0:
        # Procesar cada línea de la salida para extraer IP, hostname y latencia
        for line in result.stdout.splitlines():
            # Extraer datos usando una expresión regular (esto puede variar según el sistema)
            hop_match = re.search(r'(\d+)\s+([^\s]+)\s+\(([\d.]+)\)\s+([\d.]+ ms)', line)
            if hop_match:
                hop = {
                    "ip": hop_match.group(3),
                    "host": hop_match.group(2),
                    "latency": hop_match.group(4),
                }
                hops.append(hop)
    else:
        hops.append({"error": "Error en el traceroute: " + result.stderr})

    return hops

def traceroute_view(request):
    if request.method == 'POST':
        target = request.POST.get('target')
        results = traceroute(target)
        return render(request, 'traceroute_results.html', {'results': results})
    
    return render(request, 'traceroute_form.html')