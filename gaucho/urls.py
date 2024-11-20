from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # Ruta para la página de inicio
    path('scan/', views.port_scan, name='port_scan'),  # Ruta para el escaneo de puertos
    path('traceroute/', views.traceroute, name='traceroute'),  # Ruta para traceroute
]
