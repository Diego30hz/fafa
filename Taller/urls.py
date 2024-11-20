from django.contrib import admin
from django.urls import path, include  # Incluye la función include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('gaucho.urls')),  # Asegúrate de que el nombre del archivo de la aplicación sea correcto
]


