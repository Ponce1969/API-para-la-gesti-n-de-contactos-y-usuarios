FROM python:3.10-slim

# Reduce el tamaño de la imagen y evita archivos temporales
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Instala solo las dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia solo el código necesario
COPY app ./app
COPY docker_create_admin.py .
COPY .env .

# Comando para producción (sin --reload)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
