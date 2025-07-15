# AWS S3 Security Laboratory

Laboratorio educativo para aprender técnicas de enumeración y análisis de buckets S3 usando Python y Burp Suite.

## Características

- **Configuración automática** de entorno AWS
- **Dos enfoques de enumeración**: requests vs Boto3
- **Interceptación de tráfico** con Burp Suite
- **Herramienta multi-servicio** para explorar otros servicios AWS
- **Limpieza automática** del entorno

## Prerequisitos

### 1. Crear cuenta AWS (si no tienes una)

1. **Ir a [aws.amazon.com](https://aws.amazon.com)**
2. **Hacer clic en "Crear una cuenta de AWS"**
3. **Seguir el proceso de registro** (requiere tarjeta de crédito para verificación)
4. **Activar la cuenta** mediante email

> **Nota**: Este laboratorio usa servicios de la capa gratuita de AWS

### 2. Instalar AWS CLI

#### Linux (Ubuntu/Debian)
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verificar instalación
aws --version

Configurar credenciales AWS
Crear usuario IAM

Acceder a AWS Console → console.aws.amazon.com
Ir a IAM:

Buscar "IAM" en la barra de búsqueda
Hacer clic en el servicio IAM


Crear usuario:

Clic en "Usuarios" (sidebar izquierdo)
Clic en "Crear usuario"
Nombre: S3LabUser (o el que prefieras)
Clic en "Siguiente"


Asignar permisos:

Seleccionar "Adjuntar políticas directamente"
Buscar y seleccionar: AmazonS3FullAccess
Clic en "Siguiente" → "Crear usuario"


Crear clave de acceso:

Clic en el usuario recién creado
Ir a pestaña "Credenciales de seguridad"
Clic en "Crear clave de acceso"
Seleccionar "Command Line Interface (CLI)"
Marcar casilla de confirmación → "Siguiente"
⚠️ IMPORTANTE: Descargar el archivo .csv o copiar las credenciales
Esta es la única vez que podrás ver la clave secreta

## Instalación Rápida

```bash
git clone https://github.com/Elisaelias02/aws-s3-security-lab.git
cd aws-s3-security-lab
chmod +x setup_lab.sh
./setup_lab.sh

