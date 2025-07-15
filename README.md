# AWS S3 Security Laboratory

Laboratorio educativo para aprender técnicas de enumeración y análisis de buckets S3 usando Python y Burp Suite.

## 🚀 Características

- ⚙️ **Configuración automática** de entorno AWS  
- 🔍 **Dos enfoques de enumeración**: `requests` vs `boto3`  
- 🧪 **Interceptación de tráfico** con Burp Suite  
- ☁️ **Herramienta multi-servicio** para explorar otros servicios AWS  
- 🧹 **Limpieza automática** del entorno  

---

## 📦 Prerrequisitos

### 1. Crear una cuenta en AWS (si aún no tienes una)

1. Ve a 👉 [aws.amazon.com](https://aws.amazon.com)  
2. Haz clic en **"Crear una cuenta de AWS"**  
3. Sigue el proceso de registro (se requiere tarjeta de crédito para verificación)  
4. Activa tu cuenta mediante el email de confirmación  

> ⚠️ **Nota**: Este laboratorio utiliza servicios dentro de la capa gratuita de AWS.

---

### 2. Instalar AWS CLI

#### En Linux (Ubuntu/Debian)

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verificar instalación
aws --version

## ⚡ Instalación Rápida del Laboratorio
git clone https://github.com/Elisaelias02/aws-s3-security-lab.git
cd aws-s3-security-lab
chmod +x setup_lab.sh
./setup_lab.sh

