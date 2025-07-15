#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUCKET_PREFIX="aws-lab-s3"
TIMESTAMP=$(date +%Y%m%d%H%M)
BUCKET_NAME="${BUCKET_PREFIX}-${TIMESTAMP}"
IAM_USER="AWSLabUser"

print_status() {
    echo "[$(date '+%H:%M:%S')] $1"
}

print_error() {
    echo "[ERROR] $1" >&2
}

check_requirements() {
    print_status "Verificando requisitos..."
    
    command -v aws >/dev/null 2>&1 || { print_error "AWS CLI no instalado"; exit 1; }
    command -v python3 >/dev/null 2>&1 || { print_error "Python3 no instalado"; exit 1; }
    command -v pip3 >/dev/null 2>&1 || { print_error "pip3 no instalado"; exit 1; }
    command -v openssl >/dev/null 2>&1 || { print_error "OpenSSL no instalado"; exit 1; }
    command -v curl >/dev/null 2>&1 || { print_error "curl no instalado"; exit 1; }
    
    print_status "Requisitos verificados"
}

install_python_dependencies() {
    print_status "Instalando dependencias Python..."
    pip3 install --user boto3 requests urllib3 >/dev/null 2>&1
    print_status "Dependencias instaladas"
}

setup_aws_credentials() {
    print_status "Configurando credenciales AWS..."
    
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        print_status "Credenciales AWS no configuradas. Configure manualmente:"
        echo "  aws configure"
        echo "Luego ejecute este script nuevamente."
        exit 1
    fi
    
    CALLER_INFO=$(aws sts get-caller-identity)
    ACCOUNT_ID=$(echo "$CALLER_INFO" | python3 -c "import sys, json; print(json.load(sys.stdin)['Account'])")
    USER_ARN=$(echo "$CALLER_INFO" | python3 -c "import sys, json; print(json.load(sys.stdin)['Arn'])")
    
    print_status "Autenticado como: $USER_ARN"
    print_status "Cuenta AWS: $ACCOUNT_ID"
}

create_lab_files() {
    print_status "Creando archivos del laboratorio..."
    
    mkdir -p lab_files/{directorio1,directorio2,directorio3}
    
    cat > lab_files/index.html << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS S3 Laboratory</title>
</head>
<body>
    <h1>AWS S3 Security Laboratory</h1>
    <p>This is a test page for S3 bucket enumeration laboratory.</p>
    <p>Explore the directories to find more files.</p>
    <footer>
        <p>Created for cybersecurity education purposes</p>
    </footer>
</body>
</html>
EOF

    cat > lab_files/directorio1/server_config.txt << 'EOF'
SERVER CONFIGURATION REPORT

=== SYSTEM INFORMATION ===
Hostname: web-server-01
IP Address: 192.168.1.100
Operating System: Ubuntu 20.04 LTS
Last Update: 2025-05-22

=== NETWORK CONFIGURATION ===
Gateway: 192.168.1.1
DNS Servers: 8.8.8.8, 1.1.1.1
Firewall Status: Enabled

Laboratory ID: LAB-S3-001
Access Level: Public
EOF

    cat > lab_files/directorio1/app_config.json << 'EOF'
{
    "application": {
        "name": "WebApp-Production",
        "version": "2.1.4",
        "environment": "production",
        "debug": false
    },
    "database": {
        "host": "db.internal.company.com",
        "port": 5432,
        "name": "webapp_prod",
        "ssl": true
    },
    "services": [
        {
            "name": "nginx",
            "port": 80,
            "status": "active"
        },
        {
            "name": "redis",
            "port": 6379,
            "status": "active"
        }
    ]
}
EOF

    cat > lab_files/directorio2/users.csv << 'EOF'
ID,Username,Email,Department,Role,LastLogin
001,admin,admin@company.com,IT,Administrator,2025-05-22
002,maria.garcia,maria@company.com,Marketing,User,2025-05-21
003,juan.lopez,juan@company.com,Sales,User,2025-05-20
004,ana.rodriguez,ana@company.com,HR,Manager,2025-05-22
005,carlos.martinez,carlos@company.com,IT,Developer,2025-05-22
006,lucia.fernandez,lucia@company.com,Finance,Analyst,2025-05-19
EOF

    cat > lab_files/directorio2/access_logs.txt << 'EOF'
[2025-05-22 10:30:15] INFO: System startup completed successfully
[2025-05-22 10:30:16] INFO: Database connection established
[2025-05-22 10:35:22] WARNING: Failed login attempt for user: test_user
[2025-05-22 10:35:45] ERROR: Authentication failure from IP: 192.168.1.200
[2025-05-22 10:40:12] INFO: User admin authenticated successfully
[2025-05-22 11:15:33] WARNING: High CPU usage detected (85%)
[2025-05-22 11:20:01] INFO: Automatic backup completed successfully
[2025-05-22 12:00:00] INFO: Daily security scan initiated
[2025-05-22 12:15:30] WARNING: Suspicious file access detected
[2025-05-22 12:30:45] INFO: Security scan completed - 2 issues found
EOF

    cat > lab_files/directorio3/credentials.txt << 'EOF'
CONFIDENTIAL - SYSTEM CREDENTIALS

=== DATABASE CREDENTIALS ===
Production Database:
- Host: db.internal.company.com
- Username: db_admin
- Password: SecureP@ssw0rd2025!
- Port: 5432

=== APPLICATION SECRETS ===
Admin User: sysadmin
Admin Password: AdminSecure123#
API Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

=== ENCRYPTION KEYS ===
AES Key: 2B7E151628AED2A6ABF7158809CF4F3C
RSA Private Key: -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7SMT6GUxJmwm...
[TRUNCATED FOR SECURITY]
-----END RSA PRIVATE KEY-----

WARNING: Change these credentials regularly
Last Updated: 2025-05-22
Next Review: 2025-08-22
EOF

    cat > lab_files/directorio3/backup_config.json << 'EOF'
{
    "backup_settings": {
        "encryption_enabled": true,
        "encryption_key": "AES256-GCM-PRODUCTION-KEY-2025",
        "destination": {
            "type": "s3",
            "bucket": "company-backups-encrypted",
            "region": "us-east-1"
        },
        "credentials": {
            "access_key": "AKIAI44QH8DHBEXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        },
        "schedule": {
            "daily": "02:00 UTC",
            "weekly": "Sunday 03:00 UTC",
            "monthly": "1st day 04:00 UTC"
        },
        "retention": {
            "daily_backups": "30 days",
            "weekly_backups": "12 weeks",
            "monthly_backups": "12 months"
        }
    },
    "last_backup": "2025-05-21T02:00:00Z",
    "next_backup": "2025-05-23T02:00:00Z",
    "backup_size_gb": 15.7
}
EOF

    print_status "Archivos del laboratorio creados"
}

create_s3_bucket() {
    print_status "Creando bucket S3: $BUCKET_NAME"
    
    aws s3 mb s3://$BUCKET_NAME >/dev/null 2>&1
    
    print_status "Subiendo archivos al bucket..."
    aws s3 cp lab_files/ s3://$BUCKET_NAME/ --recursive --quiet
    
    print_status "Verificando contenido del bucket..."
    FILE_COUNT=$(aws s3 ls s3://$BUCKET_NAME --recursive | wc -l)
    print_status "Archivos subidos: $FILE_COUNT"
}

create_lab_scripts() {
    print_status "Creando scripts del laboratorio..."
    
    cat > s3_enumerator.py << 'EOF'
#!/usr/bin/env python3

import requests
import re
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def enumerar_s3(bucket_name):
    print(f"Enumerando bucket: {bucket_name}")
    
    download_dir = f"descargas_{bucket_name}"
    os.makedirs(download_dir, exist_ok=True)
    
    base_url = f"https://s3.amazonaws.com/{bucket_name}"
    list_url = f"{base_url}?list-type=2&prefix=&delimiter=%2F&encoding-type=url"
    
    try:
        response = requests.get(list_url, verify=False)
        
        if response.status_code == 200:
            print("Bucket accesible")
            
            directorios = re.findall(r'<Prefix>(.*?)</Prefix>', response.text)
            print(f"Directorios encontrados: {len(directorios)}")
            
            directorios.append("")
            
            total_archivos = 0
            
            for directorio in directorios:
                dir_name = directorio if directorio else "/ (raíz)"
                print(f"\nExplorando: {dir_name}")
                
                dir_url = f"{base_url}?list-type=2&prefix={directorio}&delimiter=%2F&encoding-type=url"
                dir_response = requests.get(dir_url, verify=False)
                
                if dir_response.status_code == 200:
                    archivos = re.findall(r'<Key>(.*?)</Key>', dir_response.text)
                    
                    for archivo in archivos:
                        if archivo == directorio:
                            continue
                            
                        print(f"   Encontrado: {archivo}")
                        total_archivos += 1
                        
                        download_url = f"{base_url}/{archivo}"
                        print(f"      Descargando...")
                        
                        file_response = requests.get(download_url, verify=False)
                        
                        if file_response.status_code == 200:
                            local_path = os.path.join(download_dir, archivo)
                            os.makedirs(os.path.dirname(local_path), exist_ok=True)
                            
                            with open(local_path, 'wb') as f:
                                f.write(file_response.content)
                            
                            print(f"      Guardado: {local_path}")
                        else:
                            print(f"      Error {file_response.status_code}")
                
                elif dir_response.status_code == 403:
                    print(f"   Sin permisos para: {dir_name}")
                else:
                    print(f"   Error {dir_response.status_code} en: {dir_name}")
            
            print(f"\nRESUMEN:")
            print(f"   Total archivos: {total_archivos}")
            print(f"   Directorio: {os.path.abspath(download_dir)}")
            
        elif response.status_code == 403:
            print("Sin permisos para acceder al bucket")
        elif response.status_code == 404:
            print("Bucket no existe")
        else:
            print(f"Error {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión: {e}")

if __name__ == "__main__":
    bucket_name = input("Nombre del bucket: ")
    enumerar_s3(bucket_name)
EOF

    cat > s3_boto3_lab.py << 'EOF'
#!/usr/bin/env python3

import boto3
import json
import os
from datetime import datetime

def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def whoami_aws():
    print("\nIdentificando usuario actual (STS)...")
    
    sts_client = boto3.client('sts')
    
    try:
        caller_info = sts_client.get_caller_identity()
        print(f"   Usuario ID: {caller_info['UserId']}")
        print(f"   Cuenta AWS: {caller_info['Account']}")
        print(f"   ARN: {caller_info['Arn']}")
        return True
    except Exception as e:
        print(f"   ERROR: {e}")
        print("   Verificar credenciales AWS")
        return False

def enumerar_s3_boto3(bucket_name):
    print(f"\nEnumerando bucket con Boto3: {bucket_name}")
    
    s3_client = boto3.client('s3')
    download_dir = f"boto3_downloads_{bucket_name}"
    
    try:
        os.makedirs(download_dir, exist_ok=True)
        os.chdir(download_dir)
        print(f"   Directorio creado: {download_dir}")
    except Exception as e:
        print(f"   Error creando directorio: {e}")
        return
    
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        
        if 'Contents' not in response:
            print("   Bucket vacío o sin permisos")
            return
        
        print(f"   Archivos encontrados: {len(response['Contents'])}")
        
        for obj in response['Contents']:
            file_name = obj['Key']
            file_size = obj['Size']
            last_modified = obj['LastModified']
            
            print(f"   Archivo: {file_name}")
            print(f"      Tamaño: {file_size} bytes")
            print(f"      Modificado: {last_modified}")
            print(f"      Descargando...")
            
            try:
                if '/' in file_name:
                    os.makedirs(os.path.dirname(file_name), exist_ok=True)
                
                with open(file_name, 'wb') as f:
                    s3_client.download_fileobj(bucket_name, file_name, f)
                
                print(f"      Descargado exitosamente")
                
            except Exception as e:
                print(f"      Error descargando: {e}")
        
        os.chdir('..')
        print(f"\nDescarga completada en: {os.path.abspath(download_dir)}")
        
    except Exception as e:
        print(f"   Error accediendo al bucket: {e}")

def enumerar_secrets_manager():
    print(f"\nEnumerando AWS Secrets Manager...")
    
    try:
        secrets_client = boto3.client('secretsmanager')
        response = secrets_client.list_secrets()
        
        if 'SecretList' not in response or not response['SecretList']:
            print("   No se encontraron secretos o sin permisos")
            return
        
        print(f"   Secretos encontrados: {len(response['SecretList'])}")
        
        for secret in response['SecretList']:
            secret_name = secret['Name']
            print(f"\n   Secreto: {secret_name}")
            
            if 'Description' in secret:
                print(f"      Descripción: {secret['Description']}")
            
            try:
                secret_value = secrets_client.get_secret_value(SecretId=secret_name)
                print(f"      Acceso exitoso al secreto")
                
                if 'SecretString' in secret_value:
                    secret_length = len(secret_value['SecretString'])
                    print(f"      Longitud: {secret_length} caracteres")
                    preview = secret_value['SecretString'][:10] + "..."
                    print(f"      Preview: {preview}")
                
            except Exception as e:
                print(f"      Sin permisos para leer el secreto: {str(e)}")
    
    except Exception as e:
        print(f"   Error accediendo a Secrets Manager: {e}")

def main():
    print("Laboratorio Boto3 - AWS SDK")
    print("=" * 40)
    
    if not whoami_aws():
        print("Error de autenticación. Verificar credenciales AWS.")
        return
    
    bucket_name = input("\nIngresa el nombre del bucket S3: ").strip()
    
    if not bucket_name:
        print("Nombre de bucket requerido")
        return
    
    enumerar_s3_boto3(bucket_name)
    
    continuar = input("\n¿Enumerar Secrets Manager? (y/N): ").lower().startswith('y')
    if continuar:
        enumerar_secrets_manager()
    
    print("\nLaboratorio completado!")

if __name__ == "__main__":
    main()
EOF

    chmod +x s3_enumerator.py s3_boto3_lab.py
    
    print_status "Scripts del laboratorio creados"
}

create_burp_config_script() {
    cat > configure_burp_proxy.sh << 'EOF'
#!/bin/bash

print_status() {
    echo "[$(date '+%H:%M:%S')] $1"
}

print_status "Configurando proxy para Burp Suite..."

export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

print_status "Descargando certificado de Burp..."
curl -s http://127.0.0.1:8080/cert --output ./certificate.cer

if [ ! -f certificate.cer ]; then
    echo "Error: No se pudo descargar el certificado de Burp"
    echo "Asegúrate de que Burp Suite esté ejecutándose en 127.0.0.1:8080"
    exit 1
fi

print_status "Convirtiendo certificado a formato PEM..."
openssl x509 -inform der -in ./certificate.cer -out ./certificate.pem

export AWS_CA_BUNDLE="$(pwd)/certificate.pem"

print_status "Configuración de proxy completada"
print_status "Variables de entorno configuradas:"
echo "  HTTP_PROXY=$HTTP_PROXY"
echo "  HTTPS_PROXY=$HTTPS_PROXY"
echo "  AWS_CA_BUNDLE=$AWS_CA_BUNDLE"
echo ""
echo "Para usar en la sesión actual, ejecuta:"
echo "  source configure_burp_proxy.sh"
EOF

    chmod +x configure_burp_proxy.sh
    print_status "Script de configuración de Burp creado"
}

create_cleanup_script() {
    cat > cleanup_lab.sh << 'EOF'
#!/bin/bash

BUCKET_PREFIX="aws-lab-s3"

print_status() {
    echo "[$(date '+%H:%M:%S')] $1"
}

print_status "Limpiando entorno del laboratorio..."

print_status "Eliminando buckets del laboratorio..."
aws s3 ls | grep "$BUCKET_PREFIX" | awk '{print $3}' | while read bucket; do
    if [ ! -z "$bucket" ]; then
        print_status "Eliminando contenido del bucket: $bucket"
        aws s3 rm s3://$bucket --recursive --quiet 2>/dev/null
        print_status "Eliminando bucket: $bucket"
        aws s3 rb s3://$bucket --force 2>/dev/null
    fi
done

print_status "Eliminando archivos locales..."
rm -rf lab_files/ descargas_* boto3_downloads_* 2>/dev/null
rm -f certificate.cer certificate.pem 2>/dev/null

print_status "Limpieza completada"
EOF

    chmod +x cleanup_lab.sh
    print_status "Script de limpieza creado"
}

create_readme() {
    cat > README.md << EOF
# Laboratorio AWS S3 - Enumeración y Exfiltración

## Configuración Automática

### Requisitos
- AWS CLI instalado y configurado
- Python 3 con pip
- OpenSSL y curl

### Instalación
\`\`\`bash
# Clonar o descargar los archivos
# Ejecutar configuración automática
./setup_lab.sh
\`\`\`

### Uso

#### Laboratorio Básico (requests)
\`\`\`bash
python3 s3_enumerator.py
# Ingresa: $BUCKET_NAME
\`\`\`

#### Laboratorio Avanzado (Boto3)
\`\`\`bash
python3 s3_boto3_lab.py
# Ingresa: $BUCKET_NAME
\`\`\`

#### Con Burp Suite
\`\`\`bash
# 1. Abrir Burp Suite Community
# 2. Configurar proxy
source configure_burp_proxy.sh

# 3. Ejecutar scripts normalmente
python3 s3_enumerator.py
\`\`\`

### Información del Bucket
- Nombre: \`$BUCKET_NAME\`
- Archivos: 8 archivos en 3 directorios
- Contenido: Archivos de configuración, logs, credenciales

### Limpieza
\`\`\`bash
./cleanup_lab.sh
\`\`\`

### Estructura
\`\`\`
/
├── index.html
├── directorio1/
│   ├── server_config.txt
│   └── app_config.json
├── directorio2/
│   ├── users.csv
│   └── access_logs.txt
└── directorio3/
    ├── credentials.txt
    └── backup_config.json
\`\`\`

### Scripts Incluidos
- \`s3_enumerator.py\` - Enumeración con requests
- \`s3_boto3_lab.py\` - Enumeración con Boto3
- \`configure_burp_proxy.sh\` - Configuración de proxy
- \`cleanup_lab.sh\` - Limpieza del entorno
EOF

    print_status "README creado"
}

main() {
    print_status "Iniciando configuración del laboratorio AWS"
    
    check_requirements
    install_python_dependencies
    setup_aws_credentials
    create_lab_files
    create_s3_bucket
    create_lab_scripts
    create_burp_config_script
    create_cleanup_script
    create_readme
    
    rm -rf lab_files/
    
    print_status "Configuración completada exitosamente"
    echo ""
    echo "INFORMACIÓN DEL LABORATORIO:"
    echo "  Bucket creado: $BUCKET_NAME"
    echo "  Scripts disponibles:"
    echo "    - s3_enumerator.py (requests)"
    echo "    - s3_boto3_lab.py (Boto3)"
    echo "    - configure_burp_proxy.sh (Burp Suite)"
    echo "    - cleanup_lab.sh (limpieza)"
    echo ""
    echo "Para empezar:"
    echo "  python3 s3_enumerator.py"
    echo "  (usar bucket: $BUCKET_NAME)"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
