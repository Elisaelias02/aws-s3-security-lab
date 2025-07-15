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
    
    local missing_reqs=()
    
    command -v aws >/dev/null 2>&1 || missing_reqs+=("AWS CLI")
    command -v python3 >/dev/null 2>&1 || missing_reqs+=("Python3")
    command -v pip3 >/dev/null 2>&1 || missing_reqs+=("pip3")
    command -v openssl >/dev/null 2>&1 || missing_reqs+=("OpenSSL")
    command -v curl >/dev/null 2>&1 || missing_reqs+=("curl")
    
    if [ ${#missing_reqs[@]} -ne 0 ]; then
        print_error "Faltan requisitos: ${missing_reqs[*]}"
        echo "Instalar con:"
        echo "  Ubuntu/Debian: sudo apt update && sudo apt install awscli python3 python3-pip openssl curl"
        echo "  macOS: brew install awscli python3 openssl curl"
        exit 1
    fi
    
    print_status "Requisitos verificados"
}

install_python_dependencies() {
    print_status "Verificando dependencias Python..."
    
    if python3 -c "import boto3, requests, urllib3" 2>/dev/null; then
        print_status "Dependencias ya instaladas"
        return 0
    fi
    
    print_status "Instalando dependencias Python..."
    
    local deps=("boto3" "requests" "urllib3")
    local failed_deps=()
    
    for dep in "${deps[@]}"; do
        print_status "Instalando $dep..."
        if ! timeout 30 pip3 install --user --quiet "$dep" 2>/dev/null; then
            if ! timeout 30 python3 -m pip install --user --quiet "$dep" 2>/dev/null; then
                failed_deps+=("$dep")
                print_error "Error instalando $dep"
            fi
        fi
    done
    
    if [ ${#failed_deps[@]} -ne 0 ]; then
        print_error "No se pudieron instalar: ${failed_deps[*]}"
        echo "Intenta manualmente: pip3 install --user ${failed_deps[*]}"
        exit 1
    fi
    
    if ! python3 -c "import boto3, requests, urllib3" 2>/dev/null; then
        print_error "Las dependencias no se importan correctamente"
        exit 1
    fi
    
    print_status "Dependencias instaladas correctamente"
}

setup_aws_credentials() {
    print_status "Verificando credenciales AWS..."
    
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        print_error "Credenciales AWS no configuradas"
        echo ""
        echo "Configurar credenciales AWS:"
        echo "1. Crear usuario IAM en AWS Console:"
        echo "   - Nombre: $IAM_USER" 
        echo "   - Política: AmazonS3FullAccess"
        echo "   - Crear clave de acceso"
        echo ""
        echo "2. Configurar AWS CLI:"
        echo "   aws configure"
        echo "   (Ingresar Access Key ID, Secret Key, región us-east-1)"
        echo ""
        echo "3. Ejecutar este script nuevamente"
        exit 1
    fi
    
    local caller_info
    if ! caller_info=$(aws sts get-caller-identity 2>/dev/null); then
        print_error "Error obteniendo información del usuario"
        exit 1
    fi
    
    local account_id user_arn
    account_id=$(echo "$caller_info" | python3 -c "import sys, json; print(json.load(sys.stdin)['Account'])" 2>/dev/null)
    user_arn=$(echo "$caller_info" | python3 -c "import sys, json; print(json.load(sys.stdin)['Arn'])" 2>/dev/null)
    
    print_status "Autenticado como: $user_arn"
    print_status "Cuenta AWS: $account_id"
}

create_lab_files() {
    print_status "Creando archivos del laboratorio..."
    
    local lab_dir="lab_files_temp"
    rm -rf "$lab_dir" 2>/dev/null || true
    mkdir -p "$lab_dir"/{directorio1,directorio2,directorio3}
    
    cat > "$lab_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS S3 Security Laboratory</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #232f3e; border-bottom: 3px solid #ff9900; padding-bottom: 10px; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .warning { background: #fff3e0; padding: 15px; border-radius: 4px; margin: 20px 0; border-left: 4px solid #ff9900; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AWS S3 Security Laboratory</h1>
        <div class="info">
            <p><strong>Laboratorio educativo</strong> para aprender técnicas de enumeración y análisis de buckets S3.</p>
        </div>
        <h2>Estructura del laboratorio:</h2>
        <ul>
            <li><strong>directorio1/</strong> - Archivos de configuración del sistema</li>
            <li><strong>directorio2/</strong> - Logs y datos de usuarios</li>
            <li><strong>directorio3/</strong> - Información confidencial</li>
        </ul>
        <div class="warning">
            <p><strong>Todo Listo.</p>
        </div>
        <footer>
            <p>Creado por Elisa Elias | Bucket: <code>BUCKET_PLACEHOLDER</code></p>
        </footer>
    </div>
</body>
</html>
EOF

    cat > "$lab_dir/directorio1/server_config.txt" << 'EOF'
SERVER CONFIGURATION REPORT - PRODUCTION ENVIRONMENT

=== SYSTEM INFORMATION ===
Hostname: web-prod-01.company.local
IP Address: 10.0.1.100
Public IP: 203.0.113.50
Operating System: Ubuntu 20.04.3 LTS
Kernel Version: 5.4.0-88-generic
Last System Update: 2025-05-22 02:00:00 UTC

=== NETWORK CONFIGURATION ===
Primary Interface: eth0
Gateway: 10.0.1.1
DNS Servers: 8.8.8.8, 1.1.1.1, 10.0.1.10
Firewall Status: UFW Active
Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)

=== INSTALLED SERVICES ===
- Nginx 1.18.0 (Active)
- PostgreSQL 12.8 (Active) 
- Redis 6.0.16 (Active)
- Node.js 16.14.2 (Active)

=== SECURITY CONFIGURATION ===
SSH Key Authentication: Enabled
Password Authentication: Disabled
Root Login: Disabled
Fail2ban: Active
Automatic Updates: Enabled

Laboratory ID: LAB-S3-ENUM-001
Environment: Production Simulation
Access Level: Public Read
Last Scan: 2025-05-22 10:30:15 UTC
EOF

    cat > "$lab_dir/directorio1/app_config.json" << 'EOF'
{
    "application": {
        "name": "CorporatePortal",
        "version": "3.2.1",
        "environment": "production",
        "debug": false,
        "maintenance_mode": false
    },
    "database": {
        "host": "db-cluster.internal.company.com",
        "port": 5432,
        "name": "corporate_portal_prod",
        "username": "app_user",
        "ssl_mode": "require",
        "connection_pool": {
            "min_connections": 5,
            "max_connections": 100,
            "timeout": 30
        }
    },
    "redis": {
        "host": "redis-cluster.internal.company.com",
        "port": 6379,
        "database": 0,
        "password_protected": true
    },
    "external_services": {
        "payment_gateway": {
            "provider": "stripe",
            "webhook_endpoint": "/api/webhooks/stripe",
            "api_version": "2022-11-15"
        },
        "email_service": {
            "provider": "sendgrid",
            "from_address": "noreply@company.com"
        },
        "monitoring": {
            "provider": "datadog",
            "environment": "production"
        }
    },
    "security": {
        "jwt_expiration": 3600,
        "session_timeout": 1800,
        "rate_limiting": {
            "enabled": true,
            "requests_per_minute": 100
        },
        "cors": {
            "enabled": true,
            "allowed_origins": ["https://company.com", "https://app.company.com"]
        }
    }
}
EOF

    cat > "$lab_dir/directorio2/users_export.csv" << 'EOF'
ID,Username,Email,Department,Role,LastLogin,Status,CreatedDate
001,admin,admin@company.com,IT,Administrator,2025-05-22 09:45:23,Active,2023-01-15
002,maria.garcia,maria.garcia@company.com,Marketing,Manager,2025-05-22 08:30:12,Active,2023-02-20
003,juan.lopez,juan.lopez@company.com,Sales,Representative,2025-05-21 17:22:45,Active,2023-03-10
004,ana.rodriguez,ana.rodriguez@company.com,HR,Manager,2025-05-22 07:15:33,Active,2023-01-28
005,carlos.martinez,carlos.martinez@company.com,IT,Developer,2025-05-22 09:12:56,Active,2023-04-05
006,lucia.fernandez,lucia.fernandez@company.com,Finance,Analyst,2025-05-19 16:45:22,Active,2023-05-12
007,miguel.santos,miguel.santos@company.com,Operations,Supervisor,2025-05-22 06:30:11,Active,2023-06-08
008,patricia.morales,patricia.morales@company.com,Legal,Counsel,2025-05-20 14:20:35,Active,2023-07-15
009,roberto.jimenez,roberto.jimenez@company.com,IT,Security Analyst,2025-05-22 10:05:44,Active,2023-08-22
010,sandra.vargas,sandra.vargas@company.com,Customer Service,Representative,2025-05-21 15:30:28,Active,2023-09-10
EOF

    cat > "$lab_dir/directorio2/application_logs.txt" << 'EOF'
[2025-05-22 06:00:01] INFO  System startup initiated
[2025-05-22 06:00:02] INFO  Loading application configuration
[2025-05-22 06:00:03] INFO  Database connection pool initialized (5/100 connections)
[2025-05-22 06:00:04] INFO  Redis connection established
[2025-05-22 06:00:05] INFO  Security modules loaded successfully
[2025-05-22 06:00:06] INFO  Application ready to receive requests
[2025-05-22 08:15:22] INFO  User login: maria.garcia@company.com from IP 192.168.1.50
[2025-05-22 08:30:45] WARNING Failed login attempt for user: test.user@fake.com from IP 203.0.113.100
[2025-05-22 08:31:02] WARNING Failed login attempt for user: admin from IP 203.0.113.100
[2025-05-22 08:31:15] WARNING Failed login attempt for user: administrator from IP 203.0.113.100
[2025-05-22 08:31:30] ERROR  IP 203.0.113.100 blocked after 3 failed login attempts
[2025-05-22 09:12:33] INFO  User login: carlos.martinez@company.com from IP 192.168.1.75
[2025-05-22 09:45:12] INFO  User login: admin@company.com from IP 192.168.1.10
[2025-05-22 10:30:55] WARNING High CPU usage detected: 87% (threshold: 85%)
[2025-05-22 10:35:21] INFO  Automatic scaling triggered: +2 instances
[2025-05-22 11:00:00] INFO  Hourly backup completed successfully
[2025-05-22 11:15:44] WARNING Suspicious file access detected: /etc/passwd from user roberto.jimenez
[2025-05-22 11:16:00] INFO  Security scan initiated by system
[2025-05-22 11:20:33] INFO  Security scan completed: 1 warning, 0 critical issues
[2025-05-22 12:00:00] INFO  Daily maintenance window started
[2025-05-22 12:05:15] INFO  Database optimization completed
[2025-05-22 12:10:30] INFO  Cache cleared and rebuilt
[2025-05-22 12:15:00] INFO  Maintenance window completed
EOF

    cat > "$lab_dir/directorio3/production_secrets.txt" << 'EOF'
=== PRODUCTION ENVIRONMENT SECRETS ===
Classification: CONFIDENTIAL
Access Level: Restricted to DevOps and Senior Staff Only

=== DATABASE CREDENTIALS ===
Production Database Cluster:
  Primary Host: db-prod-primary.internal.company.com
  Replica Host: db-prod-replica.internal.company.com
  Database: corporate_portal_prod
  Username: prod_app_user
  Password: PrOd_DB_P@ssw0rd_2025!
  Port: 5432
  Connection String: postgresql://prod_app_user:PrOd_DB_P@ssw0rd_2025!@db-prod-primary.internal.company.com:5432/corporate_portal_prod

=== REDIS CREDENTIALS ===
Redis Cluster:
  Host: redis-prod.internal.company.com
  Port: 6379
  Password: Red1s_Pr0d_K3y_2025#
  Database: 0

=== API KEYS AND TOKENS ===
Stripe API (Payment Processing):
  Public Key: pk_live_51J1234567890abcdefghijklmnopqrstuvwxyz
  Secret Key: sk_live_51J1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef
  Webhook Secret: whsec_1234567890abcdefghijklmnopqrstuvwxyz

SendGrid API (Email Service):
  API Key: SG.1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyz1234567890abcd
  From Address: noreply@company.com

JWT Signing Key:
  Secret: JwT_S1gn1ng_K3y_V3ry_S3cur3_2025_Pr0duct10n!
  Algorithm: HS256
  Expiration: 3600 seconds

=== ENCRYPTION KEYS ===
AES Encryption Key (Data at Rest):
  Key: 2B7E151628AED2A6ABF7158809CF4F3C2B7E151628AED2A6ABF7158809CF4F3C
  Algorithm: AES-256-GCM
  
RSA Private Key (SSL/TLS):
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7SMT6GUxJmwm3v4Z8N5cQ2+3a1b2C3d4E5f6G7h8I9j0K1l2
M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2G3h4I5j6K7l8M9n0O1p2Q3r4
[TRUNCATED FOR SECURITY - Full key would be much longer]
-----END RSA PRIVATE KEY-----

=== AWS CREDENTIALS (Service Accounts) ===
S3 Backup Service:
  Access Key ID: AKIAI44QH8DHBEXAMPLE123
  Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY456
  Bucket: company-prod-backups-encrypted

CloudWatch Monitoring:
  Access Key ID: AKIAI55RH9EIBFEXAMPLE789
  Secret Access Key: xKbmrYVuofFN/L8NEOFH/cQyRgjDBFXAMPLEKEY012

=== SECURITY NOTES ===
Last Password Rotation: 2025-04-15
Next Scheduled Rotation: 2025-07-15
Access Log Location: /var/log/secrets-access.log
Emergency Contact: security@company.com

WARNING: This file contains production secrets. Unauthorized access or 
distribution is strictly prohibited and may result in termination and 
legal action. All access is logged and monitored.

Generated: 2025-05-22 02:00:00 UTC
Expires: 2025-08-22 02:00:00 UTC
EOF

    cat > "$lab_dir/directorio3/backup_configuration.json" << 'EOF'
{
    "backup_system": {
        "version": "2.1.4",
        "environment": "production",
        "last_updated": "2025-05-22T02:00:00Z"
    },
    "encryption": {
        "enabled": true,
        "algorithm": "AES-256-GCM",
        "key_rotation_days": 90,
        "current_key_id": "backup-key-2025-05-001",
        "master_key": "BaCkUp_M@st3r_K3y_AES256_2025_Pr0duct10n_V3ry_S3cur3!"
    },
    "destinations": {
        "primary": {
            "type": "aws_s3",
            "bucket": "company-production-backups-primary",
            "region": "us-east-1",
            "storage_class": "STANDARD_IA",
            "credentials": {
                "access_key_id": "AKIAI33GH7FIBEXAMPLE456",
                "secret_access_key": "yLcnsZWupgGP/M9OEQG/dRzRhjECGXAMPLEKEY789",
                "role_arn": "arn:aws:iam::123456789012:role/BackupServiceRole"
            }
        },
        "secondary": {
            "type": "aws_s3",
            "bucket": "company-production-backups-secondary", 
            "region": "us-west-2",
            "storage_class": "GLACIER",
            "credentials": {
                "access_key_id": "AKIAI44GH8EIBEXAMPLE123",
                "secret_access_key": "zMdotAXvqhHQ/N0PFRI/eSaSikFDHYAMPLEKEY012"
            }
        }
    },
    "schedule": {
        "database_full_backup": {
            "frequency": "daily",
            "time": "02:00 UTC",
            "retention_days": 30
        },
        "database_incremental": {
            "frequency": "hourly", 
            "retention_days": 7
        },
        "application_files": {
            "frequency": "daily",
            "time": "03:00 UTC",
            "retention_days": 90
        },
        "system_configuration": {
            "frequency": "weekly",
            "day": "sunday",
            "time": "04:00 UTC",
            "retention_days": 365
        }
    },
    "notification": {
        "smtp_server": "smtp.company.com",
        "smtp_port": 587,
        "username": "backup-system@company.com",
        "password": "SMTP_B@ckup_P@ssw0rd_2025!",
        "recipients": [
            "devops@company.com",
            "infrastructure@company.com",
            "security@company.com"
        ]
    },
    "monitoring": {
        "cloudwatch_logs": {
            "log_group": "/aws/backup/production",
            "log_stream": "backup-operations"
        },
        "metrics": {
            "backup_duration": "enabled",
            "backup_size": "enabled", 
            "success_rate": "enabled"
        }
    },
    "last_backup_info": {
        "timestamp": "2025-05-22T02:00:00Z",
        "status": "completed",
        "duration_minutes": 45,
        "size_gb": 127.3,
        "files_backed_up": 234567
    }
}
EOF

    print_status "Archivos del laboratorio creados"
}

create_s3_bucket() {
    print_status "Creando bucket S3: $BUCKET_NAME"
    
    if ! aws s3 mb s3://"$BUCKET_NAME" 2>/dev/null; then
        print_error "Error creando bucket. Posibles causas:"
        echo "  - Nombre ya existe (muy poco probable con timestamp)"
        echo "  - Sin permisos para crear buckets"
        echo "  - Problema de conectividad"
        exit 1
    fi
    
    print_status "Bucket creado exitosamente"
    
    print_status "Subiendo archivos al bucket..."
    if ! aws s3 cp lab_files_temp/ s3://"$BUCKET_NAME"/ --recursive --quiet; then
        print_error "Error subiendo archivos al bucket"
        print_status "Limpiando bucket creado..."
        aws s3 rb s3://"$BUCKET_NAME" --force 2>/dev/null || true
        exit 1
    fi
    
    print_status "Verificando contenido del bucket..."
    local file_count
    if ! file_count=$(aws s3 ls s3://"$BUCKET_NAME" --recursive 2>/dev/null | wc -l); then
        print_error "Error verificando contenido del bucket"
        exit 1
    fi
    
    if [ "$file_count" -eq 0 ]; then
        print_error "No se subieron archivos al bucket"
        exit 1
    fi
    
    print_status "Archivos subidos: $file_count"
    
    rm -rf lab_files_temp
}

create_lab_scripts() {
    print_status "Creando scripts del laboratorio..."
    
    cat > s3_enumerator.py << 'EOF'
#!/usr/bin/env python3

import requests
import re
import os
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def enumerar_s3(bucket_name):
    print(f"Enumerando bucket: {bucket_name}")
    
    download_dir = f"descargas_{bucket_name}"
    os.makedirs(download_dir, exist_ok=True)
    
    base_url = f"https://s3.amazonaws.com/{bucket_name}"
    list_url = f"{base_url}?list-type=2&prefix=&delimiter=%2F&encoding-type=url"
    
    try:
        print("Realizando solicitud inicial al bucket...")
        response = requests.get(list_url, verify=False, timeout=30)
        
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
                
                try:
                    dir_response = requests.get(dir_url, verify=False, timeout=30)
                    
                    if dir_response.status_code == 200:
                        archivos = re.findall(r'<Key>(.*?)</Key>', dir_response.text)
                        
                        for archivo in archivos:
                            if archivo == directorio:
                                continue
                                
                            print(f"   Encontrado: {archivo}")
                            total_archivos += 1
                            
                            download_url = f"{base_url}/{archivo}"
                            print(f"      Descargando...")
                            
                            try:
                                file_response = requests.get(download_url, verify=False, timeout=30)
                                
                                if file_response.status_code == 200:
                                    local_path = os.path.join(download_dir, archivo)
                                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                                    
                                    with open(local_path, 'wb') as f:
                                        f.write(file_response.content)
                                    
                                    file_size = len(file_response.content)
                                    print(f"      Guardado: {local_path} ({file_size} bytes)")
                                else:
                                    print(f"      Error {file_response.status_code}")
                            except requests.exceptions.RequestException as e:
                                print(f"      Error descargando: {e}")
                    
                    elif dir_response.status_code == 403:
                        print(f"   Sin permisos para: {dir_name}")
                    else:
                        print(f"   Error {dir_response.status_code} en: {dir_name}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"   Error de conexión para {dir_name}: {e}")
            
            print(f"\nRESUMEN:")
            print(f"   Total archivos: {total_archivos}")
            print(f"   Directorio: {os.path.abspath(download_dir)}")
            
        elif response.status_code == 403:
            print("Sin permisos para acceder al bucket")
        elif response.status_code == 404:
            print("Bucket no existe")
        else:
            print(f"Error {response.status_code}: {response.text[:200]}")
            
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión: {e}")
        return False
    
    return True

def main():
    print("=" * 50)
    print("LABORATORIO S3 - ENUMERACIÓN CON REQUESTS")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        bucket_name = sys.argv[1]
    else:
        bucket_name = input("Nombre del bucket: ").strip()
    
    if not bucket_name:
        print("Error: Nombre de bucket requerido")
        sys.exit(1)
    
    success = enumerar_s3(bucket_name)
    
    if success:
        print("\nLaboratorio completado exitosamente")
    else:
        print("\nLaboratorio completado con errores")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

    cat > s3_boto3_lab.py << 'EOF'
#!/usr/bin/env python3

import boto3
import json
import os
import sys
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def whoami_aws():
    print("\nIdentificando usuario actual (STS)...")
    
    try:
        sts_client = boto3.client('sts')
        caller_info = sts_client.get_caller_identity()
        
        print(f"   Usuario ID: {caller_info['UserId']}")
        print(f"   Cuenta AWS: {caller_info['Account']}")
        print(f"   ARN: {caller_info['Arn']}")
        return True
        
    except NoCredentialsError:
        print("   ERROR: Credenciales AWS no encontradas")
        print("   Ejecutar: aws configure")
        return False
    except ClientError as e:
        print(f"   ERROR: {e}")
        return False
    except Exception as e:
        print(f"   ERROR: {e}")
        return False

def enumerar_s3_boto3(bucket_name):
    print(f"\nEnumerando bucket con Boto3: {bucket_name}")
    
    try:
        s3_client = boto3.client('s3')
        download_dir = f"boto3_downloads_{bucket_name}"
        
        os.makedirs(download_dir, exist_ok=True)
        original_dir = os.getcwd()
        os.chdir(download_dir)
        print(f"   Directorio creado: {download_dir}")
        
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        
        if 'Contents' not in response:
            print("   Bucket vacío o sin permisos")
            os.chdir(original_dir)
            return False
        
        print(f"   Archivos encontrados: {len(response['Contents'])}")
        
        downloaded_count = 0
        failed_count = 0
        
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
                
                downloaded_count += 1
                print(f"      Descargado exitosamente")
                
            except Exception as e:
                failed_count += 1
                print(f"      Error descargando: {e}")
        
        os.chdir(original_dir)
        print(f"\nDescarga completada en: {os.path.abspath(download_dir)}")
        print(f"Archivos descargados: {downloaded_count}")
        print(f"Archivos fallidos: {failed_count}")
        
        return True
        
    except ClientError as e:
        print(f"   Error de AWS: {e}")
        return False
    except Exception as e:
        print(f"   Error: {e}")
        return False

def enumerar_secrets_manager():
    print(f"\nEnumerando AWS Secrets Manager...")
    
    try:
        secrets_client = boto3.client('secretsmanager')
        response = secrets_client.list_secrets()
        
        if 'SecretList' not in response or not response['SecretList']:
            print("   No se encontraron secretos o sin permisos")
            return True
        
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
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                print(f"      Sin permisos para leer el secreto: {error_code}")
            except Exception as e:
                print(f"      Error: {e}")
        
        return True
    
    except ClientError as e:
        print(f"   Error de AWS: {e}")
        return False
    except Exception as e:
        print(f"   Error: {e}")
        return False

def main():
    print("=" * 50)
    print("LABORATORIO BOTO3 - AWS SDK")
    print("=" * 50)
    
    if not whoami_aws():
        print("Error de autenticación. Verificar credenciales AWS.")
        return False
    
    if len(sys.argv) > 1:
        bucket_name = sys.argv[1]
    else:
        bucket_name = input("\nIngresa el nombre del bucket S3: ").strip()
    
    if not bucket_name:
        print("Nombre de bucket requerido")
        return False
    
    if not enumerar_s3_boto3(bucket_name):
        print("Error en enumeración S3")
        return False
    
    continuar = input("\n¿Enumerar Secrets Manager? (y/N): ").lower().startswith('y')
    if continuar:
        enumerar_secrets_manager()
    
    print("\nLaboratorio completado!")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
EOF

    chmod +x s3_enumerator.py s3_boto3_lab.py
    
    print_status "Scripts del laboratorio creados"
}

create_burp_config_script() {
    print_status "Creando script de configuración para Burp Suite..."
    
    cat > configure_burp_proxy.sh << 'EOF'
#!/bin/bash

print_status() {
    echo "[$(date '+%H:%M:%S')] $1"
}

print_error() {
    echo "[ERROR] $1" >&2
}

check_burp_running() {
    if ! curl -s --connect-timeout 5 http://127.0.0.1:8080 >/dev/null 2>&1; then
        print_error "Burp Suite no está ejecutándose en 127.0.0.1:8080"
        echo ""
        echo "Para configurar Burp Suite:"
        echo "1. Abrir Burp Suite Community Edition"
        echo "2. Ir a Proxy → Options"
        echo "3. Verificar que esté escuchando en 127.0.0.1:8080"
        echo "4. Ejecutar este script nuevamente"
        return 1
    fi
    return 0
}

main() {
    print_status "Configurando proxy para Burp Suite..."
    
    if ! check_burp_running; then
        exit 1
    fi
    
    export HTTP_PROXY=http://127.0.0.1:8080
    export HTTPS_PROXY=http://127.0.0.1:8080
    
    print_status "Descargando certificado de Burp..."
    if ! curl -s --max-time 10 http://127.0.0.1:8080/cert --output ./certificate.cer; then
        print_error "No se pudo descargar el certificado de Burp"
        exit 1
    fi
    
    if [ ! -f certificate.cer ] || [ ! -s certificate.cer ]; then
        print_error "Certificado descargado está vacío o no existe"
        exit 1
    fi
    
    print_status "Convirtiendo certificado a formato PEM..."
    if ! openssl x509 -inform der -in ./certificate.cer -out ./certificate.pem 2>/dev/null; then
        print_error "Error convirtiendo certificado"
        exit 1
    fi
    
    export AWS_CA_BUNDLE="$(pwd)/certificate.pem"
    
    print_status "Configuración de proxy completada"
    echo ""
    echo "Variables de entorno configuradas:"
    echo "  HTTP_PROXY=$HTTP_PROXY"
    echo "  HTTPS_PROXY=$HTTPS_PROXY" 
    echo "  AWS_CA_BUNDLE=$AWS_CA_BUNDLE"
    echo ""
    echo "Para usar en la sesión actual:"
    echo "  source configure_burp_proxy.sh"
    echo ""
    echo "Para probar:"
    echo "  python3 s3_enumerator.py [bucket_name]"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
EOF

    chmod +x configure_burp_proxy.sh
    print_status "Script de configuración de Burp creado"
}

create_cleanup_script() {
    print_status "Creando script de limpieza..."
    
    cat > cleanup_lab.sh << 'EOF'
#!/bin/bash

BUCKET_PREFIX="aws-lab-s3"

print_status() {
    echo "[$(date '+%H:%M:%S')] $1"
}

cleanup_s3_buckets() {
    print_status "Buscando buckets del laboratorio..."
    
    local buckets
    if ! buckets=$(aws s3 ls 2>/dev/null | grep "$BUCKET_PREFIX" | awk '{print $3}'); then
        print_status "Error listando buckets o no hay buckets del laboratorio"
        return
    fi
    
    if [ -z "$buckets" ]; then
        print_status "No se encontraron buckets del laboratorio"
        return
    fi
    
    echo "$buckets" | while read -r bucket; do
        if [ ! -z "$bucket" ]; then
            print_status "Eliminando contenido del bucket: $bucket"
            aws s3 rm s3://"$bucket" --recursive --quiet 2>/dev/null || true
            
            print_status "Eliminando bucket: $bucket"
            aws s3 rb s3://"$bucket" --force 2>/dev/null || true
        fi
    done
}

cleanup_local_files() {
    print_status "Eliminando archivos locales..."
    
    local items_to_remove=(
        "lab_files_temp/"
        "descargas_*/"
        "boto3_downloads_*/"
        "certificate.cer"
        "certificate.pem"
    )
    
    for item in "${items_to_remove[@]}"; do
        if ls $item 1> /dev/null 2>&1; then
            rm -rf $item 2>/dev/null || true
            print_status "Eliminado: $item"
        fi
    done
}

main() {
    print_status "Iniciando limpieza del laboratorio..."
    
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        print_status "Credenciales AWS no configuradas, saltando limpieza de S3"
    else
        cleanup_s3_buckets
    fi
    
    cleanup_local_files
    
    print_status "Limpieza completada"
    echo ""
    echo "Para verificar que no queden buckets:"
    echo "  aws s3 ls | grep $BUCKET_PREFIX"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
EOF

    chmod +x cleanup_lab.sh
    print_status "Script de limpieza creado"
}

create_readme() {
    print_status "Creando documentación..."
    
    cat > README.md << EOF
# Laboratorio AWS S3 - Enumeración y Exfiltración

Laboratorio para aprender técnicas de enumeración y análisis de buckets S3 usando Python y Burp Suite.

## Características

- **Configuración automática** de entorno AWS
- **Dos enfoques de enumeración**: requests vs Boto3  
- **Interceptación de tráfico** con Burp Suite
- **Archivos realistas** para práctica
- **Limpieza automática** del entorno

## Instalación Rápida

\`\`\`bash
# Descargar y ejecutar
wget https://raw.githubusercontent.com/TU_USUARIO/aws-s3-security-lab/main/setup_lab.sh
chmod +x setup_lab.sh
./setup_lab.sh
\`\`\`

## Uso

### Información del Bucket Creado
El script creó el bucket: **$BUCKET_NAME**

### Laboratorio 1: Enumeración con requests
\`\`\`bash
python3 s3_enumerator.py $BUCKET_NAME
\`\`\`

### Laboratorio 2: Enumeración con Boto3
\`\`\`bash
python3 s3_boto3_lab.py $BUCKET_NAME
\`\`\`

### Laboratorio 3: Con Burp Suite
\`\`\`bash
# 1. Abrir Burp Suite Community
# 2. Configurar proxy
source configure_burp_proxy.sh

# 3. Ejecutar scripts normalmente
python3 s3_enumerator.py $BUCKET_NAME
\`\`\`

## Estructura del Bucket

\`\`\`
$BUCKET_NAME/
├── index.html                          # Página principal
├── directorio1/
│   ├── server_config.txt              # Configuración del servidor
│   └── app_config.json                # Configuración de aplicación
├── directorio2/
│   ├── users_export.csv               # Export de usuarios
│   └── application_logs.txt           # Logs de aplicación
└── directorio3/
    ├── production_secrets.txt         # Credenciales y secretos
    └── backup_configuration.json      # Configuración de backups
\`\`\`

## Requisitos

- AWS CLI configurado con credenciales válidas
- Python 3.6+ con pip
- Burp Suite Community (opcional)
- OpenSSL y curl

## Scripts Incluidos

- \`s3_enumerator.py\` - Enumeración con requests HTTP
- \`s3_boto3_lab.py\` - Enumeración con SDK oficial  
- \`configure_burp_proxy.sh\` - Configuración de proxy
- \`cleanup_lab.sh\` - Limpieza del entorno

## Limpieza

\`\`\`bash
./cleanup_lab.sh
\`\`\`

## Casos de Uso

- **Auditorías de seguridad** - Identificar buckets mal configurados
- **Respuesta a incidentes** - Recopilar evidencia rápidamente  
- **Educación** - Entender APIs de AWS y técnicas de enumeración
- **Red Team** - Automatizar reconocimiento de infraestructura

## Disclaimer

Este laboratorio es únicamente para fines educativos. Solo usar en cuentas AWS propias o con autorización explícita.
Hecho con amor por Elisa Elias. <3

## Troubleshooting

### Error de credenciales AWS
\`\`\`bash
aws configure
aws sts get-caller-identity
\`\`\`

### Error con Burp Suite
\`\`\`bash
# Verificar que Burp esté en 127.0.0.1:8080
curl http://127.0.0.1:8080
\`\`\`

### Error de dependencias Python
\`\`\`bash
pip3 install --user boto3 requests urllib3
\`\`\`
EOF

    print_status "README creado"
}

show_completion_info() {
    echo ""
    echo "=" * 60
    print_status "CONFIGURACIÓN COMPLETADA EXITOSAMENTE"
    echo "=" * 60
    echo ""
    echo "INFORMACIÓN DEL LABORATORIO:"
    echo "  Bucket creado: $BUCKET_NAME"
    echo "  Archivos subidos: 8 archivos en 3 directorios"
    echo ""
    echo "SCRIPTS DISPONIBLES:"
    echo "  s3_enumerator.py    - Laboratorio básico (requests)"
    echo "  s3_boto3_lab.py     - Laboratorio avanzado (Boto3)"
    echo "  configure_burp_proxy.sh - Configuración para Burp Suite"
    echo "  cleanup_lab.sh      - Limpieza automática"
    echo ""
    echo "PARA EMPEZAR:"
    echo "  python3 s3_enumerator.py $BUCKET_NAME"
    echo ""
    echo "CON BURP SUITE:"
    echo "  1. Abrir Burp Suite Community"
    echo "  2. source configure_burp_proxy.sh"
    echo "  3. python3 s3_enumerator.py $BUCKET_NAME"
    echo ""
    echo "LIMPIEZA:"
    echo "  ./cleanup_lab.sh"
    echo ""
}

main() {
    print_status "Iniciando configuración del laboratorio AWS"
    echo ""
    
    check_requirements
    install_python_dependencies
    setup_aws_credentials
    create_lab_files
    create_s3_bucket
    create_lab_scripts
    create_burp_config_script
    create_cleanup_script
    create_readme
    
    show_completion_info
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
