#!/bin/bash
# =============================================================================
# Script de despliegue a produccion - Portal DIM
# =============================================================================
# Este script despliega los cambios desde el repositorio Git a produccion
# de forma segura, con backups y confirmaciones en cada paso.
# =============================================================================

set -e  # Salir si hay error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuracion
PROD_DIR="/home/isantolaya@arsyslan.es/dimportal"
BACKUP_DIR="/home/isantolaya@arsyslan.es"
GIT_REPO="https://github.com/darconada/dimportal.git"
PROD_FRONTEND_PORT="5173"
PROD_BACKEND_PORT="4500"

# Funciones
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

confirm() {
    echo -e "${YELLOW}"
    read -p "$1 (s/N): " response
    echo -e "${NC}"
    case "$response" in
        [sS][iI]|[sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# =============================================================================
# PASO 0: Verificaciones previas
# =============================================================================
echo ""
echo "=============================================="
echo "  DESPLIEGUE A PRODUCCION - Portal DIM"
echo "=============================================="
echo ""

log_info "Directorio de produccion: $PROD_DIR"
log_info "Puerto frontend produccion: $PROD_FRONTEND_PORT"
log_info "Puerto backend produccion: $PROD_BACKEND_PORT"
echo ""

if [ ! -d "$PROD_DIR" ]; then
    log_error "El directorio de produccion no existe: $PROD_DIR"
    exit 1
fi

if ! confirm "¿Continuar con el despliegue a produccion?"; then
    log_warning "Despliegue cancelado"
    exit 0
fi

# =============================================================================
# PASO 1: Crear backup
# =============================================================================
echo ""
log_info "PASO 1: Creando backup de produccion..."

BACKUP_NAME="dimportal.backup.$(date +%Y%m%d_%H%M%S)"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"

log_info "Backup se guardara en: $BACKUP_PATH"

if confirm "¿Crear backup ahora?"; then
    cp -r "$PROD_DIR" "$BACKUP_PATH"
    log_success "Backup creado: $BACKUP_PATH"
else
    log_warning "Backup omitido (no recomendado)"
fi

# =============================================================================
# PASO 2: Guardar configuracion actual
# =============================================================================
echo ""
log_info "PASO 2: Guardando configuracion actual..."

# Guardar .env si existe
if [ -f "$PROD_DIR/backend/.env" ]; then
    cp "$PROD_DIR/backend/.env" "/tmp/dimportal_prod_env.backup"
    log_success "Archivo .env guardado temporalmente"
else
    log_warning "No se encontro .env en produccion"
fi

# Guardar api_keys.json si existe
if [ -f "$PROD_DIR/backend/api_keys.json" ]; then
    cp "$PROD_DIR/backend/api_keys.json" "/tmp/dimportal_api_keys.backup"
    log_success "Archivo api_keys.json guardado temporalmente"
fi

# =============================================================================
# PASO 3: Inicializar Git si no existe
# =============================================================================
echo ""
log_info "PASO 3: Configurando Git..."

cd "$PROD_DIR"

if [ ! -d ".git" ]; then
    log_info "Inicializando repositorio Git..."
    git init
    git remote add origin "$GIT_REPO"
    log_success "Git inicializado y remote configurado"
else
    log_success "Git ya esta configurado"
    # Verificar que el remote es correcto
    CURRENT_REMOTE=$(git remote get-url origin 2>/dev/null || echo "none")
    if [ "$CURRENT_REMOTE" != "$GIT_REPO" ]; then
        log_warning "Remote actual: $CURRENT_REMOTE"
        if confirm "¿Actualizar remote a $GIT_REPO?"; then
            git remote set-url origin "$GIT_REPO"
            log_success "Remote actualizado"
        fi
    fi
fi

# =============================================================================
# PASO 4: Traer cambios de Git
# =============================================================================
echo ""
log_info "PASO 4: Descargando cambios del repositorio..."

if confirm "¿Descargar cambios de Git? (esto sobreescribira archivos locales)"; then
    git fetch origin
    git checkout main 2>/dev/null || git checkout -b main origin/main
    git reset --hard origin/main
    log_success "Cambios descargados y aplicados"
else
    log_warning "Descarga de Git omitida"
fi

# =============================================================================
# PASO 5: Restaurar configuracion
# =============================================================================
echo ""
log_info "PASO 5: Restaurando configuracion..."

# Restaurar .env
if [ -f "/tmp/dimportal_prod_env.backup" ]; then
    cp "/tmp/dimportal_prod_env.backup" "$PROD_DIR/backend/.env"
    log_success "Archivo .env restaurado"
    rm "/tmp/dimportal_prod_env.backup"
else
    log_warning "No hay .env para restaurar - deberas configurarlo manualmente"
fi

# Restaurar api_keys.json
if [ -f "/tmp/dimportal_api_keys.backup" ]; then
    cp "/tmp/dimportal_api_keys.backup" "$PROD_DIR/backend/api_keys.json"
    log_success "Archivo api_keys.json restaurado"
    rm "/tmp/dimportal_api_keys.backup"
fi

# =============================================================================
# PASO 6: Ajustar puertos para produccion
# =============================================================================
echo ""
log_info "PASO 6: Ajustando puertos para produccion..."

# Ajustar vite.config.js
VITE_CONFIG="$PROD_DIR/frontend/vite.config.js"
if [ -f "$VITE_CONFIG" ]; then
    sed -i "s/port: [0-9]*/port: $PROD_FRONTEND_PORT/" "$VITE_CONFIG"
    sed -i "s|'http://localhost:[0-9]*'|'http://localhost:$PROD_BACKEND_PORT'|" "$VITE_CONFIG"
    log_success "vite.config.js actualizado (puerto $PROD_FRONTEND_PORT, proxy a $PROD_BACKEND_PORT)"
fi

# Ajustar run.sh
RUN_SH="$PROD_DIR/backend/run.sh"
if [ -f "$RUN_SH" ]; then
    sed -i "s/--port [0-9]*/--port $PROD_BACKEND_PORT/" "$RUN_SH"
    log_success "run.sh actualizado (puerto $PROD_BACKEND_PORT)"
fi

# =============================================================================
# PASO 7: Instalar dependencias y build
# =============================================================================
echo ""
log_info "PASO 7: Instalando dependencias y haciendo build..."

if confirm "¿Ejecutar npm install y build del frontend?"; then
    cd "$PROD_DIR/frontend"

    # Instalar dependencias
    log_info "Ejecutando npm install..."
    npm install
    log_success "Dependencias instaladas"

    # Build
    log_info "Ejecutando npm run build..."
    npm run build
    log_success "Build completado"
else
    log_warning "Build omitido - deberas ejecutarlo manualmente"
fi

# =============================================================================
# PASO 8: Verificar entorno Python
# =============================================================================
echo ""
log_info "PASO 8: Verificando entorno Python..."

cd "$PROD_DIR/backend"

if [ ! -d ".venv" ]; then
    log_warning "No existe .venv - puede que necesites recrearlo"
    if confirm "¿Crear entorno virtual Python?"; then
        python3 -m venv .venv
        source .venv/bin/activate
        pip install -r requirements.txt
        log_success "Entorno virtual creado e instalado"
    fi
else
    log_success "Entorno virtual existe"
    if confirm "¿Actualizar dependencias Python?"; then
        source .venv/bin/activate
        pip install -r requirements.txt
        log_success "Dependencias Python actualizadas"
    fi
fi

# =============================================================================
# PASO 9: Resumen y siguientes pasos
# =============================================================================
echo ""
echo "=============================================="
echo "  DESPLIEGUE COMPLETADO"
echo "=============================================="
echo ""
log_success "Los cambios han sido desplegados a produccion"
echo ""
log_info "Siguientes pasos manuales:"
echo "  1. Reiniciar el backend de produccion:"
echo "     cd $PROD_DIR/backend"
echo "     ./stop.sh  # si existe"
echo "     ./run.sh"
echo ""
echo "  2. Verificar que la aplicacion funciona:"
echo "     http://servidor:$PROD_BACKEND_PORT"
echo ""
echo "  3. Si algo falla, restaurar backup:"
echo "     rm -rf $PROD_DIR"
echo "     mv $BACKUP_PATH $PROD_DIR"
echo ""
log_warning "IMPORTANTE: Revisa que el .env tenga la FERNET_KEY correcta"
echo ""
