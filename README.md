# Portal DIM

Aplicacion web para gestion de infraestructura de red sobre NetDB (ndcli).

## Funcionalidades

- **Consultas ACS**: Busqueda de pools, subredes, VLANs, DNS, IPs y dispositivos en dominios ACS
- **Consultas IONOS**: Busqueda de subredes e IPs en dominios no-ACS
- **Gestion DNS**: Creacion y eliminacion de registros DNS (individual y masivo)
- **Importacion IPs**: Importacion masiva de IPs desde CSV
- **API REST**: Endpoints programaticos con autenticacion por API key

## Requisitos

- Python 3.9+
- Node.js 18+
- Acceso a ndcli (NetDB CLI)
- Credenciales LDAP corporativas

## Instalacion

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Crear archivo `.env`:

```
LDAP_BIND_PASSWORD=<password_ldap>
SESSION_SECRET=<secreto_32_caracteres_minimo>
FERNET_KEY=<clave_fernet_generada>
```

Generar FERNET_KEY:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Frontend

```bash
cd frontend
npm install
npm run build
```

## Ejecucion

```bash
cd backend
./run.sh
```

La aplicacion estara disponible en `http://localhost:4501`

## API REST

### Autenticacion

Usar header `X-API-Key` con una clave generada desde la interfaz web (pestana API).

### Endpoints ACS

| Endpoint | Descripcion |
|----------|-------------|
| `GET /api/v1/acs/pool/{name}` | Buscar pool por nombre |
| `GET /api/v1/acs/subnet/{cidr}` | Buscar subred por CIDR |
| `GET /api/v1/acs/vlan/{id}` | Buscar pools por VLAN |
| `GET /api/v1/acs/dns/{fqdn}` | Resolver FQDN |
| `GET /api/v1/acs/ip/{ip}` | Buscar informacion de IP |
| `GET /api/v1/acs/device/{name}` | Buscar por dispositivo |

### Endpoints IONOS

| Endpoint | Descripcion |
|----------|-------------|
| `GET /api/v1/ionos/subnet/{cidr}` | Buscar subred (excluye ACS) |
| `GET /api/v1/ionos/ip/{ip}` | Buscar IP (excluye ACS) |

### Ejemplo

```bash
curl -H "X-API-Key: dim_xxx..." "http://localhost:4501/api/v1/acs/ip/10.140.16.10"
```

## Estructura

```
dimportal/
├── backend/
│   ├── main.py          # API FastAPI
│   ├── models.py        # Esquemas Pydantic
│   ├── settings.py      # Configuracion layer3domains
│   ├── ndcli_exec.py    # Wrapper ndcli
│   └── parsers.py       # Parser de salida ndcli
├── frontend/
│   └── src/
│       ├── App.jsx      # Componente principal
│       └── api.js       # Cliente API
└── CLAUDE.md            # Guia para Claude Code
```

## Desarrollo

Frontend con hot-reload:
```bash
cd frontend
npm run dev
```

El servidor de desarrollo corre en `:5174` y hace proxy a `:4501`.
