import logging
import shlex
from typing import Dict, List, Optional, Set
import threading
import ipaddress
import re
import os
import ssl
import secrets
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import FileResponse
from starlette.staticfiles import StaticFiles
from ldap3 import Server, Connection, Tls, SUBTREE
from dotenv import load_dotenv
from pathlib import Path

from models import (
    ResultItem,
    LoginPayload,
    SessionInfo,
    ImportIPRequestItem,
    ImportIPPayload,
    ImportIPResponseItem,
    ImportExecutePayload,
    ImportExecuteResponseItem,
    ImportDryrunResponseItem,
)
from settings import LAYER3DOMAINS, LdapConfig, ACS_LAYER3DOMAINS, default_layer3domain
from ndcli_exec import (
    run_ndcli,
    with_layer3domain,
    NdcliError,
    set_ndcli_credentials,
    _ndcli_creds,
)
from cryptography.fernet import Fernet, InvalidToken
from parsers import (
    parse_show_subnet,
    parse_show_pool,
    extract_subnets_from_list_ips,
    parse_first_block,
)

# Carga .env desde la raíz del proyecto (padre de backend/) y fallback en backend/.env
ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")
load_dotenv(Path(__file__).resolve().parent / ".env")

# --- Sesiones ---

SESSION_COOKIE_NAME = "dim_session"
SESSION_STORE: Dict[str, Dict[str, str]] = {}
SESSION_MAX_ENTRIES = 2048
SESSION_SECRET = os.getenv("SESSION_SECRET", "CHANGE_ME_DIM_SESSION_SECRET")
SESSION_TTL = 900  # 15 minutos en segundos


FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    # Clave efímera si no se define; recomendable fijarla en .env
    FERNET_KEY = Fernet.generate_key().decode()
fernet = Fernet(FERNET_KEY.encode())

app = FastAPI(title="Portal DIM API")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False,
    session_cookie=SESSION_COOKIE_NAME,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VALID_TYPES = {"pool", "subnet", "vlan", "dns", "ip", "device"}
FALLBACK_TYPES = {"pool", "subnet", "vlan", "ip"}
LDAP_SETTINGS = LdapConfig()
# Configuración básica de logging (incluye nuestros mensajes en uvicorn.out)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Sanitizadores simples
POOL_RE = re.compile(r"^[a-z0-9._:-]+[a-z0-9]$", re.I)
VLAN_RE = re.compile(r"^\d{1,4}$")
FQDN_RE = re.compile(r"^[A-Za-z0-9._-]+\.?$")
ACS_POOL_PREFIXES = ("es-lgr-pl-acs", "es-mad-gsw-acs", "us-mia-mi1-acs", "es-gb-gsw-acs")


def ensure_l3d(l3d: Optional[str]) -> Optional[str]:
    if l3d is None:
        return None
    if l3d not in LAYER3DOMAINS:
        raise HTTPException(status_code=400, detail="layer3domain inválido")
    return l3d


def _layer3domain_candidates(override: Optional[str]) -> List[str]:
    if override:
        return [override]
    seen = set()
    ordered = []
    for candidate in [default_layer3domain(), *ACS_LAYER3DOMAINS]:
        if candidate and candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _detect_layer3domain_for_ip(ipstr: str) -> Optional[str]:
    """
    Devuelve el primer layer3domain donde `show ip <ip>` funciona según el orden:
    default -> 8560-arsys-rfc1918 -> dominios ACS.
    """
    try:
        ipaddress.ip_address(ipstr)
    except Exception:
        raise HTTPException(status_code=400, detail="IP inválida")

    domain_order: List[str] = []
    for candidate in [default_layer3domain(), "8560-arsys-rfc1918", *ACS_LAYER3DOMAINS]:
        if candidate and candidate not in domain_order:
            domain_order.append(candidate)

    last_error: Optional[Exception] = None
    for domain_name in domain_order:
        try:
            run_ndcli(with_layer3domain(["show", "ip", ipstr], domain_name))
            return domain_name
        except NdcliError as exc:
            if _looks_like_not_found(exc):
                last_error = exc
                continue
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

    if last_error:
        raise HTTPException(status_code=404, detail="No se encontró layer3domain para la IP")
    return None


def _ionos_layer3domain_candidates(override: Optional[str]) -> List[str]:
    """
    Orden para IONOS: override (si aplica y no es ACS), default, 8560-arsys-rfc1918, y el resto de dominios no ACS.
    """
    if override and override in ACS_LAYER3DOMAINS:
        raise HTTPException(status_code=400, detail="layer3domain no disponible para consultas IONOS")

    candidates: List[str] = []
    if override:
        candidates.append(override)
    for candidate in [default_layer3domain(), "8560-arsys-rfc1918", *LAYER3DOMAINS]:
        if candidate in ACS_LAYER3DOMAINS:
            continue
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _is_acs_pool(pool_name: str) -> bool:
    return any(pool_name.lower().startswith(pref) for pref in ACS_POOL_PREFIXES)


def _looks_like_not_found(err: NdcliError) -> bool:
    msg = (err.stderr or "").lower()
    return any(
        phrase in msg
        for phrase in [
            "not found",
            "does not exist",
            "no such",
            "no subnet",
            "no pool",
            "not an existing",
        ]
    )


def _perform_search(search_type: str, value: str, layer3domain: Optional[str]) -> List[ResultItem]:
    if search_type == "subnet":
        return handle_subnet(value, layer3domain)
    if search_type == "pool":
        return handle_pool(value, layer3domain)
    if search_type == "vlan":
        return handle_vlan(value, layer3domain)
    if search_type == "ip":
        return handle_ip(value, layer3domain)
    if search_type == "device":
        return handle_device(value)
    raise HTTPException(status_code=400, detail="Tipo de búsqueda no soportado")


def search_across_domains(search_type: str, value: str, override_l3d: Optional[str]) -> List[ResultItem]:
    candidates = _layer3domain_candidates(override_l3d)
    last_not_found: Optional[Exception] = None

    for domain in candidates:
        try:
            results = _perform_search(search_type, value, domain)
            if results:
                return results
        except HTTPException as exc:
            if exc.status_code == 404:
                last_not_found = exc
                continue
            raise
        except NdcliError as exc:
            if _looks_like_not_found(exc):
                last_not_found = exc
                continue
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

    if last_not_found:
        raise HTTPException(status_code=404, detail="Sin resultados DIM para la consulta")
    raise HTTPException(status_code=404, detail="Sin resultados DIM para la consulta")


def build_ldap_server():
    parsed = urlparse(LDAP_SETTINGS.server_url)
    host = parsed.hostname or LDAP_SETTINGS.server_url
    port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
    use_ssl = parsed.scheme == "ldaps"
    tls = None
    if use_ssl and not LDAP_SETTINGS.verify_ssl:
        tls = Tls(validate=ssl.CERT_NONE)
    return Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=None)


def authenticate_user(username: str, password: str) -> tuple[bool, Optional[str]]:
    username = (username or "").strip()
    if not username or not password:
        return False, None

    if not LDAP_SETTINGS.bind_password:
        raise HTTPException(status_code=500, detail="LDAP_BIND_PASSWORD no configurada en el servidor")

    server = build_ldap_server()

    # Bind de servicio
    try:
        service_conn = Connection(
            server,
            user=LDAP_SETTINGS.bind_dn,
            password=LDAP_SETTINGS.bind_password,
            auto_bind=True,
        )
    except Exception as exc:  # pylint: disable=broad-except
        raise HTTPException(status_code=502, detail="No se pudo conectar al LDAP (bind servicio)") from exc

    search_filter = f"({LDAP_SETTINGS.user_attribute}={username})"
    display_name: Optional[str] = None

    try:
        service_conn.search(
            search_base=LDAP_SETTINGS.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["dn", "cn", "displayName"],
            size_limit=1,
        )
        if not service_conn.entries:
            service_conn.unbind()
            return False, None
        user_dn = service_conn.entries[0].entry_dn
        # Intentamos displayName, luego cn
        for attr in ("displayName", "cn"):
            value = getattr(service_conn.entries[0], attr, None)
            if value:
                display_name = str(value)
                break
    except Exception:  # pylint: disable=broad-except
        service_conn.unbind()
        raise HTTPException(status_code=500, detail="Error buscando el usuario en el directorio")

    try:
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()
    except Exception:
        service_conn.unbind()
        return False, None

    service_conn.unbind()
    return True, display_name


async def require_session(request: Request) -> str:
    sid = request.session.get("sid")
    data = SESSION_STORE.get(sid or "")
    if not data:
        raise HTTPException(status_code=401, detail="No autenticado")
    now = datetime.now(timezone.utc)
    last_seen: datetime = data.get("last_seen") or now
    if (now - last_seen).total_seconds() > SESSION_TTL:
        SESSION_STORE.pop(sid, None)
        raise HTTPException(status_code=401, detail="Sesión expirada")

    pwd_plain: Optional[str] = None
    enc_pwd = data.get("password")
    if enc_pwd:
        try:
            pwd_plain = fernet.decrypt(enc_pwd).decode()
        except InvalidToken:
            pwd_plain = None
    if not pwd_plain:
        logger.error("require_session sin password descifrada para usuario %s", data.get("user"))
        set_ndcli_credentials(None, None)
        raise HTTPException(status_code=401, detail="Sesión expirada")
    set_ndcli_credentials(data.get("user"), pwd_plain)
    data["last_seen"] = now
    return data["user"]


def store_session(user: str, display_name: Optional[str], password: Optional[str]) -> str:
    # Limita el número de sesiones en memoria
    if len(SESSION_STORE) >= SESSION_MAX_ENTRIES:
        try:
            oldest = next(iter(SESSION_STORE))
            SESSION_STORE.pop(oldest, None)
        except StopIteration:
            pass
    sid = secrets.token_urlsafe(32)
    enc_pwd = fernet.encrypt(password.encode()) if password else None
    now = datetime.now(timezone.utc)
    SESSION_STORE[sid] = {
        "user": user,
        "display_name": display_name or user,
        "password": enc_pwd,
        "last_seen": now,
        "created": now,
    }
    return sid


def destroy_session(request: Request):
    sid = request.session.pop("sid", None)
    if sid:
        SESSION_STORE.pop(sid, None)
    set_ndcli_credentials(None, None)
    request.session.clear()


@app.get("/api/ping")
async def ping():
    return {"ok": True}


@app.get("/api/layer3domains")
async def get_l3ds():
    return {"items": LAYER3DOMAINS}


@app.post("/api/auth/login", response_model=SessionInfo)
async def login(payload: LoginPayload, request: Request):
    ok, display_name = authenticate_user(payload.username, payload.password)
    if not ok:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    sid = store_session(payload.username, display_name, payload.password)
    request.session.clear()
    request.session["sid"] = sid
    return SessionInfo(username=payload.username, display_name=display_name or payload.username)


@app.post("/api/auth/logout")
async def logout(request: Request):
    destroy_session(request)
    return {"ok": True}


@app.get("/api/auth/session", response_model=SessionInfo)
async def session_info(request: Request):
    sid = request.session.get("sid")
    data = SESSION_STORE.get(sid or "")
    if not data:
        raise HTTPException(status_code=401, detail="No autenticado")
    now = datetime.now(timezone.utc)
    last_seen: datetime = data.get("last_seen") or now
    if (now - last_seen).total_seconds() > SESSION_TTL:
        SESSION_STORE.pop(sid, None)
        raise HTTPException(status_code=401, detail="Sesión expirada")
    data["last_seen"] = now
    user = data["user"]
    return SessionInfo(username=user, display_name=data.get("display_name") or user)


@app.get("/api/search", response_model=List[ResultItem])
async def search(
    type: str = Query(...),
    q: str = Query(...),
    layer3domain: Optional[str] = None,
    view: Optional[str] = None,
    scope: Optional[str] = Query(None),
    _: str = Depends(require_session),
):
    if type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail="type inválido")

    l3d = ensure_l3d(layer3domain)
    sanitized = q.strip()
    if not sanitized:
        raise HTTPException(status_code=400, detail="Query vacío")

    scope_norm = (scope or "").lower()
    is_ionos = scope_norm == "ionos"

    try:
        if is_ionos:
            if type == "subnet":
                return handle_subnet_ionos(sanitized, l3d)
            if type == "ip":
                normalized_ip = _normalize_ip_simple(sanitized)
                return handle_ip_ionos(normalized_ip, l3d)
            raise HTTPException(status_code=400, detail="Tipo de búsqueda no soportado en Consultas IONOS")

        if type == "subnet":
            # Subred: buscamos en todos los layer3domains (default, 8560 y ACS) y agregamos todos los hallazgos ACS
            return handle_subnet(sanitized, l3d)
        elif type == "pool":
            _validate_pool(sanitized)
            return search_across_domains("pool", sanitized, l3d)
        elif type == "vlan":
            return search_across_domains("vlan", sanitized, l3d)
        elif type == "dns":
            return handle_dns(sanitized, l3d, view)
        elif type == "ip":
            normalized_ip = _normalize_ip_simple(sanitized)
            return search_across_domains("ip", normalized_ip, l3d)
        elif type == "device":
            return handle_device(sanitized)
    except NdcliError as e:
        raise HTTPException(
            status_code=502, detail=f"DIM error: {e.stderr or str(e)}"
        )

    raise HTTPException(status_code=400, detail="Caso no contemplado")


@app.post("/api/import/ip-info", response_model=List[ImportIPResponseItem])
async def import_ip_info(payload: ImportIPPayload, _: str = Depends(require_session)):
    if not payload.items:
        raise HTTPException(status_code=400, detail="Lista de IPs vacía")

    creds_snapshot = _ndcli_creds.get(None)
    if not creds_snapshot or not creds_snapshot.get("user") or not creds_snapshot.get("password"):
        logger.error("import_ip_info sin credenciales ndcli en sesión")
        raise HTTPException(status_code=401, detail="Sesión expirada")

    subnet_cache: List[tuple[ipaddress._BaseNetwork, str, str]] = []  # (network, pool, layer3domain)
    subnet_cache_lock = threading.Lock()

    def _lookup_cached(ip_obj: ipaddress._BaseAddress) -> Optional[tuple[str, str]]:
        with subnet_cache_lock:
            for network, pool_name, domain_name in subnet_cache:
                if ip_obj in network:
                    return pool_name, domain_name
        return None

    def _maybe_store_network(subnet: Optional[str], pool_name: str, domain_name: str):
        if not subnet:
            return
        try:
            net_obj = ipaddress.ip_network(subnet, strict=False)
        except Exception:
            return
        with subnet_cache_lock:
            for existing, _, _ in subnet_cache:
                if existing == net_obj:
                    return
            subnet_cache.append((net_obj, pool_name, domain_name))

    def _resolve_entry(entry: ImportIPRequestItem) -> ImportIPResponseItem:
        raw_ip = (entry.ip or "").strip()
        hostname = (entry.hostname or "").strip() or None
        if not raw_ip:
            return ImportIPResponseItem(
                ip="",
                hostname=hostname,
                pool=None,
                layer3domain=None,
                status="error",
                detail="IP vacía en el CSV",
            )
        try:
            normalized_ip = _normalize_ip_simple(raw_ip)
            ip_obj = ipaddress.ip_address(normalized_ip)
        except HTTPException as exc:
            return ImportIPResponseItem(
                ip=raw_ip,
                hostname=hostname,
                pool=None,
                layer3domain=None,
                status="error",
                detail=str(exc.detail),
            )
        cached = _lookup_cached(ip_obj)
        if cached:
            pool_name, domain_name = cached
            return ImportIPResponseItem(
                ip=normalized_ip,
                hostname=hostname,
                pool=pool_name,
                layer3domain=domain_name,
                status="ok",
                detail=None,
            )
        try:
            found = _find_acs_pool_for_ip(normalized_ip, creds=creds_snapshot)
        except NdcliError as exc:
            return ImportIPResponseItem(
                ip=normalized_ip,
                hostname=hostname,
                pool=None,
                layer3domain=None,
                status="error",
                detail=exc.stderr or "Fallo ejecutando ndcli",
            )
        if not found:
            return ImportIPResponseItem(
                ip=normalized_ip,
                hostname=hostname,
                pool=None,
                layer3domain=None,
                status="error",
                detail="IP no encontrada en pools ACS",
            )

        pool_name, domain_name, subnet_cidr = found
        _maybe_store_network(subnet_cidr, pool_name, domain_name)
        return ImportIPResponseItem(
            ip=normalized_ip,
            hostname=hostname,
            pool=pool_name,
            layer3domain=domain_name,
            status="ok",
            detail=None,
        )

    max_workers = min(16, max(1, len(payload.items)))
    results: List[Optional[ImportIPResponseItem]] = [None] * len(payload.items)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ctx = {
            executor.submit(_resolve_entry, entry): (idx, entry) for idx, entry in enumerate(payload.items)
        }
        for future in as_completed(future_to_ctx):
            idx, entry = future_to_ctx[future]
            try:
                results[idx] = future.result()
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Error resolviendo importación idx=%s ip=%s: %s", idx, entry.ip, exc)
                results[idx] = ImportIPResponseItem(
                    ip=(entry.ip or "").strip(),
                    hostname=(entry.hostname or "").strip() or None,
                    pool=None,
                    layer3domain=None,
                    status="error",
                    detail="Error interno al resolver la IP",
                )

    # results no debería contener None, pero protegemos por seguridad
    return [
        res
        if res is not None
        else ImportIPResponseItem(
            ip=(payload.items[idx].ip or "").strip(),
            hostname=(payload.items[idx].hostname or "").strip() or None,
            pool=None,
            layer3domain=None,
            status="error",
            detail="Sin resultado para la IP",
        )
        for idx, res in enumerate(results)
    ]


@app.post("/api/import/execute", response_model=List[ImportExecuteResponseItem])
async def import_ip_execute(payload: ImportExecutePayload, _: str = Depends(require_session)):
    if not payload.items:
        raise HTTPException(status_code=400, detail="Lista de IPs vacía")

    results: List[ImportExecuteResponseItem] = []
    for entry in payload.items:
        raw_ip = (entry.ip or "").strip()
        raw_pool = (entry.pool or "").strip()
        raw_layer3domain = (entry.layer3domain or "").strip()
        raw_hostname = (entry.hostname or "").strip()

        if not raw_ip or not raw_pool or not raw_layer3domain:
            results.append(
                ImportExecuteResponseItem(
                    ip=raw_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool or None,
                    layer3domain=raw_layer3domain or None,
                    action="error",
                    detail="Datos incompletos para la IP",
                    status=None,
                    existing_comment=None,
                    command=None,
                )
            )
            continue

        try:
            normalized_ip = _normalize_ip_simple(raw_ip)
        except HTTPException as exc:
            results.append(
                ImportExecuteResponseItem(
                    ip=raw_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    action="error",
                    detail=str(exc.detail),
                    status=None,
                    existing_comment=None,
                    command=None,
                )
            )
            continue

        try:
            _validate_pool(raw_pool)
        except HTTPException as exc:
            results.append(
                ImportExecuteResponseItem(
                    ip=normalized_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    action="error",
                    detail=str(exc.detail),
                    status=None,
                    existing_comment=None,
                    command=None,
                )
            )
            continue

        try:
            show_output = run_ndcli(["show", "ip", normalized_ip, "layer3domain", raw_layer3domain])
        except NdcliError as exc:
            results.append(
                ImportExecuteResponseItem(
                    ip=normalized_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    action="error",
                    detail=exc.stderr or "Fallo ejecutando ndcli",
                    status=None,
                    existing_comment=None,
                    command=None,
                )
            )
            continue

        record = parse_first_block(show_output)
        status_ip = (record.get("status") or "").strip()
        existing_comment = (record.get("comment") or "").strip()
        status_lower = status_ip.lower()
        should_execute = False
        success_detail = ""

        if status_lower == "available":
            should_execute = True
            success_detail = "IP disponible en DIM"
        elif status_lower == "static":
            if existing_comment:
                results.append(
                    ImportExecuteResponseItem(
                        ip=normalized_ip,
                        hostname=raw_hostname or None,
                        pool=raw_pool,
                        layer3domain=raw_layer3domain,
                        action="skipped",
                        detail=f"La IP {normalized_ip} ya estaba documentada en DIM",
                        status=status_ip or None,
                        existing_comment=existing_comment or None,
                        command="--",
                        output="--",
                    )
                )
                continue
            should_execute = True
            success_detail = "IP estática sin comentario; se aplicó comentario"
        else:
            results.append(
                ImportExecuteResponseItem(
                    ip=normalized_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    action="skipped",
                    detail=f"Estado '{status_ip}' no soportado para importación",
                    status=status_ip or None,
                    existing_comment=existing_comment or None,
                    command=None,
                )
            )
            continue

        if not should_execute:
            continue

        escaped_comment = raw_hostname.replace('"', '\\"')
        command_args = [
            "modify",
            "pool",
            raw_pool,
            "mark",
            "ip",
            normalized_ip,
            f'comment:"{escaped_comment}"',
        ]
        command_repr = _format_ndcli_command(command_args)

        try:
            output = run_ndcli(command_args)
        except NdcliError as exc:
            stderr_lower = (exc.stderr or "").lower()
            stdout_lower = (exc.stdout or "").lower()
            already = "already allocated" in stderr_lower or "already allocated" in stdout_lower
            if already:
                results.append(
                    ImportExecuteResponseItem(
                        ip=normalized_ip,
                        hostname=raw_hostname or None,
                        pool=raw_pool,
                        layer3domain=raw_layer3domain,
                        action="skipped",
                        detail=f"La IP {normalized_ip} ya estaba documentada en DIM",
                        status=status_ip or None,
                        existing_comment=existing_comment or None,
                        command="--",
                        output="--",
                    )
                )
                continue
            results.append(
                ImportExecuteResponseItem(
                    ip=normalized_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    action="error",
                    detail=exc.stderr or "Fallo ejecutando ndcli",
                    status=status_ip or None,
                    existing_comment=existing_comment or None,
                    command=command_repr,
                    output=exc.stdout or None,
                )
            )
            continue

        results.append(
            ImportExecuteResponseItem(
                ip=normalized_ip,
                hostname=raw_hostname or None,
                pool=raw_pool,
                layer3domain=raw_layer3domain,
                action="executed",
                detail=success_detail,
                status=status_ip or None,
                existing_comment=existing_comment or None,
                command=command_repr,
                output=output or None,
            )
        )
    return results


@app.post("/api/import/dryrun", response_model=List[ImportDryrunResponseItem])
async def import_ip_dryrun(payload: ImportExecutePayload, _: str = Depends(require_session)):
    if not payload.items:
        raise HTTPException(status_code=400, detail="Lista de IPs vacía")

    results: List[ImportDryrunResponseItem] = []
    for entry in payload.items:
        raw_ip = (entry.ip or "").strip()
        raw_pool = (entry.pool or "").strip()
        raw_layer3domain = (entry.layer3domain or "").strip()
        raw_hostname = (entry.hostname or "").strip()

        if not raw_ip or not raw_pool or not raw_layer3domain:
            results.append(
                ImportDryrunResponseItem(
                    ip=raw_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool or None,
                    layer3domain=raw_layer3domain or None,
                    status="error",
                    error="Datos incompletos para la IP",
                    command=None,
                )
            )
            continue

        try:
            normalized_ip = _normalize_ip_simple(raw_ip)
        except HTTPException as exc:
            results.append(
                ImportDryrunResponseItem(
                    ip=raw_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    status="error",
                    error=str(exc.detail),
                    command=None,
                )
            )
            continue

        try:
            _validate_pool(raw_pool)
        except HTTPException as exc:
            results.append(
                ImportDryrunResponseItem(
                    ip=normalized_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    status="error",
                    error=str(exc.detail),
                    command=None,
                )
            )
            continue

        escaped_comment = (raw_hostname or "").replace('"', '\\"') or "sin-hostname"
        cmd_args = [
          "modify",
          "pool",
          raw_pool,
          "mark",
          "ip",
          normalized_ip,
          f'comment:"{escaped_comment}"',
          "--dryrun",
        ]
        command_repr = _format_ndcli_command(cmd_args)

        def _with_banner(text: Optional[str]) -> str:
            banner = "INFO - Dryrun mode, no data will be modified"
            base = (text or "").strip()
            if not base:
                return banner
            # elimina ocurrencias existentes para evitar duplicados y luego antepone
            lower_banner = banner.lower()
            filtered_lines = [
                line for line in base.splitlines() if line.strip().lower() != lower_banner
            ]
            filtered = "\n".join(filtered_lines).strip()
            return f"{banner}\n{filtered}" if filtered else banner

        try:
            output = run_ndcli(cmd_args, include_stderr=True)
            results.append(
                ImportDryrunResponseItem(
                    ip=normalized_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    status="ok",
                    output=_with_banner(output),
                    error=None,
                    command=command_repr,
                )
            )
        except NdcliError as exc:
            combined_err = f"{exc.stdout}{exc.stderr}"
            results.append(
                ImportDryrunResponseItem(
                    ip=normalized_ip,
                    hostname=raw_hostname or None,
                    pool=raw_pool,
                    layer3domain=raw_layer3domain,
                    status="error",
                    output=None,
                    error=_with_banner(combined_err) if combined_err else (exc.stderr or "Fallo ejecutando ndcli"),
                    command=command_repr,
                )
            )
    return results


# ---------- Handlers ----------


def handle_subnet(cidr: str, l3d: Optional[str]) -> List[ResultItem]:
    # Determinar si es CIDR o parcial
    is_cidr = "/" in cidr
    if is_cidr:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except Exception:
            raise HTTPException(status_code=400, detail="CIDR inválido")
    else:
        # Subred parcial básica: validamos que sean 1-3 octetos numéricos
        parts = [p for p in cidr.split(".") if p]
        if not parts or len(parts) > 3 or any(not p.isdigit() or int(p) < 0 or int(p) > 255 for p in parts):
            raise HTTPException(status_code=400, detail="Subred parcial inválida")

    allowed_prefixes = ("es-lgr-pl-acs", "es-mad-gsw-acs", "us-mia-mi1-acs", "es-gb-gsw-acs")

    domain_order: List[str] = []
    if l3d:
        domain_order.append(l3d)
    for candidate in [default_layer3domain(), "8560-arsys-rfc1918", *ACS_LAYER3DOMAINS]:
        if candidate and candidate not in domain_order:
            domain_order.append(candidate)

    results: List[ResultItem] = []

    if is_cidr:
        for domain in domain_order:
            out = None
            try:
                out = run_ndcli(with_layer3domain(["show", "subnet", cidr], domain))
            except NdcliError as exc:
                stderr = (exc.stderr or "").lower()
                if "unparsed tokens" in stderr and "layer3domain" in stderr:
                    try:
                        out = run_ndcli(["show", "subnet", cidr])
                    except NdcliError:
                        continue
                elif "layer3domain is needed" in stderr or _looks_like_not_found(exc):
                    continue
                else:
                    continue

            if not out:
                continue

            kv = parse_show_subnet(out)
            pool = kv.get("pool") or ""
            if not pool.lower().startswith(allowed_prefixes):
                continue

            vlan = None
            try:
                out_pool = _run_pool_command(["show", "pool", pool], domain)
                kv_pool = parse_show_pool(out_pool)
                vlan = kv_pool.get("vlan")
            except NdcliError:
                pass

            subnets: List[str] = []
            try:
                out_list = _run_pool_command(["list", "pool", pool, "subnets"], domain)
                subnets = _parse_list_pool(out_list)
            except NdcliError:
                subnets = [kv.get("ip") or cidr]
            if not subnets:
                subnets = [kv.get("ip") or cidr]
            results.append(
                ResultItem(
                    pool=pool,
                    vlan=vlan,
                    subnets=subnets,
                    layer3domain=kv.get("layer3domain") or domain,
                )
            )
    else:
        # Subred parcial: list pools por dominio y filtrar por prefijo ACS y coincidencia en CIDR
        partial = cidr
        for domain in domain_order:
            try:
                out = run_ndcli(["list", "pools", "layer3domain", domain])
            except NdcliError:
                continue

            for line in out.splitlines():
                stripped = line.strip()
                if not stripped or stripped.lower().startswith("name"):
                    continue
                tokens = stripped.split()
                if len(tokens) < 2:
                    continue
                pool_name = tokens[0]
                pool_lower = pool_name.lower()
                if not pool_lower.startswith(allowed_prefixes):
                    continue
                cidr_tokens = [t for t in tokens if "/" in t]
                if not cidr_tokens:
                    continue
                if not any(partial in ct for ct in cidr_tokens):
                    continue
                vlan_token = next((t for t in tokens[1:] if t.isdigit()), "")

                subnets = cidr_tokens[:]  # incluye todos los cidr declarados en la línea
                try:
                    out_list = run_ndcli(with_layer3domain(["list", "pool", pool_name, "subnets"], domain))
                    parsed_subnets = _parse_list_pool(out_list)
                    if parsed_subnets:
                        subnets = parsed_subnets
                except NdcliError:
                    pass

                results.append(
                    ResultItem(
                        pool=pool_name,
                        vlan=vlan_token,
                        subnets=subnets,
                        layer3domain=domain,
                    )
                )

    if results:
        def order_key(item: ResultItem) -> int:
            try:
                return domain_order.index(item.layer3domain or "")
            except ValueError:
                return len(domain_order)
        return sorted(results, key=order_key)

    raise HTTPException(status_code=404, detail="Sin resultados DIM para la consulta")


def handle_subnet_ionos(cidr: str, l3d: Optional[str]) -> List[ResultItem]:
    """
    Variante IONOS: solo busca en dominios no ACS y en pools que no sean ACS.
    """
    is_cidr = "/" in cidr
    if is_cidr:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except Exception:
            raise HTTPException(status_code=400, detail="CIDR inválido")
    else:
        parts = [p for p in cidr.split(".") if p]
        if not parts or len(parts) > 3 or any(not p.isdigit() or int(p) < 0 or int(p) > 255 for p in parts):
            raise HTTPException(status_code=400, detail="Subred parcial inválida")

    domain_order = _ionos_layer3domain_candidates(l3d)
    results: List[ResultItem] = []

    if is_cidr:
        for domain in domain_order:
            out = None
            try:
                out = run_ndcli(with_layer3domain(["show", "subnet", cidr], domain))
            except NdcliError as exc:
                stderr = (exc.stderr or "").lower()
                if "unparsed tokens" in stderr and "layer3domain" in stderr:
                    try:
                        out = run_ndcli(["show", "subnet", cidr])
                    except NdcliError:
                        continue
                elif "layer3domain is needed" in stderr or _looks_like_not_found(exc):
                    continue
                else:
                    continue

            if not out:
                continue

            kv = parse_show_subnet(out)
            pool = kv.get("pool") or ""
            if _is_acs_pool(pool):
                continue

            vlan = None
            try:
                out_pool = _run_pool_command(["show", "pool", pool], domain)
                kv_pool = parse_show_pool(out_pool)
                vlan = kv_pool.get("vlan")
            except NdcliError:
                pass

            subnets: List[str] = []
            try:
                out_list = _run_pool_command(["list", "pool", pool, "subnets"], domain)
                subnets = _parse_list_pool(out_list)
            except NdcliError:
                subnets = [kv.get("ip") or cidr]
            if not subnets:
                subnets = [kv.get("ip") or cidr]
            results.append(
                ResultItem(
                    pool=pool,
                    vlan=vlan,
                    subnets=subnets,
                    layer3domain=kv.get("layer3domain") or domain,
                )
            )
    else:
        partial = cidr
        for domain in domain_order:
            try:
                out = run_ndcli(["list", "pools", "layer3domain", domain])
            except NdcliError:
                continue

            for line in out.splitlines():
                stripped = line.strip()
                if not stripped or stripped.lower().startswith("name"):
                    continue
                tokens = stripped.split()
                if len(tokens) < 2:
                    continue
                pool_name = tokens[0]
                if _is_acs_pool(pool_name):
                    continue
                cidr_tokens = [t for t in tokens if "/" in t]
                if not cidr_tokens:
                    continue
                if not any(partial in ct for ct in cidr_tokens):
                    continue
                vlan_token = next((t for t in tokens[1:] if t.isdigit()), "")

                subnets = cidr_tokens[:]
                try:
                    out_list = run_ndcli(with_layer3domain(["list", "pool", pool_name, "subnets"], domain))
                    parsed_subnets = _parse_list_pool(out_list)
                    if parsed_subnets:
                        subnets = parsed_subnets
                except NdcliError:
                    pass

                results.append(
                    ResultItem(
                        pool=pool_name,
                        vlan=vlan_token,
                        subnets=subnets,
                        layer3domain=domain,
                    )
                )

    if results:
        def order_key(item: ResultItem) -> int:
            try:
                return domain_order.index(item.layer3domain or "")
            except ValueError:
                return len(domain_order)
        return sorted(results, key=order_key)

    raise HTTPException(status_code=404, detail="Sin resultados DIM para la consulta")


def handle_pool(pool: str, l3d: Optional[str]) -> List[ResultItem]:
    if not POOL_RE.match(pool):
        raise HTTPException(status_code=400, detail="Nombre de pool inválido")

    # show pool (con fallback si layer3domain no es aceptado como token)
    out = _run_pool_command(["show", "pool", pool], l3d)
    kvp = parse_show_pool(out)
    vlan = kvp.get("vlan")
    effective_l3d = kvp.get("layer3domain") or (l3d or default_layer3domain())

    subnets: List[str] = []
    try:
        out_list = _run_pool_command(["list", "pool", pool, "subnets"], l3d)
        subnets = _parse_list_pool(out_list)
    except NdcliError:
        subnets = []

    return [
        ResultItem(
            pool=pool,
            vlan=vlan,
            subnets=subnets,
            layer3domain=effective_l3d,
        )
    ]


def handle_vlan(vlan: str, l3d: Optional[str]) -> List[ResultItem]:
    if not VLAN_RE.match(vlan):
        raise HTTPException(status_code=400, detail="VLAN inválido")

    allowed_prefixes = ("es-lgr-pl-acs", "es-mad-gsw-acs", "us-mia-mi1-acs")
    # Orden de búsqueda: default, 8560-arsys-rfc1918, luego ACS
    domain_order: List[str] = []
    for candidate in ["default", "8560-arsys-rfc1918", *ACS_LAYER3DOMAINS]:
        if candidate not in domain_order:
            domain_order.append(candidate)

    results: List[ResultItem] = []

    for domain in domain_order:
        pools = _find_pools_by_vlan(vlan, domain, allowed_prefixes)
        if not pools:
            continue

        for pool in pools:
            try:
                # Obtenemos VLAN y subredes del pool (comandos de pool sin layer3domain)
                pool_info = _run_pool_command(["show", "pool", pool], domain)
                kv = parse_show_pool(pool_info)
                out_list = _run_pool_command(["list", "pool", pool, "subnets"], domain)
                subnets = _parse_list_pool(out_list)
            except NdcliError:
                continue

            results.append(
                ResultItem(
                    pool=pool,
                    vlan=kv.get("vlan") or vlan,
                    subnets=subnets,
                    layer3domain=domain,
                )
            )

        if results:
            break

    if not results:
        raise HTTPException(status_code=404, detail="Sin resultados para VLAN")

    return results


def handle_dns(fqdn: str, l3d: Optional[str], view_opt: Optional[str]) -> List[ResultItem]:
    if not FQDN_RE.match(fqdn):
        raise HTTPException(status_code=400, detail="FQDN inválido")

    fqdn_lower = fqdn.lower()
    fqdn_norm = fqdn_lower.rstrip(".")

    views_to_try: List[str] = []
    if fqdn_norm.endswith(".arsyscloud.tools"):
        if view_opt == "internal":
            views_to_try = ["internal"]
        elif view_opt == "public":
            views_to_try = ["public"]
        elif view_opt == "both":
            views_to_try = ["internal", "public"]
        else:
            views_to_try = ["internal"]
    else:
        views_to_try = ["default"]

    ips: List[tuple[str, Optional[str]]] = []  # (ip, vista usada)
    zone_value: Optional[str] = None
    found_ips = False

    for v in views_to_try:
        cmd = ["show", "rr", fqdn, "a"]
        if v:
            cmd += ["view", v]
        try:
            out = run_ndcli(cmd)
        except NdcliError as exc:
            if _looks_like_not_found(exc) or ips:
                continue
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

        for line in out.splitlines():
            if line.lower().startswith("zone:"):
                _, _, zval = line.partition(":")
                zone_value = zval.strip() or zone_value

        for line in out.splitlines():
            if line.lower().startswith("rr:"):
                # Ej: rr:host A 10.0.0.1
                parts = line.split()
                if len(parts) >= 3:
                    maybe_ip = parts[-1]
                    try:
                        ipaddress.ip_address(maybe_ip)
                        ips.append((maybe_ip, v if fqdn_norm.endswith(".arsyscloud.tools") else None))
                        found_ips = True
                    except ValueError:
                        continue

        # No cortamos; acumulamos IPs de todas las vistas solicitadas

    if not ips:
        raise HTTPException(status_code=404, detail="Sin resultados")

    # Orden de búsqueda para localizar pool/subred de la IP: default -> 8560-arsys-rfc1918 -> dominios ACS
    layer_order: List[str] = []
    for cand in [default_layer3domain(), "8560-arsys-rfc1918", *ACS_LAYER3DOMAINS]:
        if cand and cand not in layer_order:
            layer_order.append(cand)
    last_exc: Optional[Exception] = None

    domain_results: list[ResultItem] = []
    for ip, used_view in ips:
        found_in_acs = False
        last_not_found: Optional[Exception] = None
        for layer in layer_order:
            try:
                out_ip = run_ndcli(with_layer3domain(["show", "ip", ip], layer))
                kv = parse_first_block(out_ip)
                pool = kv.get("pool") or ""
                subnet = kv.get("subnet")

                if not pool:
                    continue
                if not (
                    pool.startswith("es-lgr-pl-acs")
                    or pool.startswith("es-mad-gsw-acs")
                    or pool.startswith("us-mia-mi1-acs")
                    or pool.startswith("es-gb-gsw-acs")
                ):
                    continue

                vlan = None
                try:
                    pool_info = _run_pool_command(["show", "pool", pool], layer)
                    kv_pool = parse_show_pool(pool_info)
                    vlan = kv_pool.get("vlan")
                except NdcliError:
                    pass

                subnets = [subnet] if subnet else []
                if not subnets:
                    try:
                        out_list = _run_pool_command(["list", "pool", pool, "subnets"], layer)
                        subnets = _parse_list_pool(out_list)
                    except NdcliError:
                        subnets = []

                domain_results.append(
                    ResultItem(
                        pool=pool,
                        vlan=vlan,
                        subnets=subnets,
                        layer3domain=layer,
                        dns_zone=zone_value,
                        fqdn=fqdn,
                        ip_address=ip,
                        dns_view=used_view,
                    )
                )
                found_in_acs = True
                break
            except NdcliError as exc:
                if _looks_like_not_found(exc):
                    last_not_found = exc
                    continue
                raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc
        if found_in_acs:
            continue
        if last_not_found:
            last_exc = last_not_found

    if domain_results:
        return domain_results

    if last_exc:
        raise HTTPException(status_code=404, detail="Sin resultados DIM para la consulta DNS")

    raise HTTPException(status_code=404, detail="Sin resultados DIM para la consulta DNS")


def handle_ip(ipstr: str, l3d: Optional[str], *, skip_pool_prefix_check: bool = False) -> List[ResultItem]:
    try:
        ipaddress.ip_address(ipstr)
    except Exception:
        raise HTTPException(status_code=400, detail="IP inválida")

    allowed_prefixes = ("es-lgr-pl-acs", "es-mad-gsw-acs", "us-mia-mi1-acs", "es-gb-gsw-acs")

    # Orden de búsqueda: layer3domain solicitado (si aplica), default, 8560-arsys-rfc1918, luego ACS
    domain_order: List[str] = []
    if l3d:
        domain_order.append(l3d)
    for candidate in [default_layer3domain(), "8560-arsys-rfc1918", *ACS_LAYER3DOMAINS]:
        if candidate and candidate not in domain_order:
            domain_order.append(candidate)

    last_error: Optional[HTTPException] = None

    for domain in domain_order:
        try:
            out_ip = run_ndcli(with_layer3domain(["show", "ip", ipstr], domain))
        except NdcliError as exc:
            if _looks_like_not_found(exc):
                last_error = HTTPException(status_code=404, detail="Sin resultados")
                continue
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

        kv = parse_first_block(out_ip)
        pool = kv.get("pool") or ""
        subnet = kv.get("subnet")
        if not pool:
            continue
        if (not skip_pool_prefix_check) and not any(pool.startswith(pref) for pref in allowed_prefixes):
            continue

        vlan = None
        try:
            pool_info = _run_pool_command(["show", "pool", pool], domain)
            kv_pool = parse_show_pool(pool_info)
            vlan = kv_pool.get("vlan")
        except NdcliError:
            pass

        subnets = [subnet] if subnet else []
        if not subnets:
            try:
                out_list = _run_pool_command(["list", "pool", pool, "subnets"], domain)
                subnets = _parse_list_pool(out_list)
            except NdcliError:
                subnets = []

        return [
            ResultItem(
                pool=pool,
                vlan=vlan,
                subnets=subnets,
                layer3domain=domain,
                ip_address=ipstr,
                ptr_target=kv.get("ptr_target"),
                comment=kv.get("comment"),
            )
        ]

    if last_error:
        raise last_error

    raise HTTPException(status_code=404, detail="Sin resultados")


def handle_ip_ionos(ipstr: str, l3d: Optional[str]) -> List[ResultItem]:
    """
    Variante IONOS: busca IPs solo en dominios no ACS y omite pools ACS.
    """
    try:
        ipaddress.ip_address(ipstr)
    except Exception:
        raise HTTPException(status_code=400, detail="IP inválida")

    domain_order = _ionos_layer3domain_candidates(l3d)
    last_error: Optional[HTTPException] = None

    for domain in domain_order:
        try:
            out_ip = run_ndcli(with_layer3domain(["show", "ip", ipstr], domain))
        except NdcliError as exc:
            if _looks_like_not_found(exc):
                last_error = HTTPException(status_code=404, detail="Sin resultados")
                continue
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

        kv = parse_first_block(out_ip)
        pool = kv.get("pool") or ""
        subnet = kv.get("subnet")
        if not pool or _is_acs_pool(pool):
            continue

        vlan = None
        try:
            pool_info = _run_pool_command(["show", "pool", pool], domain)
            kv_pool = parse_show_pool(pool_info)
            vlan = kv_pool.get("vlan")
        except NdcliError:
            pass

        subnets = [subnet] if subnet else []
        if not subnets:
            try:
                out_list = _run_pool_command(["list", "pool", pool, "subnets"], domain)
                subnets = _parse_list_pool(out_list)
            except NdcliError:
                subnets = []

        return [
            ResultItem(
                pool=pool,
                vlan=vlan,
                subnets=subnets,
                layer3domain=domain,
                ip_address=ipstr,
                ptr_target=kv.get("ptr_target"),
                comment=kv.get("comment"),
            )
        ]

    if last_error:
        raise last_error

    raise HTTPException(status_code=404, detail="Sin resultados")


def _lookup_ip_result(ipstr: str, domain_hint: Optional[str] = None) -> Optional[ResultItem]:
    """Reutiliza handle_ip para obtener detalle de una IP sin lanzar en 404."""
    try:
        results = handle_ip(ipstr, domain_hint, skip_pool_prefix_check=True)
        return results[0] if results else None
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise


def _safe_lookup_ip_result(ipstr: str, domain_hint: Optional[str] = None) -> Optional[ResultItem]:
    """
    Variante tolerante para Device: ignora entradas cuyo value no sea una IP válida.
    """
    try:
        return _lookup_ip_result(ipstr, domain_hint)
    except HTTPException as exc:
        if exc.status_code == 400 and exc.detail == "IP inválida":
            logger.error("Descartando entrada con IP inválida en device: %s", ipstr)
            return None
        raise


def _build_result_from_pool(ipstr: str, pool: str, domain: str) -> ResultItem:
    """Construye un ResultItem mínimo usando el contexto de pool."""
    vlan = None
    subnets: List[str] = []
    try:
        pool_info = _run_pool_command(["show", "pool", pool], domain)
        kv_pool = parse_show_pool(pool_info)
        vlan = kv_pool.get("vlan")
    except NdcliError:
        vlan = None
    try:
        out_list = _run_pool_command(["list", "pool", pool, "subnets"], domain)
        subnets = _parse_list_pool(out_list)
    except NdcliError:
        subnets = []
    return ResultItem(
        pool=pool,
        vlan=vlan,
        subnets=subnets,
        layer3domain=domain,
        ip_address=ipstr,
    )


def _find_acs_pool_for_ip(ipstr: str, creds: Optional[Dict[str, str]] = None) -> Optional[tuple[str, str, Optional[str]]]:
    """
    Busca la IP en default -> 8560 -> dominios ACS. Devuelve (pool, layer3domain) sólo si el pool es ACS.
    """
    domains: List[str] = []
    for candidate in [default_layer3domain(), "8560-arsys-rfc1918", *ACS_LAYER3DOMAINS]:
        if candidate and candidate not in domains:
            domains.append(candidate)

    for domain in domains:
        try:
            out_ip = run_ndcli(with_layer3domain(["show", "ip", ipstr], domain), creds=creds)
        except NdcliError as exc:
            if _looks_like_not_found(exc):
                continue
            raise
        kv = parse_first_block(out_ip)
        pool_name = (kv.get("pool") or "").strip()
        if pool_name and _is_acs_pool(pool_name):
            subnet_cidr = (kv.get("subnet") or "").strip() or None
            return pool_name, domain, subnet_cidr
    return None


def _parse_ndcli_table_lines(out: str, needle: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Parse salidas tipo tabla de ndcli list rrs:
    record zone view ttl type value [layer3domain]
    TTL puede venir vacío, y puede haber una columna extra de layer3domain.
    """
    rows: List[Dict[str, str]] = []
    needle_lower = needle.lower() if needle else None
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("info -") or line.lower().startswith("result for"):
            continue
        if line.lower().startswith("record "):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        record, zone, view = parts[0], parts[1], parts[2]
        tail = parts[3:]
        if not tail:
            continue
        ttl = ""
        rtype = ""
        value = None
        # Busca el primer token que parezca un tipo (A, AAAA, PTR, CNAME, TXT...)
        type_idx = None
        for idx, token in enumerate(tail):
            if re.match(r"^[A-Z]+$", token):
                type_idx = idx
                break
        if type_idx is None:
            continue
        rtype = tail[type_idx]
        if type_idx > 0:
            ttl = tail[type_idx - 1] if tail[type_idx - 1].isdigit() else ""
        if len(tail) > type_idx + 1:
            value = tail[type_idx + 1]
        if needle_lower and needle_lower not in line.lower():
            continue
        rows.append(
            {
                "record": record,
                "zone": zone,
                "view": view,
                "ttl": ttl,
                "type": rtype,
                "value": value,
            }
        )
    return rows


def _parse_ndcli_list_ips_line(line: str, needle: Optional[str] = None) -> Optional[Dict[str, str]]:
    """
    Parse una línea de `ndcli list ips <pool> status used | grep <device>`
    Formatos vistos:
    - "record zone view ttl type value" (tabla estándar)
    - "172.16.234.250 Static es-glb-ins-ifw01-01.arsysnet.lan. es-glb-ins-ifw01-01 mgmt"
    """
    text = line.strip()
    if not text:
        return None
    if text.lower().startswith("info -") or text.lower().startswith("result for"):
        return None
    if needle and needle.lower() not in text.lower():
        return None

    parts = text.split()
    # Caso tabla (record zone view ttl type value)
    if len(parts) >= 6 and not re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
        record, zone, view, ttl, rtype, value = parts[:6]
        return {
            "record": record,
            "zone": zone,
            "view": view,
            "ttl": ttl,
            "type": rtype,
            "value": value,
        }

    # Caso lista de IPs con status/fqdn/record/comment
    if not parts:
        return None
    try:
        ipaddress.ip_address(parts[0])
    except Exception:
        return None
    ip_val = parts[0]
    status = parts[1] if len(parts) > 1 else ""
    idx = 2
    fqdn = None
    record = None
    comment = None
    # Si el siguiente token parece fqdn, lo tomamos
    if len(parts) > idx and "." in parts[idx]:
        fqdn = parts[idx].rstrip(".")
        idx += 1
    # Si queda token, record
    if len(parts) > idx:
        record = parts[idx]
        idx += 1
    # El resto, comentario (puede estar vacío si no hay más tokens)
    if len(parts) > idx:
        comment = " ".join(parts[idx:]).strip() or None
    # Si no hay fqdn pero hay record con puntos (ej. eth2-2500.es-glb-acs-cfw01-01.arsysnet.lan.), úsalo como fqdn
    if not fqdn and record and "." in record:
        fqdn = record.rstrip(".")
    # Si seguimos sin fqdn y el record no lleva puntos, empujamos ese token al comentario
    if not fqdn and record and "." not in record:
        comment = " ".join(filter(None, [record, comment])).strip() or None
        record = None
    return {
        "ip": ip_val,
        "status": status,
        "fqdn": fqdn,
        "record": record,
        "comment": comment,
        "zone": None,
        "view": None,
        "value": ip_val,
    }


def _extract_pool_prefix(pool_name: str) -> Optional[str]:
    """Obtiene el prefijo inicial de un pool ACS (hasta 'acs')."""
    cleaned = (pool_name or "").strip()
    if not cleaned or "acs" not in cleaned.lower():
        return None
    match = re.match(r"^([a-z0-9-]*?acs)", cleaned, re.I)
    if not match:
        return None
    return match.group(1)


def _merge_views(current: Optional[str], new: Optional[str]) -> Optional[str]:
    """
    Une vistas dns_view evitando duplicados. Devuelve valores en minúsculas separados por "/".
    """
    seen: List[str] = []
    for value in (current, new):
        if not value:
            continue
        for token in re.split(r"[ ,/]+", value.strip()):
            tok = token.lower()
            if tok and tok not in seen:
                seen.append(tok)
    if not seen:
        return None
    return "/".join(seen)


def _gather_acs_pools() -> List[tuple[str, str]]:
    """
    Devuelve pares (pool, layer3domain) para todos los dominios en orden
    default -> 8560 -> ACS, filtrando pools ACS.
    """
    domains: List[str] = []
    for candidate in [default_layer3domain(), "8560-arsys-rfc1918", *ACS_LAYER3DOMAINS]:
        if candidate and candidate not in domains:
            domains.append(candidate)

    pools: List[tuple[str, str]] = []
    seen: Set[tuple[str, str]] = set()
    for domain in domains:
        try:
            out = run_ndcli(with_layer3domain(["list", "pools"], domain))
        except NdcliError as exc:
            if _looks_like_not_found(exc):
                continue
            logger.error("ndcli list pools l3d=%s falló: %s", domain, exc.stderr or exc)
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc
        for line in out.splitlines():
            raw = line.strip()
            if not raw or raw.lower().startswith("info -") or raw.lower().startswith("result for") or raw.lower().startswith("layer3domain"):
                continue
            parts = re.split(r"\s+", raw)
            if not parts:
                continue
            pool_name = parts[0]
            # Si la última columna parece un layer3domain, la usamos
            candidate_dom = parts[-1] if len(parts) > 1 else domain
            pool_domain = domain
            if candidate_dom in LAYER3DOMAINS or candidate_dom == "default" or "arsys" in candidate_dom or "acs" in candidate_dom:
                pool_domain = candidate_dom
            key = (pool_name, pool_domain)
            if _extract_pool_prefix(pool_name) and key not in seen:
                pools.append(key)
                seen.add(key)
    return pools


def handle_device(device: str) -> List[ResultItem]:
    """
    Búsqueda por Device:
    1) DNS que contienen el texto (list rrs <device>* a)
    2) IPs en comentarios/listados de pools ACS (list ips <pool> status used filtrando por device)
    """
    start_ts = datetime.now()
    device = device.strip()
    if not device:
        raise HTTPException(status_code=400, detail="Device vacío")

    results_map: Dict[tuple, ResultItem] = {}
    creds_snapshot = _ndcli_creds.get(None)
    if not creds_snapshot or not creds_snapshot.get("user") or not creds_snapshot.get("password"):
        logger.error("handle_device sin credenciales ndcli en sesión")
        # Mejor devolvemos 401 para que el front limpie sesión de forma consistente
        raise HTTPException(status_code=401, detail="Sesión expirada")

    # Fase 1: DNS que contienen el device
    try:
        out_rrs = run_ndcli(["list", "rrs", f"*{device}*", "a"], timeout=30, creds=creds_snapshot)
    except NdcliError as exc:
        # Si no hay coincidencias, list rrs devuelve cabecera vacía; continuamos
        out_rrs = ""
        if not _looks_like_not_found(exc):
            logger.error("ndcli list rrs para device %s falló: %s", device, exc.stderr or exc)
            # No abortamos aún: seguimos con la fase de pools por si hubiera resultados en comentarios
            out_rrs = ""

    for row in _parse_ndcli_table_lines(out_rrs, needle=device):
        ip_val = row.get("value")
        if not ip_val:
            continue
        base = _safe_lookup_ip_result(ip_val)
        if not base:
            continue
        fqdn_val = f"{row.get('record')}.{row.get('zone')}".strip(".")
        base.fqdn = fqdn_val
        base.dns_zone = row.get("zone")
        base.dns_view = _merge_views(base.dns_view, row.get("view"))
        base.device = device
        base.ptr_target = base.ptr_target or row.get("record")
        key = (base.ip_address, base.pool, base.layer3domain, base.fqdn)
        if key in results_map:
            existing = results_map[key]
            if (not existing.comment) and base.comment:
                existing.comment = base.comment
            if (not existing.ptr_target) and base.ptr_target:
                existing.ptr_target = base.ptr_target
            existing.dns_view = _merge_views(existing.dns_view, base.dns_view)
        else:
            results_map[key] = base

    # Fase 2: IPs cuyo registro contiene el device dentro de pools ACS
    pools = _gather_acs_pools()
    prefixes: Set[tuple[str, str]] = set()
    for pool_name, domain_name in pools:
        prefix = _extract_pool_prefix(pool_name)
        if prefix:
            prefixes.add((prefix, domain_name))

    def _search_prefix(prefix: str, domain_name: str) -> List[ResultItem]:
        local_results: List[ResultItem] = []
        if creds_snapshot:
            set_ndcli_credentials(creds_snapshot.get("user"), creds_snapshot.get("password"))
        try:
            out_ips = run_ndcli(
                with_layer3domain(
                    ["list", "ips", f"{prefix}*", "status", "used", "-L", "2000"],
                    domain_name,
                ),
                creds=creds_snapshot,
                timeout=10,
            )
        except NdcliError as exc:
            if not _looks_like_not_found(exc):
                logger.error(
                    "ndcli list ips prefix=%s* l3d=%s falló: %s", prefix, domain_name, exc.stderr or exc
                )
            # En device seguimos con el resto de pools aunque uno falle
            return local_results
        for raw_line in out_ips.splitlines():
            parsed = _parse_ndcli_list_ips_line(raw_line, needle=device)
            if not parsed:
                continue
            logger.info("parse_ips hit prefix=%s* l3d=%s line=%s parsed=%s", prefix, domain_name, raw_line, parsed)
            ip_val = parsed.get("value") or parsed.get("ip")
            if not ip_val:
                continue
            base = _safe_lookup_ip_result(ip_val, domain_hint=domain_name)
            if not base:
                continue
            if parsed.get("fqdn"):
                base.fqdn = parsed["fqdn"]
            elif parsed.get("record") and parsed.get("zone"):
                base.fqdn = f"{parsed.get('record')}.{parsed.get('zone')}".strip(".")
            base.dns_zone = parsed.get("zone") or base.dns_zone
            base.dns_view = _merge_views(base.dns_view, parsed.get("view"))
            base.device = device
            if parsed.get("comment"):
                base.comment = parsed["comment"]
            if parsed.get("record") and "." in parsed.get("record", ""):
                base.ptr_target = base.ptr_target or parsed.get("record")
            local_results.append(base)
        return local_results

    max_workers = min(64, max(1, len(prefixes)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_pool = {
            executor.submit(_search_prefix, prefix, domain): (prefix, domain) for prefix, domain in prefixes
        }
        for future in as_completed(future_to_pool):
            try:
                pool_results = future.result()
            except HTTPException:
                raise
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Error procesando pool %s: %s", future_to_pool[future], exc)
                continue
            for item in pool_results:
                key = (item.ip_address, item.pool, item.layer3domain, item.fqdn)
                if key in results_map:
                    existing = results_map[key]
                    if (not existing.comment) and item.comment:
                        existing.comment = item.comment
                    if (not existing.ptr_target) and item.ptr_target:
                        existing.ptr_target = item.ptr_target
                    if (not existing.fqdn) and item.fqdn:
                        existing.fqdn = item.fqdn
                    if (not existing.dns_zone) and item.dns_zone:
                        existing.dns_zone = item.dns_zone
                    existing.dns_view = _merge_views(existing.dns_view, item.dns_view)
                else:
                    results_map[key] = item

    duration = (datetime.now() - start_ts).total_seconds()
    logger.info(
        "handle_device device=%s pools=%s prefixes=%s results=%s tiempo=%.1fs",
        device,
        len(pools),
        len(prefixes),
        len(results_map),
        duration,
    )

    if results_map:
        return list(results_map.values())

    raise HTTPException(status_code=404, detail="Sin resultados DIM para el device")


def _normalize_ip_simple(value: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(value.strip())
    except Exception:
        raise HTTPException(status_code=400, detail="IP inválida")
    return str(ip_obj)


def _normalize_view_value(view_raw: Optional[str]) -> str:
    """
    Normaliza valores de vista provenientes del frontend (incluyendo etiquetas en español)
    a tokens aceptados por ndcli: internal, public, both o default.
    """
    if view_raw is None:
        return "default"
    normalized = view_raw.strip().lower()
    if not normalized:
        return "default"

    mapping = {
        "internal": "internal",
        "interna": "internal",
        "public": "public",
        "publica": "public",
        "pública": "public",
        "both": "both",
        "internal/public": "both",
        "public/internal": "both",
        "internal public": "both",
        "public internal": "both",
        "interna/publica": "both",
        "interna/pública": "both",
        "publica/interna": "both",
        "pública/interna": "both",
    }
    return mapping.get(normalized, normalized)


def _validate_pool(pool: str) -> None:
    if not POOL_RE.match(pool):
        raise HTTPException(status_code=400, detail="Nombre de pool inválido")


def _format_ndcli_command(args: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in ["ndcli", *args])


def _parse_list_ips(output: str) -> List[Dict[str, str]]:
    """Parses a simple ndcli 'list ips' table into a list of dicts."""
    rows: List[Dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("result for") or line.lower().startswith("ip "):
            continue
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        status = parts[1] if len(parts) > 1 else "-"

        # El resto de la línea puede contener DNS y/o comentario con espacios
        remainder = line[len(ip) :].strip()
        if status:
            remainder = remainder[len(status) :].strip()

        ptr_target = ""
        comment = ""
        dns_view = None
        if remainder:
            tokens = remainder.split()
            if "view" in tokens:
                try:
                    idx_view = tokens.index("view")
                    if idx_view + 1 < len(tokens):
                        dns_view = tokens[idx_view + 1]
                        del tokens[idx_view : idx_view + 2]
                except ValueError:
                    pass
            if tokens and "." in tokens[0] and not tokens[0].startswith("-"):
                ptr_target = tokens[0]
                comment = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            else:
                comment = " ".join(tokens).strip() or remainder
        rows.append(
            {
                "ip": ip,
                "status": status.lower(),
                "ptr_target": ptr_target or None,
                "comment": comment,
                "dns_view": dns_view.lower() if dns_view else None,
            }
        )
    return rows


def _parse_list_pool(output: str) -> List[str]:
    """Parses 'ndcli list pool <pool>' and extracts subnet/cidr values."""
    subnets: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("prio") or line.lower().startswith("info -"):
            continue
        parts = line.split()
        if len(parts) >= 2 and "/" in parts[1]:
            subnets.append(parts[1])
    return subnets


def _run_pool_command(args: List[str], layer3domain: Optional[str]) -> str:
    """
    Ejecuta comandos de pool. Algunos ndcli no aceptan 'layer3domain' como token;
    si aparece 'Unparsed tokens: layer3domain' volvemos a intentar sin ese token.
    """
    try:
        return run_ndcli(args)
    except NdcliError:
        return run_ndcli(args)


def _optional_ndcli(args: List[str]) -> str:
    """Executes ndcli but tolerates missing binary."""
    try:
        return run_ndcli(args)
    except FileNotFoundError:
        # In entornos sin ndcli devolvemos vacío simulando sin resultados
        return ""


def _find_pools_by_vlan(vlan: str, layer3domain: str, allowed_prefixes: tuple[str, ...]) -> List[str]:
    """
    Ejecuta `ndcli list pools layer3domain <l3d>` y filtra las líneas que contengan la VLAN
    y además cuyos pools empiecen por alguno de los prefijos permitidos.
    """
    pools: List[str] = []
    try:
        out = run_ndcli(["list", "pools", "layer3domain", layer3domain])
    except NdcliError:
        return pools

    for line in out.splitlines():
        tokens = line.strip().split()
        if len(tokens) < 2:
            continue
        pool_name = tokens[0]
        vlan_token = tokens[1]
        if vlan_token != vlan:
            continue
        if not pool_name.lower().startswith(allowed_prefixes):
            continue
        pools.append(pool_name)
    return pools


def _detect_views_for_fqdn(fqdn: str, layer3domain: Optional[str]) -> List[str]:
    """
    Devuelve las vistas existentes para un fqdn usando `show rr ... view <vista>`.
    Prueba con y sin layer3domain porque algunos ndcli no aceptan ese token.
    """
    views_found: List[str] = []
    clean = fqdn.rstrip(".")
    fqdn_with_dot = f"{clean}."
    if not clean:
        return views_found

    def _has_view(candidate: str) -> bool:
        commands = [
            with_layer3domain(["show", "rr", fqdn_with_dot, "a", "view", candidate], layer3domain),
            ["show", "rr", fqdn_with_dot, "a", "view", candidate],
        ]
        for cmd in commands:
            try:
                out = _optional_ndcli(cmd)
            except NdcliError as exc:
                logger.warning("detect_views ndcli error cmd=%s rc=%s stderr=%s", cmd, exc.rc, exc.stderr)
                continue
            if out.strip():
                return True
        return False

    for cand in ("internal", "public"):
        if _has_view(cand):
            views_found.append(cand)
    return views_found


@app.post("/api/dns/view")
async def dns_view(payload: dict, _: str = Depends(require_session)):
    name = (payload.get("name") or "").strip()
    layer3domain = (payload.get("layer3domain") or "").strip() or None
    if not name or not FQDN_RE.match(name):
        raise HTTPException(status_code=400, detail="FQDN inválido")
    views = _detect_views_for_fqdn(name, layer3domain)
    merged = _merge_views(None, "/".join(views))
    logger.info("dns_view name=%s layer3domain=%s detected_views=%s merged=%s", name, layer3domain, views, merged)
    return {"name": name, "views": views, "view": merged or "default"}


# ---- Endpoints auxiliares restaurados ----


@app.post("/api/subnet/ips")
async def list_subnet_ips(payload: dict, _: str = Depends(require_session)):
    subnet = (payload.get("subnet") or "").strip()
    layer3domain = (payload.get("layer3domain") or "").strip() or None
    status = (payload.get("status") or "all").strip().lower()
    limit = payload.get("limit") or 256

    if not subnet:
        raise HTTPException(status_code=400, detail="Subred inválida")
    try:
        ipaddress.ip_network(subnet, strict=False)
    except Exception:
        raise HTTPException(status_code=400, detail="Subred inválida")

    args = ["list", "ips", subnet, "status", status]
    try:
        lim = int(limit)
        if lim > 0:
            args += ["-L", str(lim)]
    except Exception:
        pass
    args = with_layer3domain(args, layer3domain)
    output = _optional_ndcli(args)
    rows = _parse_list_ips(output)
    if not rows:
        return []
    # Enriquecemos vistas DNS para dominios arsyscloud.tools
    targets = {(row.get("ptr_target") or "").rstrip(".").lower() for row in rows if row.get("ptr_target")}
    targets = {t for t in targets if t.endswith(".arsyscloud.tools")}
    view_map: Dict[str, str] = {}
    for fqdn in targets:
        merged = _merge_views(None, "/".join(_detect_views_for_fqdn(fqdn, layer3domain)))
        if merged:
            view_map[fqdn] = merged
    for row in rows:
        ptr = (row.get("ptr_target") or "").rstrip(".").lower()
        if not ptr:
            continue
        if ptr.endswith(".arsyscloud.tools"):
            row["dns_view"] = view_map.get(ptr)
        else:
            row["dns_view"] = "default"
    if limit:
        try:
            lim = int(limit)
            if lim > 0:
                rows = rows[:lim]
        except Exception:
            pass
    return rows


@app.post("/api/ip/reserve")
async def reserve_ip(payload: dict, _: str = Depends(require_session)):
    pool = (payload.get("pool") or "").strip()
    ip_value = (payload.get("ip") or "").strip()
    comment = (payload.get("comment") or "").strip()
    create_dns = payload.get("create_dns")
    fqdn = (payload.get("fqdn") or "").strip()
    view = _normalize_view_value(payload.get("view"))
    layer3domain = (payload.get("layer3domain") or "").strip() or default_layer3domain()

    if not pool or not POOL_RE.match(pool):
        raise HTTPException(status_code=400, detail="Pool inválido")
    try:
        ipaddress.ip_address(ip_value)
    except Exception:
        raise HTTPException(status_code=400, detail="IP inválida")

    wants_dns = True if create_dns is None else bool(create_dns)

    if wants_dns:
        if not fqdn:
            raise HTTPException(status_code=400, detail="FQDN inválido")
        cmd_args = ["create", "rr", fqdn, "a", ip_value]
        if view and view != "default":
            cmd_args += ["view", view]
        if layer3domain:
            cmd_args += ["layer3domain", layer3domain]
        commands_executed = []
        command_str = _format_ndcli_command(cmd_args)
        commands_executed.append(command_str)
        try:
            output = _optional_ndcli(cmd_args)
        except NdcliError as exc:
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

        second_command = ""
        if comment:
            escaped_comment = comment.replace('"', '\\"')
            cmd_comment = ["modify", "pool", pool, "ip", ip_value, "set", "attrs", f'comment:{escaped_comment}']
            second_command = _format_ndcli_command(cmd_comment)
            commands_executed.append(second_command)
            try:
                _optional_ndcli(cmd_comment)
            except NdcliError as exc:
                raise HTTPException(status_code=502, detail=exc.stderr or "Fallo aplicando comentario") from exc

        return {
          "action": "executed",
          "detail": "IP reservada y DNS creado correctamente" if comment else "IP reservada con DNS",
          "command": command_str,
          "commands": commands_executed,
          "output": output,
          "comment_command": second_command or None,
        }
    else:
        escaped_comment = comment.replace('"', '\\"')
        cmd_args = ["modify", "pool", pool, "mark", "ip", ip_value]
        if escaped_comment:
            cmd_args.append(f'comment:{escaped_comment}')

    command_str = _format_ndcli_command(cmd_args)
    output = ""
    try:
        output = _optional_ndcli(cmd_args)
    except NdcliError as exc:
        stderr_lower = (exc.stderr or "").lower()
        if "already allocated" in stderr_lower and "static" in stderr_lower:
            raise HTTPException(status_code=409, detail="La IP ya está reservada (estado Static)") from exc
        raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

    return {
        "action": "executed",
        "detail": "IP reservada correctamente" if output is not None else "IP reservada",
        "command": command_str,
        "output": output,
    }


@app.post("/api/ip/release")
async def release_ip(payload: dict, _: str = Depends(require_session)):
    pool = (payload.get("pool") or "").strip()
    ip_value = (payload.get("ip") or "").strip()

    _validate_pool(pool)
    ip_value = _normalize_ip_simple(ip_value)

    cmd_args = ["modify", "pool", pool, "free", "ip", ip_value]
    command_str = _format_ndcli_command(cmd_args)

    try:
        output = _optional_ndcli(cmd_args)
    except NdcliError as exc:
        stderr_lower = (exc.stderr or "").lower()
        if "not allocated" in stderr_lower or "not in pool" in stderr_lower:
            raise HTTPException(status_code=409, detail="La IP no estaba reservada en este pool") from exc
        raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

    return {
        "action": "executed",
        "detail": "IP liberada correctamente",
        "command": command_str,
        "output": output,
    }


@app.post("/api/ip/edit")
async def edit_ip(payload: dict, _: str = Depends(require_session)):
    pool = (payload.get("pool") or "").strip()
    ip_value = (payload.get("ip") or "").strip()
    new_dns = (payload.get("dns") or "").strip()
    old_dns = (payload.get("old_dns") or "").strip()
    comment = (payload.get("comment") or "").strip()
    view = _normalize_view_value(payload.get("view"))
    old_view = _normalize_view_value(payload.get("old_view"))
    layer3domain = (payload.get("layer3domain") or "").strip() or default_layer3domain()
    changed_dns = bool(payload.get("changed_dns"))
    changed_comment = bool(payload.get("changed_comment"))

    _validate_pool(pool)
    ip_value = _normalize_ip_simple(ip_value)

    if not changed_dns and not changed_comment:
        return {"action": "noop", "detail": "Sin cambios"}

    if changed_dns and new_dns:
        if not new_dns.endswith(".") or not FQDN_RE.match(new_dns):
            raise HTTPException(status_code=400, detail="FQDN inválido")

    def _views_for_dns(name: str, view_value: str) -> List[str]:
        """
        Devuelve las vistas explícitas indicadas (internal/public/both) aunque el dominio no sea arsyscloud.tools.
        Para dominios arsyscloud.tools sin vista explícita devolvemos [] para forzar la validación más abajo.
        """
        lowered = _normalize_view_value(view_value)
        normalized_name = (name or "").lower().rstrip(".")
        if lowered in ("both", "internal/public", "public/internal"):
            return ["internal", "public"]
        if lowered in ("internal", "public"):
            return [lowered]
        if normalized_name.endswith(".arsyscloud.tools"):
            return []
        return []

    commands: List[str] = []
    outputs: List[str] = []
    normalized_old_dns = old_dns.lower().rstrip(".")
    normalized_new_dns = new_dns.lower().rstrip(".") if new_dns else ""
    old_views = _views_for_dns(old_dns, old_view)
    # Para dominios arsyscloud.tools intentamos detectar las vistas reales, aunque cambie el nombre
    if normalized_old_dns.endswith(".arsyscloud.tools"):
        detected_old_any = _detect_views_for_fqdn(normalized_old_dns, layer3domain)
        if detected_old_any:
            old_views = detected_old_any
    # Si es el mismo FQDN arsyscloud.tools, forzamos detección real de vistas para no depender del payload
    same_dns_name = bool(new_dns and old_dns and normalized_old_dns == normalized_new_dns)
    if same_dns_name and normalized_new_dns.endswith(".arsyscloud.tools"):
        detected_old_same = _detect_views_for_fqdn(normalized_old_dns, layer3domain)
        if detected_old_same:
            old_views = detected_old_same
    new_views = _views_for_dns(new_dns, view) if new_dns else []

    # Si el FQDN exige vista y no hemos obtenido ninguna, forzamos 'internal' por defecto
    if new_dns:
        normalized_name = new_dns.lower().rstrip(".")
        if normalized_name.endswith(".arsyscloud.tools") and not new_views:
            new_views = ["internal"]

    views_diff = set(old_views) != set(new_views)
    needs_view_update = same_dns_name and normalized_new_dns.endswith(".arsyscloud.tools") and views_diff
    dns_change = changed_dns or needs_view_update

    logger.info(
        "edit_ip payload pool=%s ip=%s dns=%s old_dns=%s view=%s old_view=%s new_views=%s old_views=%s needs_view_update=%s",
        pool,
        ip_value,
        new_dns,
        old_dns,
        view,
        old_view,
        new_views,
        old_views,
        needs_view_update,
    )

    if dns_change and old_dns:
        if needs_view_update:
            views_to_remove = sorted(set(old_views) - set(new_views))
            for v in views_to_remove:
                cmd_del = ["delete", "rr", old_dns, "a", "view", v]
                commands.append(_format_ndcli_command(cmd_del))
                logger.info("edit_ip running: %s", commands[-1])
                try:
                    outputs.append(_optional_ndcli(cmd_del))
                except NdcliError as exc:
                    if _looks_like_not_found(exc):
                        logger.warning("edit_ip delete (viewed) not found, ignoring: %s", exc.stderr)
                        continue
                    raise HTTPException(status_code=502, detail=exc.stderr or "Fallo eliminando DNS") from exc
        else:
            delete_views: List[str] = []
            if old_views:
                delete_views = old_views
            elif normalized_old_dns.endswith(".arsyscloud.tools"):
                delete_views = ["internal", "public"] if view == "both" else ([view] if view and view != "default" else [])
            if delete_views:
                for v in delete_views:
                    cmd_del = ["delete", "rr", old_dns, "a", "view", v]
                    commands.append(_format_ndcli_command(cmd_del))
                    logger.info("edit_ip running: %s", commands[-1])
                    try:
                        outputs.append(_optional_ndcli(cmd_del))
                    except NdcliError as exc:
                        if _looks_like_not_found(exc):
                            logger.warning("edit_ip delete (viewed) not found, ignoring: %s", exc.stderr)
                            continue
                        raise HTTPException(status_code=502, detail=exc.stderr or "Fallo eliminando DNS") from exc
            else:
                cmd_del = ["delete", "rr", old_dns, "a"]
                commands.append(_format_ndcli_command(cmd_del))
                logger.info("edit_ip running: %s", commands[-1])
                try:
                    outputs.append(_optional_ndcli(cmd_del))
                except NdcliError as exc:
                    if _looks_like_not_found(exc):
                        logger.warning("edit_ip delete (no-view) not found, ignoring: %s", exc.stderr)
                    else:
                        raise HTTPException(status_code=502, detail=exc.stderr or "Fallo eliminando DNS") from exc

    if dns_change and new_dns:
        if needs_view_update:
            views_to_create = sorted(set(new_views) - set(old_views))
            for v in views_to_create:
                cmd_create = ["create", "rr", new_dns, "a", ip_value, "view", v]
                if layer3domain:
                    cmd_create += ["layer3domain", layer3domain]
                commands.append(_format_ndcli_command(cmd_create))
                logger.info("edit_ip running: %s", commands[-1])
                try:
                    outputs.append(_optional_ndcli(cmd_create))
                except NdcliError as exc:
                    raise HTTPException(status_code=502, detail=exc.stderr or "Fallo creando DNS") from exc
        else:
            if new_views:
                for v in new_views:
                    cmd_create = ["create", "rr", new_dns, "a", ip_value, "view", v]
                    if layer3domain:
                        cmd_create += ["layer3domain", layer3domain]
                    commands.append(_format_ndcli_command(cmd_create))
                    logger.info("edit_ip running: %s", commands[-1])
                    try:
                        outputs.append(_optional_ndcli(cmd_create))
                    except NdcliError as exc:
                        raise HTTPException(status_code=502, detail=exc.stderr or "Fallo creando DNS") from exc
            else:
                cmd_create = ["create", "rr", new_dns, "a", ip_value]
                if view and view != "default":
                    cmd_create += ["view", view]
                if layer3domain:
                    cmd_create += ["layer3domain", layer3domain]
                commands.append(_format_ndcli_command(cmd_create))
                logger.info("edit_ip running: %s", commands[-1])
                try:
                    outputs.append(_optional_ndcli(cmd_create))
                except NdcliError as exc:
                    raise HTTPException(status_code=502, detail=exc.stderr or "Fallo creando DNS") from exc

    if changed_comment or dns_change:
        escaped_comment = comment.replace('"', '\\"')
        if changed_dns and not new_dns:
            cmd_comment = ["modify", "pool", pool, "mark", "ip", ip_value, f'comment:{escaped_comment}']
        else:
            cmd_comment = ["modify", "pool", pool, "ip", ip_value, "set", "attrs", f'comment:{escaped_comment}']
        commands.append(_format_ndcli_command(cmd_comment))
        logger.info("edit_ip running: %s", commands[-1])
        try:
            outputs.append(_optional_ndcli(cmd_comment))
        except NdcliError as exc:
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo aplicando comentario") from exc

    return {
        "action": "executed",
        "detail": "IP actualizada correctamente",
        "commands": commands,
        "output": outputs,
    }

@app.post("/api/dns/check")
async def dns_check(payload: dict, _: str = Depends(require_session)):
    name = (payload.get("name") or "").strip()
    view = _normalize_view_value(payload.get("view"))
    if not name:
        raise HTTPException(status_code=400, detail="FQDN inválido")

    args = ["list", "rrs", name, "a"]
    if view and view != "default":
        args += ["view", view]
    try:
        output = _optional_ndcli(args)
        exists = bool(output.strip())
    except NdcliError as exc:
        if _looks_like_not_found(exc):
            exists = False
        else:
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

    return {"name": name, "view": view or "default", "exists": exists}


@app.post("/api/dns/create")
async def dns_create(payload: dict, _: str = Depends(require_session)):
    name = (payload.get("name") or "").strip()
    record_type = (payload.get("record_type") or "A").strip().upper()
    value = (payload.get("value") or "").strip()
    view = _normalize_view_value(payload.get("view"))
    layer3domain = (payload.get("layer3domain") or "").strip()
    dry_run = bool(payload.get("dry_run"))

    if not name or not value:
        raise HTTPException(status_code=400, detail="Datos DNS incompletos")

    if not layer3domain:
        layer3domain = _detect_layer3domain_for_ip(value) or default_layer3domain()

    args = ["create", "rr", name, record_type, value]
    if view and view != "default":
        args += ["view", view]
    if layer3domain:
        args += ["layer3domain", layer3domain]
    command_str = _format_ndcli_command(args + (["--dryrun"] if dry_run else []))

    if dry_run:
        try:
            output = run_ndcli([*args, "--dryrun"], include_stderr=True)
        except FileNotFoundError:
            output = ""
        except NdcliError as exc:
            raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc
        return {
            "action": "preview",
            "command": command_str,
            "name": name,
            "record_type": record_type,
            "value": value,
            "view": view,
            "layer3domain": layer3domain,
            "output": output,
        }

    try:
        output = _optional_ndcli(args)
    except NdcliError as exc:
        raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

    return {
        "action": "executed",
        "command": command_str,
        "name": name,
        "record_type": record_type,
        "value": value,
        "view": view,
        "layer3domain": layer3domain,
        "detail": "Registro creado",
        "output": output,
    }


@app.post("/api/ip/layer3domain")
async def detect_layer3domain(payload: dict, _: str = Depends(require_session)):
    ip_value = (payload.get("ip") or "").strip()
    l3d = _detect_layer3domain_for_ip(ip_value)
    if not l3d:
        raise HTTPException(status_code=404, detail="No se encontró layer3domain para la IP")
    return {"ip": ip_value, "layer3domain": l3d}


@app.post("/api/dns/delete")
async def dns_delete(payload: dict, _: str = Depends(require_session)):
    name = (payload.get("name") or "").strip()
    view = _normalize_view_value(payload.get("view"))
    dry_run = bool(payload.get("dry_run"))

    if not name:
        raise HTTPException(status_code=400, detail="FQDN inválido")

    args = ["delete", "rr", name, "a"]
    if view and view != "default":
        args += ["view", view]
    command_str = _format_ndcli_command(args)

    if dry_run:
        return {"action": "preview", "command": command_str, "name": name, "view": view}

    try:
        output = _optional_ndcli(args)
    except NdcliError as exc:
        if _looks_like_not_found(exc):
            raise HTTPException(status_code=404, detail="Registro DNS no encontrado")
        raise HTTPException(status_code=502, detail=exc.stderr or "Fallo ejecutando ndcli") from exc

    return {"action": "executed", "command": command_str, "name": name, "view": view, "output": output}


@app.post("/api/dns/bulk/preview")
async def dns_bulk_preview(payload: dict, _: str = Depends(require_session)):
    items = payload.get("items") or []
    results = []
    for item in items:
        name = (item.get("name") or "").strip()
        record_type = (item.get("record_type") or "A").strip().upper()
        value = (item.get("value") or "").strip()
        view = _normalize_view_value(item.get("view"))
        if not name or not value:
            results.append(
                {
                    "status": "error",
                    "detail": "Entrada inválida",
                    "detailField": "name" if not name else "value",
                    "layer3domain": "ERROR (Revisar manualmente)",
                    "view": view,
                }
            )
            continue
        results.append(
            {
                "status": "ok",
                "detail": "",
                "layer3domain": default_layer3domain(),
                "view": view,
            }
        )
    return results


@app.post("/api/dns/bulk/delete/preview")
async def dns_bulk_delete_preview(payload: dict, _: str = Depends(require_session)):
    items = payload.get("items") or []
    results = []
    for item in items:
        name = (item.get("name") or "").strip()
        view = _normalize_view_value(item.get("view"))
        if not name:
            results.append(
                {
                    "status": "error",
                    "detail": "FQDN inválido",
                    "records": [],
                    "view": view,
                }
            )
            continue
        results.append(
            {
                "status": "ok",
                "detail": "",
                "records": [],
                "view": view,
            }
        )
    return results


@app.post("/api/dns/bulk/delete/execute")
async def dns_bulk_delete_execute(payload: dict, _: str = Depends(require_session)):
    items = payload.get("items") or []
    results = []
    for item in items:
        name = (item.get("name") or "").strip()
        view = _normalize_view_value(item.get("view"))
        cmd = ["delete", "rr", name, "a"]
        if view and view != "default":
            cmd += ["view", view]
        cmd_str = _format_ndcli_command(cmd)
        try:
            output = _optional_ndcli(cmd)
            results.append(
                {
                    "name": name,
                    "view": view,
                    "action": "executed",
                    "detail": "Eliminado",
                    "command": cmd_str,
                    "output": output,
                }
            )
        except NdcliError as exc:
            results.append(
                {
                    "name": name,
                    "view": view,
                    "action": "error",
                    "detail": exc.stderr or "Fallo ejecutando ndcli",
                    "command": cmd_str,
                    "output": "",
                }
            )
    return results


# Servir frontend estático
static_dir = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")
