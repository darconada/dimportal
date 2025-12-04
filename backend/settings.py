from pydantic import BaseModel
from typing import List, Optional
import os
import configparser
from pathlib import Path
from dotenv import load_dotenv

# Lista cerrada de layer3domains (amplía aquí cuando sea necesario)
LAYER3DOMAINS: List[str] = [
    "default",
    "8560-arsys-rfc1918",
    "8560-arsys-acs-rfc1918-cbd-mia",
    "8560-arsys-acs-rfc1918-cbd-por",
    "8560-arsys-acs-rfc1918-cbd-glb",
    "8560-arsys-acs-rfc1918-flex",
    "8560-arsys-acs-rfc1918-ded-env-592525-uax",
    "8560-arsys-acs-rfc1918-ded-env-276092-cgcof",
    "8560-arsys-acs-rfc1918-ded-env-479589-lks",
    "8560-arsys-acs-rfc1918-ded-env-370855-setram",
    "8560-arsys-acs-rfc1918-ded-env-612183-vasalto",
]

# Dominio ACS filtrado (heurística: contiene "acs")
ACS_LAYER3DOMAINS: List[str] = [l for l in LAYER3DOMAINS if "acs" in l]

DEFAULT_TIMEOUT = 10  # segundos

# Carga variables de entorno desde .env en la raíz del proyecto
ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")
load_dotenv(Path(__file__).resolve().parent / ".env")


def default_layer3domain() -> str:
    """Lee el layer3domain por defecto desde ~/.ndclirc si existe, si no devuelve 'default'."""
    ndcli_rc = Path.home() / ".ndclirc"
    if ndcli_rc.is_file():
        parser = configparser.ConfigParser()
        try:
            parser.read(ndcli_rc)
            if parser.has_option("global", "layer3domain"):
                return parser.get("global", "layer3domain")
        except Exception:
            pass
    return "default"


class LdapConfig(BaseModel):
    server_url: str = "ldaps://ldap.1and1.org:636"
    base_dn: str = "ou=toacsengnetworkdimportal,ou=ims_service,o=1und1,c=DE"
    bind_dn: str = "uid=toacsengnetworkdimportal,ou=accounts,ou=ims_service,o=1und1,c=DE"
    bind_password: Optional[str] = os.getenv("LDAP_BIND_PASSWORD") or None
    member_dn_template: str = "uid={username},ou=users,ou=toacsengnetworkdimportal,ou=ims_service,o=1und1,c=DE"
    verify_ssl: bool = False
    user_attribute: str = "uid"
