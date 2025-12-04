import re
from typing import Dict, List, Optional

# Utilidades de parseo para salidas de ndcli tipo "key:value"
KV_LINE = re.compile(r"^(?P<k>[a-zA-Z_]+):(?P<v>.*)$")
CIDR_PATTERN = re.compile(r"^\\d{1,3}(?:\\.\\d{1,3}){3}/\\d{1,2}$")


def parse_kv_block(out: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in out.splitlines():
        m = KV_LINE.match(line.strip())
        if m:
            k = m.group("k").strip().lower()
            v = m.group("v").strip()
            data[k] = v
    return data


def parse_show_subnet(out: str) -> Dict[str, str]:
    # Espera campos como: pool:, layer3domain:, ip:, reverse_zone:
    return parse_kv_block(out)


def parse_show_pool(out: str) -> Dict[str, str]:
    data = parse_kv_block(out)
    if "layer3domain" not in data:
        for line in out.splitlines():
            line = line.strip().lower()
            if line.startswith("layer3domain:"):
                _, _, value = line.partition(":")
                data["layer3domain"] = value.strip()
                break
    return data


def extract_subnets_from_list_ips(out: str) -> List[str]:
    # Heurística: cuando listamos IPs por una entidad (VLAN/CIDR/POOL),
    # mapeamos cada IP a su subnet si la salida la incluye, o asumimos el prefijo base
    # (ajusta a tu formato concreto). Aquí detectamos líneas con "subnet:".
    subnets: set[str] = set()
    for line in out.splitlines():
        if "subnet:" in line.lower():
            parts = line.split("subnet:")
            if len(parts) > 1:
                cidr = parts[1].strip().split()[0]
                if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", cidr):
                    subnets.add(cidr)
    return sorted(subnets)


def parse_first_block(out: str) -> Dict[str, str]:
    """Devuelve el primer bloque key:value de una salida ndcli show."""
    blocks = parse_script_blocks(out)
    return blocks[0] if blocks else {}


def parse_script_blocks(out: str) -> List[Dict[str, str]]:
    """Divide la salida en bloques separados por líneas en blanco y parsea key:value."""
    blocks: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            if current:
                blocks.append(current)
                current = {}
            continue
        if line.lower().startswith("result for"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        current[key.strip().lower()] = value.strip()
    if current:
        blocks.append(current)
    return blocks
