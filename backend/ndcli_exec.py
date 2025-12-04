import subprocess
import os
import contextvars
from typing import Dict, List, Optional
from settings import DEFAULT_TIMEOUT

_ndcli_creds = contextvars.ContextVar("ndcli_creds", default=None)


class NdcliError(Exception):
    def __init__(self, msg: str, rc: int = 1, stderr: str = "", stdout: str = ""):
        super().__init__(msg)
        self.rc = rc
        self.stderr = stderr
        self.stdout = stdout


def set_ndcli_credentials(user: Optional[str], password: Optional[str]) -> None:
  """Guarda credenciales asociadas al contexto actual para comandos ndcli."""
  if user and password:
      _ndcli_creds.set({"user": user, "password": password})
  else:
      _ndcli_creds.set(None)


def run_ndcli(
    args: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    creds: Optional[Dict[str, str]] = None,
    include_stderr: bool = False,
) -> str:
    """
    Ejecuta ndcli con timeout. Devuelve stdout como str.
    Si include_stderr=True, concatena stdout+stderr en éxito para capturar banners informativos.
    Lanza NdcliError si rc != 0.
    """
    cmd_args = list(args)
    effective_creds = creds if creds is not None else _ndcli_creds.get(None)
    # Inyecta credenciales explícitas si no se han pasado ya por argumentos
    if effective_creds:
        has_user = any(tok in ("-u", "--username") for tok in cmd_args)
        has_pass = any(tok in ("-p", "--password") for tok in cmd_args)
        if not has_user:
            cmd_args = ["-u", effective_creds["user"], *cmd_args]
        if not has_pass:
            cmd_args = ["-p", effective_creds["password"], *cmd_args]
    cmd = ["ndcli", *cmd_args]
    env = None
    if effective_creds:
        env = os.environ.copy()
        env["NDCLI_USERNAME"] = effective_creds["user"]
        env["NDCLI_USER"] = effective_creds["user"]
        env["NDCLI_PASSWORD"] = effective_creds["password"]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            text=True,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        raise NdcliError(f"ndcli timeout: {' '.join(cmd)}", rc=124) from e

    if proc.returncode != 0:
        raise NdcliError(
            f"ndcli error rc={proc.returncode}",
            rc=proc.returncode,
            stderr=proc.stderr,
            stdout=proc.stdout,
        )
    if include_stderr:
        return f"{proc.stdout}{proc.stderr}"
    return proc.stdout


def with_layer3domain(args: List[str], layer3domain: Optional[str]) -> List[str]:
    # En ndcli suele ir al final: ... layer3domain <L3D>
    if layer3domain:
        return [*args, "layer3domain", layer3domain]
    return args
