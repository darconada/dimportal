from pydantic import BaseModel, Field
from typing import List, Literal, Optional

SearchType = Literal["pool", "subnet", "vlan", "dns", "ip", "device"]
ImportStatus = Literal["ok", "error"]
ImportAction = Literal["executed", "skipped", "error"]
ImportDryrunStatus = Literal["ok", "error"]


class SearchQuery(BaseModel):
    type: SearchType
    q: str = Field(min_length=1)
    layer3domain: Optional[str] = None


class ResultItem(BaseModel):
    pool: str
    vlan: Optional[str]
    subnets: List[str]
    layer3domain: str
    dns_zone: Optional[str] = None
    fqdn: Optional[str] = None
    ip_address: Optional[str] = None
    dns_view: Optional[str] = None
    ptr_target: Optional[str] = None
    comment: Optional[str] = None
    device: Optional[str] = None


class LoginPayload(BaseModel):
    username: str
    password: str


class SessionInfo(BaseModel):
    username: str
    display_name: Optional[str] = None


class ImportIPRequestItem(BaseModel):
    ip: str
    hostname: Optional[str] = None


class ImportIPPayload(BaseModel):
    items: List[ImportIPRequestItem] = Field(default_factory=list)


class ImportIPResponseItem(BaseModel):
    ip: str
    hostname: Optional[str] = None
    pool: Optional[str] = None
    layer3domain: Optional[str] = None
    status: ImportStatus
    detail: Optional[str] = None


class ImportExecuteRequestItem(BaseModel):
    ip: str
    pool: str
    layer3domain: str
    hostname: Optional[str] = None


class ImportExecutePayload(BaseModel):
    items: List[ImportExecuteRequestItem] = Field(default_factory=list)


class ImportExecuteResponseItem(BaseModel):
    ip: str
    hostname: Optional[str] = None
    pool: Optional[str] = None
    layer3domain: Optional[str] = None
    action: ImportAction
    detail: Optional[str] = None
    status: Optional[str] = None
    existing_comment: Optional[str] = None
    command: Optional[str] = None
    output: Optional[str] = None


class ImportDryrunResponseItem(BaseModel):
    ip: str
    hostname: Optional[str] = None
    pool: Optional[str] = None
    layer3domain: Optional[str] = None
    status: ImportDryrunStatus
    output: Optional[str] = None
    error: Optional[str] = None
    command: Optional[str] = None
