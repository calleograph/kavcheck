from typing import Literal

from pydantic import BaseModel, Field


class Filters(BaseModel):
    q: str = Field(default="", max_length=200)
    organization: str = Field(default="", max_length=300)
    department: str = Field(default="", max_length=300)
    division: str = Field(default="", max_length=1000)
    zone: str = Field(default="", pattern=r"^(|none|[0-9a-fA-F-]{36})$")
    kind: str = Field(default="", max_length=300)
    ownership: Literal["", "corporate", "personal", "unknown"] = ""
    os: str = Field(default="", max_length=500)
    status: Literal["", "protected", "partial", "problems", "no_av", "outside_ksc", "stale", "no_devices", "unknown"] = ""
    device_status: Literal["", "protected", "problems", "no_av", "outside_ksc", "stale", "unknown"] = ""
    freshness: Literal["", "fresh", "stale", "unknown"] = ""
    employee_id: str = Field(default="", max_length=120)
    device_id: str = Field(default="", max_length=120)
    confidence: Literal["", "confirmed", "likely", "possible", "rejected"] = ""
    inventory: bool = False
    asset_id: int | None = Field(default=None, gt=0, le=2**63 - 1)
    metric: Literal["", "employees", "uses_av", "protected", "partial", "no_av", "insufficient", "devices", "corporate", "personal"] = ""
