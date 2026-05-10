from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional


# Microsoft's OIDC metadata endpoint — used to fetch the JWKS for token validation
ENTRA_OIDC_METADATA_TEMPLATE = (
    "https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
)

# Microsoft Graph endpoint for group/role resolution
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


@dataclass
class EntraConfig:


    tenant_id: str
    client_id: str
    audience: str                           # Expected 'aud' claim in tokens

    client_secret: Optional[str] = None    # Not needed for token validation only

    # Maps Entra group display-name or OID → brand_scope values
    brand_group_map: dict[str, list[str]] = field(default_factory=dict)

    # Maps Entra app role value → SensitivityLevel string
    clearance_role_map: dict[str, str] = field(default_factory=lambda: {
        "DataReader":   "internal",
        "DataAnalyst":  "confidential",
        "DataSteward":  "confidential",
        "DataAdmin":    "restricted",
    })

    # If True, validate the 'tid' claim to prevent cross-tenant token use
    validate_tenant: bool = True

    # Clock-skew tolerance in seconds for nbf/exp validation
    clock_skew_seconds: int = 60

    # Scope to request when exchanging a user token for a downstream scope
    obo_downstream_scope: Optional[str] = None

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def oidc_metadata_url(self) -> str:
        return ENTRA_OIDC_METADATA_TEMPLATE.format(tenant_id=self.tenant_id)


    @classmethod
    def from_env(cls) -> "EntraConfig":
        # raises ValueError if ENTRA_TENANT_ID or ENTRA_CLIENT_ID are missing
        tenant_id = os.environ.get("ENTRA_TENANT_ID", "").strip()
        client_id = os.environ.get("ENTRA_CLIENT_ID", "").strip()
        audience  = os.environ.get("ENTRA_AUDIENCE", client_id).strip()

        if not tenant_id:
            raise ValueError(
                "ENTRA_TENANT_ID environment variable is required. "
                "Find it in Azure Portal → Entra ID → Overview → Tenant ID."
            )
        if not client_id:
            raise ValueError(
                "ENTRA_CLIENT_ID environment variable is required. "
                "Find it in Azure Portal → Entra ID → App registrations → "
                "your app → Application (client) ID."
            )

        brand_group_map: dict[str, list[str]] = {}
        raw_bgm = os.environ.get("ENTRA_BRAND_GROUP_MAP", "")
        if raw_bgm:
            try:
                brand_group_map = json.loads(raw_bgm)
            except json.JSONDecodeError as e:
                raise ValueError(f"ENTRA_BRAND_GROUP_MAP is not valid JSON: {e}")

        clearance_role_map: dict[str, str] = {}
        raw_crm = os.environ.get("ENTRA_CLEARANCE_ROLE_MAP", "")
        if raw_crm:
            try:
                clearance_role_map = json.loads(raw_crm)
            except json.JSONDecodeError as e:
                raise ValueError(f"ENTRA_CLEARANCE_ROLE_MAP is not valid JSON: {e}")

        return cls(
            tenant_id=tenant_id,
            client_id=client_id,
            audience=audience,
            client_secret=os.environ.get("ENTRA_CLIENT_SECRET") or None,
            brand_group_map=brand_group_map,
            clearance_role_map=clearance_role_map or {
                "DataReader":   "internal",
                "DataAnalyst":  "confidential",
                "DataSteward":  "confidential",
                "DataAdmin":    "restricted",
            },
            obo_downstream_scope=os.environ.get("ENTRA_OBO_SCOPE") or None,
        )

    @classmethod
    def for_testing(
        cls,
        tenant_id: str = "test-tenant-id",
        client_id: str = "test-client-id",
        brand_group_map: Optional[dict] = None,
        clearance_role_map: Optional[dict] = None,
    ) -> "EntraConfig":

        return cls(
            tenant_id=tenant_id,
            client_id=client_id,
            audience=client_id,
            client_secret=None,
            brand_group_map=brand_group_map or {
                "Division-A-Analysts":  ["brand_b"],
                "Corp-Group-All":   ["brand_a", "brand_b", "brand_c", "brand_d", "brand_e"],
                "Division-B-Team":   ["brand_c"],
            },
            clearance_role_map=clearance_role_map or {
                "DataReader":   "internal",
                "DataAnalyst":  "confidential",
                "DataSteward":  "confidential",
                "DataAdmin":    "restricted",
            },
            validate_tenant=False,   # Disable for test tokens
        )
