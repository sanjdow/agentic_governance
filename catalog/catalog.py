from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from core.exceptions import AssetNotFoundError, ConsentBlockedError, PolicyResolutionError
from core.models import (
    AccessRight,
    AgentContext,
    DataAsset,
    PolicyVersion,
    SensitivityLevel,
    UserContext,
)


class DataCatalog:
    """
    In-memory data catalog implementing the L1 policy source of truth.

    Provides runtime-queryable APIs for:
    - Asset registration and lookup
    - Sensitivity classification
    - Access right resolution
    - Row/column filter derivation
    - Consent state management
    - Policy versioning

    Thread-safe for read operations. Write operations (register/update)
    should be performed during initialization or under a lock in production.
    """

    def __init__(self) -> None:
        self._assets: dict[str, DataAsset] = {}
        self._consent_state: dict[str, dict[str, bool]] = {}  # {subject_id: {purpose: bool}}
        self._policy_version = self._compute_version()


    def register_asset(self, asset: DataAsset) -> None:
        """Register a data asset. Triggers policy version bump."""
        self._assets[asset.asset_id] = asset
        self._policy_version = self._compute_version()

    def get_asset(self, asset_id: str) -> DataAsset:
        if asset_id not in self._assets:
            raise AssetNotFoundError(f"Asset '{asset_id}' not found in catalog.")
        return self._assets[asset_id]

    def find_assets_by_source(self, source: str) -> list[DataAsset]:
        return [a for a in self._assets.values() if a.source == source]

    def find_assets_by_table(self, table: str) -> list[DataAsset]:
        return [a for a in self._assets.values() if a.table == table]


    def resolve_access(
        self,
        user: UserContext,
        agent: AgentContext,
        asset_id: str,
        required_right: AccessRight,
    ) -> tuple[bool, str]:
        """
        Resolve whether a user+agent combination may access an asset.

        Returns (allowed: bool, reason: str).
        This is the core policy decision that the Policy Resolver calls
        before issuing an Signed Access Token.
        """
        asset = self.get_asset(asset_id)

        # 1. Sensitivity ceiling — agent must be cleared for the asset's level
        if asset.sensitivity > agent.max_sensitivity:
            return False, (
                f"Agent '{agent.agent_id}' max sensitivity "
                f"({agent.max_sensitivity}) below asset sensitivity ({asset.sensitivity})"
            )

        # 2. User clearance must meet asset sensitivity
        if asset.sensitivity > user.clearance_level:
            return False, (
                f"User '{user.user_id}' clearance ({user.clearance_level}) "
                f"insufficient for asset sensitivity ({asset.sensitivity})"
            )

        # 3. Required access right must be in agent's allowed set
        if required_right not in agent.allowed_rights:
            return False, (
                f"Agent '{agent.agent_id}' does not have '{required_right}' right"
            )

        # 4. Brand scope — if asset is brand-tagged, user must have a non-empty
        #    brand scope that intersects with the asset's tags. A user with no
        #    brand scope is denied access to brand-tagged assets — fail closed.
        if asset.brand_tags:
            if not user.brand_scope:
                return False, (
                    f"Asset '{asset_id}' is brand-tagged {asset.brand_tags} "
                    f"but user '{user.user_id}' has no brand scope. "
                    "Fail-closed: brand-tagged assets require explicit brand scope."
                )
            intersection = set(asset.brand_tags) & set(user.brand_scope)
            if not intersection:
                return False, (
                    f"User brand scope {user.brand_scope} does not intersect "
                    f"asset brand tags {asset.brand_tags}"
                )

        # 5. Source allowlist for agent
        if agent.allowed_sources and asset.source not in agent.allowed_sources:
            return False, (
                f"Agent '{agent.agent_id}' is not allowed to access source '{asset.source}'"
            )

        # 6. Consent check for PII assets
        if asset.consent_required:
            # In a real system this would query Securiti or equivalent
            # Here we require the user to have explicit consent recorded
            consent_ok = self._check_consent(user.user_id, asset.asset_id)
            if not consent_ok:
                raise ConsentBlockedError(
                    f"Asset '{asset_id}' requires consent from user '{user.user_id}' "
                    "which has not been recorded or has been withdrawn."
                )

        return True, "Access granted"

    def derive_row_filters(self, user: UserContext, asset: DataAsset) -> dict[str, str]:
        filters: dict[str, str] = {}

        # Brand-level row isolation (e.g. division analysts only see division rows)
        if asset.brand_tags and user.brand_scope:
            allowed_brands = [
                b for b in asset.brand_tags if b in user.brand_scope
            ]
            if allowed_brands:
                # Brands have already been validated as safe identifiers by
                # UserContext._check_user_id, so this quoting is safe.
                quoted = ", ".join(f"'{b}'" for b in allowed_brands)
                filters["brand_filter"] = f"brand IN ({quoted})"

        # Apply asset's row filter template if defined.
        # Template uses {user_id} and {brand_scope} placeholders — values
        # are pre-validated safe identifiers.
        if asset.row_filter_template:
            try:
                resolved = asset.row_filter_template.format(
                    user_id=user.user_id,
                    brand_scope=",".join(f"'{b}'" for b in user.brand_scope),
                )
                filters["row_template_filter"] = resolved
            except KeyError as e:
                # Template referenced an unknown placeholder — fail closed
                raise PolicyResolutionError(
                    f"Row filter template for asset '{asset.asset_id}' "
                    f"references unknown placeholder: {e}"
                )

        return filters

    def derive_column_mask(
        self, user: UserContext, asset: DataAsset
    ) -> list[str]:
        """
        Return the list of columns the user is NOT permitted to see.
        The MCP server will remove these from the result set.
        """
        masked: list[str] = []

        # PII columns are masked unless user has RESTRICTED clearance or above
        if asset.pii_columns and user.clearance_level < SensitivityLevel.RESTRICTED:
            masked.extend(asset.pii_columns)

        return masked


    def record_consent(self, subject_id: str, asset_id: str, granted: bool) -> None:
        """Record or withdraw consent for a data subject and asset."""
        if subject_id not in self._consent_state:
            self._consent_state[subject_id] = {}
        self._consent_state[subject_id][asset_id] = granted
        self._policy_version = self._compute_version()

    def _check_consent(self, subject_id: str, asset_id: str) -> bool:
        return self._consent_state.get(subject_id, {}).get(asset_id, False)


    def get_policy_version(self) -> PolicyVersion:
        """
        Returns the current policy version.
        Proof tokens embed this version so the MCP server can detect
        stale proofs issued under superseded policies.
        """
        return PolicyVersion(
            version_id=self._policy_version,
            created_at=datetime.now(timezone.utc),
        )

    def _compute_version(self) -> str:
        state = json.dumps(
            {
                "assets": {aid: a.model_dump() for aid, a in sorted(self._assets.items())},
                "consent": {
                    sid: dict(sorted(consents.items()))
                    for sid, consents in sorted(self._consent_state.items())
                },
            },
            default=str,
            sort_keys=True,
        )
        return "v:" + hashlib.sha256(state.encode()).hexdigest()[:16]


    def list_assets(self) -> list[DataAsset]:
        return list(self._assets.values())

    def asset_count(self) -> int:
        return len(self._assets)


# ─────────────────────────────────────────────────────────────────────────────
# Factory: pre-populated demo catalog
# ─────────────────────────────────────────────────────────────────────────────

def build_demo_catalog() -> DataCatalog:
    """
    Returns a pre-populated catalog representative of a Enterprise Data Mesh
    environment. Used in examples and tests.
    """
    catalog = DataCatalog()

    catalog.register_asset(DataAsset(
        asset_id="corp_cost_data",
        name="Corp Cost Analytics",
        source="delta_lake",
        table="cost_analytics.group_costs",
        columns=["brand", "cost_center", "amount", "currency", "fiscal_year"],
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        required_rights=[AccessRight.READ, AccessRight.AGGREGATE],
        brand_tags=["brand_a", "brand_b", "brand_c", "brand_d", "brand_e"],
        # Note: row_filter_template is illustrative — production systems should
        # generate filters via sqlglot rather than string templates.
        row_filter_template=None,  # brand filter is sufficient
        pii_columns=[],
        consent_required=False,
        owner="finance_domain",
    ))

    catalog.register_asset(DataAsset(
        asset_id="division_quality_metrics",
        name="Division Quality Analytics",
        source="snowflake",
        table="quality.division_defect_rates",
        columns=["model", "defect_code", "rate", "region", "quarter"],
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        required_rights=[AccessRight.READ],
        brand_tags=["brand_b"],
        row_filter_template=None,
        pii_columns=[],
        consent_required=False,
        owner="division_quality_domain",
    ))

    catalog.register_asset(DataAsset(
        asset_id="employee_hr_data",
        name="Employee HR Records",
        source="postgres",
        table="hr.employees",
        columns=["employee_id", "name", "department", "email", "salary", "birth_date"],
        sensitivity=SensitivityLevel.RESTRICTED,
        required_rights=[AccessRight.READ],
        brand_tags=[],
        row_filter_template=None,
        pii_columns=["name", "email", "salary", "birth_date"],
        consent_required=True,
        owner="hr_domain",
    ))

    catalog.register_asset(DataAsset(
        asset_id="vehicle_telemetry",
        name="Connected Vehicle Telemetry",
        source="delta_lake",
        table="iot.vehicle_telemetry",
        columns=["vin", "timestamp", "speed", "location_lat", "location_lon", "brand"],
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        required_rights=[AccessRight.READ, AccessRight.AGGREGATE],
        brand_tags=["brand_a", "brand_b", "brand_c"],
        pii_columns=["vin", "location_lat", "location_lon"],
        consent_required=True,
        owner="connected_vehicles_domain",
    ))

    catalog.register_asset(DataAsset(
        asset_id="public_parts_catalog",
        name="Public Parts Catalog",
        source="postgres",
        table="parts.catalog",
        columns=["part_id", "description", "price", "supplier"],
        sensitivity=SensitivityLevel.PUBLIC,
        required_rights=[AccessRight.READ],
        brand_tags=[],
        consent_required=False,
        owner="parts_domain",
    ))

    return catalog
