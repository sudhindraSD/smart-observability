"""Slice 3 authentication for the Box 2 control plane.

Two trust principals, never mixed:

* Collectors authenticate with the seeded static token registry (matching the
  defaults shipped in ``collector/sender.py``) via the ``X-Collector-Token``
  header. Region/collector binding is enforced per request.
* Dashboard/API users authenticate with a demo JWT (HS256, PyJWT). The
  ``tenant_id`` and ``region`` used for every authorization decision come
  ONLY from the verified JWT claims — never from query parameters.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Dict

import jwt
from fastapi import HTTPException, Request

_JWT_ALGORITHM = "HS256"
_JWT_SECRET = os.environ.get("SAAS_JWT_SECRET", "slice3-demo-hs256-secret-do-not-use-in-production")
_JWT_EXP_MINUTES = int(os.environ.get("SAAS_JWT_EXP_MINUTES", "720"))
_DEMO_PASSWORD = os.environ.get("SAAS_DEMO_PASSWORD", "demo123")


@dataclass(frozen=True)
class CollectorIdentity:
    tenant_id: str
    region: str
    collector_id: str


@dataclass(frozen=True)
class TenantIdentity:
    tenant_id: str
    region: str


# -- collector token registry ---------------------------------------------------

_DEFAULT_COLLECTOR_TOKENS: Dict[str, CollectorIdentity] = {
    "tok-bank-a-blr": CollectorIdentity(
        tenant_id="bank-a", region="ap-south-1", collector_id="col-blr-01"
    ),
    "tok-hosp-b-fra": CollectorIdentity(
        tenant_id="hospital-b", region="eu-west-1", collector_id="col-fra-01"
    ),
}

# Env overrides remap a seeded identity to a different token value.
_TOKEN_OVERRIDE_ENVS = {
    "SAAS_TOKEN_BANK_A_BLR": "tok-bank-a-blr",
    "SAAS_TOKEN_HOSP_B_FRA": "tok-hosp-b-fra",
}


def _build_collector_registry() -> Dict[str, CollectorIdentity]:
    registry = dict(_DEFAULT_COLLECTOR_TOKENS)
    for env_name, seeded_token in _TOKEN_OVERRIDE_ENVS.items():
        override = os.environ.get(env_name, "").strip()
        if override and override != seeded_token:
            identity = registry.pop(seeded_token, None)
            if identity is not None:
                registry[override] = identity
    extra = os.environ.get("SAAS_COLLECTOR_TOKENS_JSON", "").strip()
    if extra:
        try:
            parsed = json.loads(extra)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            for token, spec in parsed.items():
                try:
                    registry[str(token)] = CollectorIdentity(
                        tenant_id=str(spec["tenant_id"]),
                        region=str(spec["region"]),
                        collector_id=str(spec["collector_id"]),
                    )
                except (KeyError, TypeError):
                    continue
    return registry


COLLECTOR_TOKENS: Dict[str, CollectorIdentity] = _build_collector_registry()


def verify_collector(
    token: str, expected_region: str, expected_collector_id: str
) -> CollectorIdentity:
    """Authenticate a collector token against the registry.

    Raises HTTP 401 for a missing/unknown token and HTTP 403 when the token's
    bound region or collector id does not match the request. (Tenant binding
    is additionally enforced at the endpoint: a payload whose ``tenant_id``
    differs from the token identity is rejected with 403 there.)
    """
    if not token or not token.strip():
        raise HTTPException(status_code=401, detail="missing collector token")
    identity = COLLECTOR_TOKENS.get(token.strip())
    if identity is None:
        raise HTTPException(status_code=401, detail="unknown collector token")
    if identity.region != expected_region:
        raise HTTPException(
            status_code=403,
            detail="collector token is not authorized for this region",
        )
    if identity.collector_id != expected_collector_id:
        raise HTTPException(
            status_code=403,
            detail="collector token is not authorized for this collector_id",
        )
    return identity


# -- demo tenant users + JWT ------------------------------------------------------

DEMO_USERS: Dict[str, TenantIdentity] = {
    "bank-a": TenantIdentity(tenant_id="bank-a", region="ap-south-1"),
    "hospital-b": TenantIdentity(tenant_id="hospital-b", region="eu-west-1"),
}


def authenticate_demo_user(username: str, password: str) -> TenantIdentity:
    identity = DEMO_USERS.get(username)
    if identity is None or password != _DEMO_PASSWORD:
        raise HTTPException(status_code=401, detail="invalid username or password")
    return identity


def issue_tenant_jwt(identity: TenantIdentity) -> str:
    now = int(time.time())
    claims = {
        "sub": identity.tenant_id,
        "tenant_id": identity.tenant_id,
        "region": identity.region,
        "iat": now,
        "exp": now + _JWT_EXP_MINUTES * 60,
    }
    return jwt.encode(claims, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def decode_tenant_jwt(token: str) -> TenantIdentity:
    try:
        claims = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    tenant_id = claims.get("tenant_id") or claims.get("sub")
    region = claims.get("region")
    if not tenant_id or not region:
        raise HTTPException(status_code=401, detail="token missing tenant claims")
    return TenantIdentity(tenant_id=str(tenant_id), region=str(region))


async def get_current_tenant(request: Request) -> TenantIdentity:
    """FastAPI dependency: tenant identity strictly from the Bearer JWT."""
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401, detail="missing Authorization: Bearer token"
        )
    return decode_tenant_jwt(token.strip())


def verify_ws_token(token: str, path_tenant_id: str) -> bool:
    """WebSocket handshake check: valid JWT whose tenant matches the path."""
    if not token:
        return False
    try:
        identity = decode_tenant_jwt(token)
    except HTTPException:
        return False
    return identity.tenant_id == path_tenant_id
