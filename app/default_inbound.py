"""Single permanent Default Inbound management.

When ``DEFAULT_INBOUND`` is enabled in config, the whole panel is locked to a
single, permanent inbound (VLESS + Reality + XHTTP). This module owns:

* Generating the Reality keypair + short id (once, persisted in the DB so they
  survive restarts / rebuilds).
* The canonical inbound definition (port, target domain, reality settings).
* Restoring the inbound into ``xray_config.json`` on every boot / restart and
  ensuring it is present in the running Xray core.
* Forcing every user onto this inbound.

It deliberately adds no new services -- it reuses Marzban's own ``xray_config``,
``xray_api`` and ``crud`` plumbing.

IMPORTANT: the top-level imports here must stay light (only ``config``) to avoid
a circular import during ``app`` package initialization. Anything from ``app``
(logger, db, xray) is imported lazily inside the functions that need it.
"""

from __future__ import annotations

import json
import secrets
from typing import Optional

from config import (
    DEFAULT_INBOUND,
    DEFAULT_INBOUND_TYPE,
    DEFAULT_NETWORK,
    DEFAULT_SECURITY,
    TARGET_DOMAIN,
    XRAY_EXTERNAL_HOST,
    XRAY_EXTERNAL_PORT,
    XRAY_INTERNAL_PORT,
    XRAY_JSON,
    XRAY_REALITY_PRIVATE_KEY,
    XRAY_REALITY_PUBLIC_KEY,
    XRAY_REALITY_SHORT_ID,
)

DEFAULT_INBOUND_TAG = "DEFAULT"


# ---------------------------------------------------------------------------
# Pure helpers (no app imports) -- safe to import from anywhere.
# ---------------------------------------------------------------------------

def is_default_inbound_enabled() -> bool:
    return bool(DEFAULT_INBOUND)


def get_external_host() -> str:
    """Public host advertised to clients. Falls back to a placeholder."""
    return XRAY_EXTERNAL_HOST or "default.inbound.local"


def get_external_port() -> int:
    """Public port advertised to clients (the port they put in their client)."""
    if XRAY_EXTERNAL_PORT:
        return int(XRAY_EXTERNAL_PORT)
    # Railway / Docker: the internal listening port is what is published.
    return int(XRAY_INTERNAL_PORT)


def get_target_domain() -> str:
    if TARGET_DOMAIN:
        return TARGET_DOMAIN
    # Reality needs a real target to impersonate. Default to the external host.
    return get_external_host()


def default_inbound_tag() -> str:
    return DEFAULT_INBOUND_TAG


# ---------------------------------------------------------------------------
# Functions that touch the app / DB / xray core -- lazy imports.
# ---------------------------------------------------------------------------

def _random_short_id(length: int = 8) -> str:
    """Generate a hex short id of the given byte length (default 8 = 16 hex chars)."""
    return secrets.token_hex(length)


def _ensure_reality_keys(db) -> dict:
    """Return a dict with private_key, public_key, short_id, persisting them.

    Explicit env vars (XRAY_REALITY_*) take precedence and are written to the
    DB so they remain authoritative. Otherwise we load from the ``system`` row
    (``reality_settings`` JSON column) or generate + store fresh keys.
    """
    from app.xray import core as xray_core

    priv = XRAY_REALITY_PRIVATE_KEY
    pub = XRAY_REALITY_PUBLIC_KEY
    sid = XRAY_REALITY_SHORT_ID

    # Generate if private key is missing (public + short id follow).
    if not priv:
        try:
            keys = xray_core.core.get_x25519()
            if keys:
                priv = keys["private_key"]
                pub = keys["public_key"]
        except Exception as e:  # pragma: no cover - xray binary issues
            import logging
            logging.getLogger("uvicorn.error").warning(
                f"[default_inbound] x25519 generation failed: {e}"
            )

    if not sid:
        sid = _random_short_id()

    settings = {
        "private_key": priv or "",
        "public_key": pub or "",
        "short_id": sid,
    }

    # Persist into the system table so keys survive restarts / rebuilds.
    try:
        from app.db import crud
        crud.set_reality_settings(db, settings)
    except Exception as e:  # pragma: no cover
        import logging
        logging.getLogger("uvicorn.error").warning(
            f"[default_inbound] could not persist reality settings: {e}"
        )

    return settings


def build_default_inbound_dict(db=None) -> dict:
    """Build the inbound dict for the Xray config when DEFAULT_INBOUND is on."""
    if db is None:
        from app.db import GetDB
        with GetDB() as _db:
            keys = _ensure_reality_keys(_db)
    else:
        keys = _ensure_reality_keys(db)

    target = get_target_domain()

    return {
        "tag": DEFAULT_INBOUND_TAG,
        "listen": "0.0.0.0",
        "port": int(XRAY_INTERNAL_PORT),
        "protocol": DEFAULT_INBOUND_TYPE,
        "settings": {
            "clients": [],
            "decryption": "none",
            "encryption": "none",
        },
        "streamSettings": {
            "network": DEFAULT_NETWORK,
            "security": DEFAULT_SECURITY,
            "externalProxy": [],
            "realitySettings": {
                "show": False,
                "xver": 0,
                "target": f"{target}:443",
                "serverNames": [target],
                "privateKey": keys["private_key"],
                "shortIds": [keys["short_id"]],
                "spiderX": "/",
                "settings": {
                    "publicKey": keys["public_key"],
                    "fingerprint": "chrome",
                    "serverName": "",
                    "spiderX": "/",
                },
            },
            "xhttpSettings": {
                "path": "/",
                "host": "",
                "mode": "auto",
                "xPaddingBytes": "100-1000",
                "xPaddingObfsMode": False,
                "sessionPlacement": "",
                "sessionKey": "",
                "seqPlacement": "",
                "seqKey": "",
                "uplinkDataPlacement": "",
                "uplinkDataKey": "",
                "scMaxEachPostBytes": "1000000",
                "noSSEHeader": False,
                "scMaxBufferedPosts": 30,
                "scStreamUpServerSecs": "20-80",
                "serverMaxHeaderBytes": 0,
                "headers": {},
            },
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls"],
        },
    }


def apply_default_inbound_to_config(path: str = XRAY_JSON) -> dict:
    """Rewrite xray_config.json so it contains only the default inbound.

    Preserves log / routing / outbounds / policy from the existing file and
    replaces the inbounds list with the single DEFAULT inbound. Returns the
    resulting config dict.
    """
    from app.db import GetDB

    with GetDB() as db:
        inbound = build_default_inbound_dict(db)

    try:
        import commentjson
        with open(path, "r") as f:
            base = commentjson.loads(f.read())
    except (FileNotFoundError, ValueError):
        base = {}

    base.setdefault("log", {"loglevel": "warning"})
    base.setdefault("routing", {"rules": []})
    base.setdefault("outbounds", [
        {"protocol": "freedom", "tag": "DIRECT"},
        {"protocol": "blackhole", "tag": "BLOCK"},
    ])

    base["inbounds"] = [inbound]

    with open(path, "w") as f:
        json.dump(base, f, indent=4)

    return base


def ensure_default_inbound():
    """Idempotent bootstrap: make the running Xray config match the default inbound.

    Called on startup and from the health-check / restart paths.
    """
    import logging

    if not is_default_inbound_enabled():
        return

    logger = logging.getLogger("uvicorn.error")
    logger.info("[default_inbound] ensuring default inbound is present")

    config_dict = apply_default_inbound_to_config()

    # Rebuild the in-memory XRayConfig from the patched file so that
    # inbounds_by_tag / inbounds_by_protocol reflect the single inbound.
    from app.xray.config import XRayConfig
    from app import xray

    new_config = XRayConfig(config_dict, api_host="127.0.0.1", api_port=_current_api_port())

    xray.config = new_config

    # Make sure the DB has the inbound row + a default host for link generation.
    from app.db import GetDB, crud
    with GetDB() as db:
        crud.get_or_create_inbound(db, DEFAULT_INBOUND_TAG)
        keys = crud.get_reality_settings(db) or {}
        host_address = get_external_host()
        host_port = get_external_port()
        _ensure_default_host(db, host_address, host_port, keys)

    # Refresh the in-memory hosts cache so subscription link generation uses
    # the default inbound's host entry.
    try:
        xray.hosts.update()
    except Exception as e:  # pragma: no cover
        logger.warning(f"[default_inbound] hosts cache refresh failed: {e}")

    # Restart the core so the new config is live.
    try:
        startup = xray.config.include_db_users()
        xray.core.restart(startup)
    except Exception as e:  # pragma: no cover
        logger.warning(f"[default_inbound] core restart during ensure failed: {e}")


def _ensure_default_host(db, address: str, port: int, keys: dict):
    """Make sure the default inbound has exactly one host entry for link gen."""
    from app.db import crud
    from app.db.models import ProxyHost
    from app.models.proxy import ProxyHostSecurity, ProxyHostFingerprint

    inbound = crud.get_or_create_inbound(db, DEFAULT_INBOUND_TAG)
    if inbound.hosts:
        # Keep only one host and sync its address/port.
        keep = inbound.hosts[0]
        keep.address = address
        keep.port = port
        keep.sni = keys.get("serverNames") or get_target_domain()
        for stale in inbound.hosts[1:]:
            db.delete(stale)
        db.commit()
        return

    host = ProxyHost(
        remark="🚀 Default Reality XHTTP [{USERNAME}]",
        address=address,
        port=port,
        inbound=inbound,
        security=ProxyHostSecurity.inbound_default,
        alpn=ProxyHostSecurity.none,
        fingerprint=ProxyHostFingerprint.chrome,
    )
    db.add(host)
    db.commit()


def _current_api_port() -> int:
    from app import xray
    return getattr(xray.config, "api_port", 8080)
