"""Android APK static analyzer.

Wraps ``androguard`` to extract package name, permissions, components,
certificates, and a heuristic risk score driven by sensitive
permissions and exported components.
"""

from __future__ import annotations

import hashlib
import io
import logging
from typing import Any

logger = logging.getLogger("detonate.services.apk_analyzer")


def is_apk(filename: str | None, mime: str | None, data: bytes | None = None) -> bool:
    if mime in {"application/vnd.android.package-archive"}:
        return True
    if filename and filename.lower().endswith(".apk"):
        return True
    if data and data.startswith(b"PK\x03\x04") and b"AndroidManifest.xml" in data[:65536]:
        return True
    return False


_DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


def analyze_apk(data: bytes, filename: str = "app.apk") -> dict[str, Any]:
    out: dict[str, Any] = {
        "filename": filename,
        "available": False,
        "package": "",
        "version_name": "",
        "version_code": 0,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "dangerous_permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
        "main_activity": "",
        "certificates": [],
        "warnings": [],
    }

    try:
        from androguard.core.apk import APK  # type: ignore
    except Exception:
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
        except Exception as exc:
            out["warnings"].append(f"androguard not installed: {exc}")
            return out

    try:
        apk = APK(io.BytesIO(data).read(), raw=True)  # type: ignore[arg-type]
    except Exception as exc:
        out["warnings"].append(f"APK parse failed: {exc}")
        return out

    out["available"] = True

    def _safe(getter, default=""):
        try:
            return getter() or default
        except Exception:
            return default

    out["package"] = _safe(apk.get_package, "")
    out["version_name"] = _safe(apk.get_androidversion_name, "")
    try:
        out["version_code"] = int(apk.get_androidversion_code() or 0)
    except Exception:
        out["version_code"] = 0
    try:
        out["min_sdk"] = int(apk.get_min_sdk_version() or 0)
    except Exception:
        pass
    try:
        out["target_sdk"] = int(apk.get_target_sdk_version() or 0)
    except Exception:
        pass

    perms = sorted(_safe(apk.get_permissions, []) or [])
    out["permissions"] = perms
    out["dangerous_permissions"] = [p for p in perms if p in _DANGEROUS_PERMISSIONS]

    out["activities"] = sorted(_safe(apk.get_activities, []) or [])
    out["services"] = sorted(_safe(apk.get_services, []) or [])
    out["receivers"] = sorted(_safe(apk.get_receivers, []) or [])
    out["providers"] = sorted(_safe(apk.get_providers, []) or [])
    out["main_activity"] = _safe(apk.get_main_activity, "")

    # Exported components
    exported: list[str] = []
    try:
        for comp_type in ("activity", "service", "receiver", "provider"):
            for comp in apk.find_tags(comp_type):
                name = apk.get_value_from_tag(comp, "name")
                exp = apk.get_value_from_tag(comp, "exported")
                if exp and exp.lower() == "true" and name:
                    exported.append(f"{comp_type}:{name}")
    except Exception:
        pass
    out["exported_components"] = sorted(set(exported))

    # Certificates
    try:
        certs_der = apk.get_certificates_der_v2() or apk.get_certificates_der_v3() or []
    except Exception:
        certs_der = []
    if not certs_der:
        try:
            certs_der = apk.get_certificates_der()
        except Exception:
            certs_der = []
    cert_list = []
    for der in certs_der or []:
        try:
            sha = hashlib.sha256(der).hexdigest()
            cert_list.append({"sha256": sha, "size": len(der)})
        except Exception:
            pass
    out["certificates"] = cert_list

    risk = 0
    risk += min(30, 6 * len(out["dangerous_permissions"]))
    risk += min(20, 4 * len(out["exported_components"]))
    if out.get("min_sdk") and out["min_sdk"] < 19:
        risk += 10
    if not cert_list:
        risk += 15
        out["warnings"].append("No signing certificate detected")
    out["risk_score"] = min(100, risk)
    return out
