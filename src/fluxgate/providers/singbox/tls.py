"""FluxGate-managed TLS CA and versioned server identities."""

from __future__ import annotations

import ipaddress
import json
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from fluxgate.core.errors import ProviderError
from fluxgate.core.state import atomic_write
from fluxgate.providers.base import OperationContext


@dataclass(frozen=True, slots=True)
class TLSIdentity:
    ca_certificate: Path
    certificate: Path
    private_key: Path


class ManagedTLSIdentityManager:
    OWNER = b"Managed by FluxGate sing-box TLS identity\n"

    def __init__(self, context: OperationContext) -> None:
        self.context = context
        self.root = context.paths.singbox_tls_dir

    @property
    def ca_key(self) -> Path:
        return self.root / "ca.key"

    @property
    def ca_certificate(self) -> Path:
        return self.root / "ca.pem"

    @property
    def current(self) -> Path:
        return self.root / "current.json"

    @property
    def marker(self) -> Path:
        return self.root / ".fluxgate-owner"

    def _run(self, args: list[str], *, input_text: str | None = None) -> bytes:
        result = self.context.runner.run(args, input_text=input_text, timeout=60.0, mutate=True)
        return result.stdout.encode()

    @staticmethod
    def _safe_regular(path: Path, private: bool = False) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        mode = stat.S_IMODE(path.stat().st_mode)
        return mode == (0o600 if private else 0o644)

    def _load_current(self) -> TLSIdentity | None:
        if self.root.is_symlink():
            return None
        if not self._safe_regular(self.current, private=True):
            return None
        try:
            raw = json.loads(self.current.read_text())
            if set(raw) != {"schema_version", "certificate", "private_key"}:
                return None
            certificate_relative = Path(raw["certificate"])
            private_key_relative = Path(raw["private_key"])
            if (
                certificate_relative.is_absolute()
                or private_key_relative.is_absolute()
                or ".." in certificate_relative.parts
                or ".." in private_key_relative.parts
            ):
                return None
            certificate = self.root / certificate_relative
            private_key = self.root / private_key_relative
            certificate.relative_to(self.root)
            private_key.relative_to(self.root)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return None
        return TLSIdentity(self.ca_certificate, certificate, private_key)

    def valid(self, identity: TLSIdentity, hostname: str, *, renewal_days: int = 30) -> bool:
        if not (
            self._safe_regular(self.ca_key, private=True)
            and self._safe_regular(identity.ca_certificate)
            and self._safe_regular(identity.certificate)
            and self._safe_regular(identity.private_key, private=True)
        ):
            return False
        if (
            self.context.runner.run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    str(identity.ca_certificate),
                    str(identity.certificate),
                ],
                check=False,
            ).returncode
            != 0
        ):
            return False
        check = self.context.runner.run(
            [
                "openssl",
                "x509",
                "-checkend",
                str(renewal_days * 86400),
                "-noout",
                "-in",
                str(identity.certificate),
            ],
            check=False,
        )
        if check.returncode != 0:
            return False
        host_flag = "-checkip" if _is_ip(hostname) else "-checkhost"
        return (
            self.context.runner.run(
                [
                    "openssl",
                    "x509",
                    "-noout",
                    host_flag,
                    hostname,
                    "-in",
                    str(identity.certificate),
                ],
                check=False,
            ).returncode
            == 0
        )

    def ensure(self, hostname: str) -> TLSIdentity:
        if not hostname:
            raise ProviderError("server.domain is required for managed sing-box TLS")
        if self.context.paths.secrets_dir.is_symlink() or self.root.is_symlink():
            raise ProviderError(f"refusing symlinked TLS identity directory: {self.root}")
        if (
            self.root.exists()
            and any(self.root.iterdir())
            and (
                self.marker.is_symlink()
                or not self.marker.is_file()
                or self.marker.read_bytes() != self.OWNER
            )
        ):
            raise ProviderError(f"refusing unmanaged TLS identity directory: {self.root}")
        self.context.paths.secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.context.paths.secrets_dir.chmod(0o700)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        atomic_write(self.marker, self.OWNER, 0o600)
        if self.ca_key.exists() and not self._safe_regular(self.ca_key, private=True):
            raise ProviderError("managed sing-box CA private key is unsafe")
        if self.ca_certificate.exists() and not self._safe_regular(self.ca_certificate):
            raise ProviderError("managed sing-box CA certificate is unsafe")
        if not self.ca_key.exists():
            key = self._run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"]
            )
            atomic_write(self.ca_key, key, 0o600)
        if not self.ca_certificate.exists():
            certificate = self._run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(self.ca_key),
                    "-sha256",
                    "-days",
                    "3650",
                    "-subj",
                    "/CN=FluxGate Managed CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ]
            )
            atomic_write(self.ca_certificate, certificate, 0o644)
        identity = self._load_current()
        if identity is not None and self.valid(identity, hostname):
            return identity
        generation = secrets.token_hex(8)
        directory = self.root / "server" / generation
        directory.mkdir(parents=True, mode=0o700)
        key_path = directory / "key.pem"
        certificate_path = directory / "cert.pem"
        key = self._run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"]
        )
        atomic_write(key_path, key, 0o600)
        san = f"IP:{hostname}" if _is_ip(hostname) else f"DNS:{hostname}"
        csr = self._run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(key_path),
                "-subj",
                f"/CN={hostname}",
                "-addext",
                f"subjectAltName={san}",
            ]
        )
        certificate = self._run(
            [
                "openssl",
                "x509",
                "-req",
                "-CA",
                str(self.ca_certificate),
                "-CAkey",
                str(self.ca_key),
                "-set_serial",
                f"0x{secrets.token_hex(16)}",
                "-days",
                "397",
                "-sha256",
                "-copy_extensions",
                "copy",
            ],
            input_text=csr.decode(),
        )
        atomic_write(certificate_path, certificate, 0o644)
        marker = {
            "schema_version": 1,
            "certificate": str(certificate_path.relative_to(self.root)),
            "private_key": str(key_path.relative_to(self.root)),
        }
        atomic_write(self.current, (json.dumps(marker, sort_keys=True) + "\n").encode(), 0o600)
        return TLSIdentity(self.ca_certificate, certificate_path, key_path)


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True
