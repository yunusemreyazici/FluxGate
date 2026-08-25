"""FluxGate-owned OpenVPN certificate authority and revocation state."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import ClassVar

from fluxgate.core.errors import ProviderError
from fluxgate.core.state import atomic_write
from fluxgate.providers.base import OperationContext


@dataclass(frozen=True, slots=True)
class PKICheckpoint:
    existed: bool
    files: dict[str, tuple[bytes, int]]


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    private_key: bytes
    certificate: bytes
    serial: str
    crl: bytes


class OpenVPNPKI:
    OWNER = b"Managed by FluxGate OpenVPN PKI\n"
    CRL_VALIDITY_DAYS = 825
    CRL_RENEWAL_WINDOW = timedelta(days=60)
    REQUIRED = (
        "OWNER",
        "openssl.cnf",
        "ca.key",
        "ca.crt",
        "server.key",
        "server.crt",
        "tls-crypt.key",
        "index.txt",
        "serial",
        "crlnumber",
        "crl.pem",
    )
    PRIVATE_FILES: ClassVar[frozenset[str]] = frozenset(
        {
            "OWNER",
            "openssl.cnf",
            "ca.key",
            "server.key",
            "tls-crypt.key",
            "index.txt",
            "serial",
            "crlnumber",
        }
    )

    def __init__(self, context: OperationContext) -> None:
        self.context = context
        self.root = context.paths.openvpn_pki_dir

    @property
    def ca_certificate_path(self) -> Path:
        return self.root / "ca.crt"

    @property
    def server_certificate_path(self) -> Path:
        return self.root / "server.crt"

    @property
    def server_key_path(self) -> Path:
        return self.root / "server.key"

    @property
    def tls_crypt_path(self) -> Path:
        return self.root / "tls-crypt.key"

    @property
    def crl_path(self) -> Path:
        return self.root / "crl.pem"

    def _config(self, root: Path) -> bytes:
        return (
            "# Managed by FluxGate.\n"
            "[ ca ]\n"
            "default_ca = CA_default\n\n"
            "[ CA_default ]\n"
            f"dir = {root}\n"
            "database = $dir/index.txt\n"
            "new_certs_dir = $dir/newcerts\n"
            "certificate = $dir/ca.crt\n"
            "private_key = $dir/ca.key\n"
            "serial = $dir/serial\n"
            "crlnumber = $dir/crlnumber\n"
            "default_md = sha256\n"
            "default_days = 825\n"
            "default_crl_days = 30\n"
            "policy = policy_fluxgate\n"
            "unique_subject = no\n"
            "copy_extensions = copy\n\n"
            "[ policy_fluxgate ]\n"
            "commonName = supplied\n\n"
            "[ server_cert ]\n"
            "basicConstraints = critical,CA:false\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer\n\n"
            "[ client_cert ]\n"
            "basicConstraints = critical,CA:false\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = clientAuth\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer\n"
        ).encode()

    def _assert_safe_root(self, *, allow_empty: bool = False) -> None:
        for parent in (self.root, *self.root.parents):
            if parent.is_symlink():
                raise ProviderError(f"refusing OpenVPN PKI symlink: {parent}")
        if not self.root.exists():
            return
        if not self.root.is_dir():
            raise ProviderError(f"OpenVPN PKI path is not a directory: {self.root}")
        entries = list(self.root.iterdir())
        marker = self.root / "OWNER"
        if entries and (not marker.is_file() or marker.read_bytes() != self.OWNER):
            raise ProviderError(f"refusing to overwrite unmanaged OpenVPN PKI: {self.root}")
        if entries or not allow_empty:
            for path in self.root.rglob("*"):
                if path.is_symlink():
                    raise ProviderError(f"refusing OpenVPN PKI symlink: {path}")
                if path.is_file() and not stat.S_ISREG(path.stat().st_mode):
                    raise ProviderError(f"unsafe OpenVPN PKI file: {path}")

    def checkpoint(self) -> PKICheckpoint:
        self._assert_safe_root(allow_empty=True)
        if not self.root.exists():
            return PKICheckpoint(existed=False, files={})
        files = {
            str(path.relative_to(self.root)): (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
            for path in self.root.rglob("*")
            if path.is_file()
        }
        return PKICheckpoint(existed=True, files=files)

    def assert_owned(self) -> None:
        self._assert_safe_root(allow_empty=True)

    def restore(self, checkpoint: PKICheckpoint) -> None:
        if not checkpoint.existed:
            if self.root.exists():
                self._assert_safe_root()
                shutil.rmtree(self.root)
            return
        self._assert_safe_root(allow_empty=True)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        expected = set(checkpoint.files)
        for path in sorted(self.root.rglob("*"), reverse=True):
            if path.is_file() and str(path.relative_to(self.root)) not in expected:
                path.unlink()
            elif path.is_dir() and not any(path.iterdir()):
                path.rmdir()
        for relative, (content, mode) in checkpoint.files.items():
            atomic_write(self.root / relative, content, mode)

    def _complete(self) -> bool:
        self._assert_safe_root(allow_empty=True)
        if not all((self.root / name).is_file() for name in self.REQUIRED):
            return False
        if not (self.root / "newcerts").is_dir():
            return False
        if (self.root / "OWNER").read_bytes() != self.OWNER:
            return False
        if (self.root / "openssl.cnf").read_bytes() != self._config(self.root):
            return False
        if stat.S_IMODE(self.root.stat().st_mode) & 0o077:
            return False
        if stat.S_IMODE((self.root / "newcerts").stat().st_mode) & 0o077:
            return False
        for name in self.PRIVATE_FILES:
            path = self.root / name
            if stat.S_IMODE(path.stat().st_mode) & 0o077:
                return False
        return True

    def complete(self) -> bool:
        try:
            return self._complete()
        except (OSError, ProviderError):
            return False

    def _run(self, args: list[str]) -> str:
        return self.context.runner.run(args, mutate=True, timeout=120.0).stdout

    def _generate_crl(self, root: Path) -> None:
        self._run(
            [
                "openssl",
                "ca",
                "-batch",
                "-config",
                str(root / "openssl.cnf"),
                "-gencrl",
                "-crldays",
                str(self.CRL_VALIDITY_DAYS),
                "-out",
                str(root / "crl.pem"),
            ]
        )

    def _initialize_stage(self, stage: Path) -> None:
        (stage / "newcerts").mkdir(mode=0o700)
        atomic_write(stage / "OWNER", self.OWNER, 0o600)
        atomic_write(stage / "openssl.cnf", self._config(stage), 0o600)
        atomic_write(stage / "index.txt", b"", 0o600)
        atomic_write(stage / "serial", b"1000\n", 0o600)
        atomic_write(stage / "crlnumber", b"1000\n", 0o600)
        self._run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
                "-out",
                str(stage / "ca.key"),
            ]
        )
        self._run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                str(stage / "ca.key"),
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/CN=FluxGate OpenVPN CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-out",
                str(stage / "ca.crt"),
            ]
        )
        self._run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
                "-out",
                str(stage / "server.key"),
            ]
        )
        self._run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(stage / "server.key"),
                "-subj",
                "/CN=fluxgate-server",
                "-out",
                str(stage / "server.csr"),
            ]
        )
        self._run(
            [
                "openssl",
                "ca",
                "-batch",
                "-config",
                str(stage / "openssl.cnf"),
                "-extensions",
                "server_cert",
                "-notext",
                "-in",
                str(stage / "server.csr"),
                "-out",
                str(stage / "server.crt"),
            ]
        )
        self._run(["openvpn", "--genkey", "secret", str(stage / "tls-crypt.key")])
        self._generate_crl(stage)
        for name in ("ca.key", "server.key", "tls-crypt.key"):
            os.chmod(stage / name, 0o600)

    def _commit_initial(self, stage: Path) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        (self.root / "newcerts").mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.root / "newcerts", 0o700)
        atomic_write(self.root / "OWNER", self.OWNER, 0o600)
        atomic_write(self.root / "openssl.cnf", self._config(self.root), 0o600)
        modes = {
            "ca.key": 0o600,
            "ca.crt": 0o644,
            "server.key": 0o600,
            "server.crt": 0o644,
            "tls-crypt.key": 0o600,
            "index.txt": 0o600,
            "serial": 0o600,
            "crlnumber": 0o600,
            "crl.pem": 0o644,
        }
        for name, mode in modes.items():
            atomic_write(self.root / name, (stage / name).read_bytes(), mode)
        for certificate in (stage / "newcerts").iterdir():
            if certificate.is_file():
                atomic_write(
                    self.root / "newcerts" / certificate.name,
                    certificate.read_bytes(),
                    0o644,
                )

    def ensure(self, *, has_clients: bool) -> bool:
        self._assert_safe_root(allow_empty=True)
        if self._complete():
            return False
        if self.root.exists() and any(self.root.iterdir()) and has_clients:
            raise ProviderError("OpenVPN PKI is incomplete while client credentials exist")
        checkpoint = self.checkpoint()
        self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with tempfile.TemporaryDirectory(
                prefix=".openvpn-pki.", dir=self.root.parent
            ) as temporary:
                stage = Path(temporary)
                self._initialize_stage(stage)
                self._commit_initial(stage)
        except BaseException as error:
            try:
                self.restore(checkpoint)
            except BaseException as rollback_error:
                raise ProviderError(
                    f"OpenVPN PKI initialization failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise
        return True

    def _copy_stage(self, stage: Path) -> None:
        if not self._complete():
            raise ProviderError("managed OpenVPN PKI is incomplete")
        shutil.copytree(self.root, stage, dirs_exist_ok=True)
        atomic_write(stage / "openssl.cnf", self._config(stage), 0o600)

    def _commit_database(self, stage: Path) -> None:
        # Publish the advanced serial before its index entry. An abrupt interruption can then
        # skip an unused serial, but cannot reuse a serial already present in the index.
        for name, mode in (
            ("serial", 0o600),
            ("index.txt", 0o600),
            ("crlnumber", 0o600),
            ("crl.pem", 0o644),
        ):
            atomic_write(self.root / name, (stage / name).read_bytes(), mode)
        for certificate in (stage / "newcerts").iterdir():
            destination = self.root / "newcerts" / certificate.name
            if certificate.is_file() and not destination.exists():
                atomic_write(destination, certificate.read_bytes(), 0o644)

    def issue_client(self, common_name: str) -> IssuedCertificate:
        if (
            not common_name.startswith("fluxgate-client-")
            or len(common_name) > 64
            or any(not (character.isalnum() or character == "-") for character in common_name)
        ):
            raise ProviderError("invalid OpenVPN client common name")
        checkpoint = self.checkpoint()
        self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with tempfile.TemporaryDirectory(
                prefix=".openvpn-client.", dir=self.root.parent
            ) as temporary:
                stage = Path(temporary)
                self._copy_stage(stage)
                key = stage / "client.key"
                request = stage / "client.csr"
                certificate = stage / "client.crt"
                self._run(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-pkeyopt",
                        "rsa_keygen_bits:3072",
                        "-out",
                        str(key),
                    ]
                )
                self._run(
                    [
                        "openssl",
                        "req",
                        "-new",
                        "-key",
                        str(key),
                        "-subj",
                        f"/CN={common_name}",
                        "-out",
                        str(request),
                    ]
                )
                self._run(
                    [
                        "openssl",
                        "ca",
                        "-batch",
                        "-config",
                        str(stage / "openssl.cnf"),
                        "-extensions",
                        "client_cert",
                        "-notext",
                        "-in",
                        str(request),
                        "-out",
                        str(certificate),
                    ]
                )
                serial_output = self._run(
                    ["openssl", "x509", "-in", str(certificate), "-noout", "-serial"]
                ).strip()
                if not serial_output.startswith("serial="):
                    raise ProviderError("OpenSSL did not return the client certificate serial")
                serial = serial_output.removeprefix("serial=")
                self._generate_crl(stage)
                os.chmod(key, 0o600)
                result = IssuedCertificate(
                    private_key=key.read_bytes(),
                    certificate=certificate.read_bytes(),
                    serial=serial,
                    crl=(stage / "crl.pem").read_bytes(),
                )
                self._commit_database(stage)
                return result
        except BaseException as error:
            try:
                self.restore(checkpoint)
            except BaseException as rollback_error:
                raise ProviderError(
                    f"OpenVPN client issuance failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise

    @staticmethod
    def _normalized_serial(serial: str) -> str:
        if not serial or any(character not in "0123456789ABCDEFabcdef" for character in serial):
            raise ProviderError("invalid OpenVPN certificate serial")
        return serial.lstrip("0").upper() or "0"

    def serial_revoked(self, serial: str) -> bool:
        expected = self._normalized_serial(serial)
        if not self._complete():
            raise ProviderError("managed OpenVPN PKI is incomplete")
        for line in (self.root / "index.txt").read_text().splitlines():
            fields = line.split("\t")
            if len(fields) >= 4 and self._normalized_serial(fields[3]) == expected:
                return fields[0] == "R"
        return False

    def refresh_crl(self) -> bytes:
        checkpoint = self.checkpoint()
        self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with tempfile.TemporaryDirectory(
                prefix=".openvpn-crl.", dir=self.root.parent
            ) as temporary:
                stage = Path(temporary)
                self._copy_stage(stage)
                self._generate_crl(stage)
                crl = (stage / "crl.pem").read_bytes()
                self._commit_database(stage)
                return crl
        except BaseException as error:
            try:
                self.restore(checkpoint)
            except BaseException as rollback_error:
                raise ProviderError(
                    f"OpenVPN CRL refresh failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise

    def revoke_client(self, certificate_path: Path, serial: str) -> bytes:
        if self.serial_revoked(serial):
            return self.refresh_crl()
        if certificate_path.is_symlink() or not certificate_path.is_file():
            raise ProviderError("OpenVPN client certificate is unavailable for revocation")
        checkpoint = self.checkpoint()
        self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with tempfile.TemporaryDirectory(
                prefix=".openvpn-revoke.", dir=self.root.parent
            ) as temporary:
                stage = Path(temporary)
                self._copy_stage(stage)
                certificate = stage / "revoked-client.crt"
                atomic_write(certificate, certificate_path.read_bytes(), 0o600)
                self._run(
                    [
                        "openssl",
                        "ca",
                        "-batch",
                        "-config",
                        str(stage / "openssl.cnf"),
                        "-revoke",
                        str(certificate),
                        "-crl_reason",
                        "cessationOfOperation",
                    ]
                )
                self._generate_crl(stage)
                crl = (stage / "crl.pem").read_bytes()
                self._commit_database(stage)
                return crl
        except BaseException as error:
            try:
                self.restore(checkpoint)
            except BaseException as rollback_error:
                raise ProviderError(
                    f"OpenVPN client revocation failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise

    def certificate_valid(self, path: Path) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        result = self.context.runner.run(
            ["openssl", "x509", "-checkend", "0", "-noout", "-in", str(path)],
            check=False,
        )
        return result.returncode == 0

    def crl_valid(self, path: Path, *, renewal_window: timedelta | None = None) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        result = self.context.runner.run(
            [
                "openssl",
                "crl",
                "-verify",
                "-CAfile",
                str(self.ca_certificate_path),
                "-nextupdate",
                "-noout",
                "-in",
                str(path),
            ],
            check=False,
        )
        if result.returncode != 0:
            return False
        line = next(
            (item for item in result.stdout.splitlines() if item.startswith("nextUpdate=")), None
        )
        if line is None:
            return False
        try:
            expires = parsedate_to_datetime(line.removeprefix("nextUpdate="))
        except (TypeError, ValueError, OverflowError):
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        minimum = datetime.now(timezone.utc) + (renewal_window or timedelta())
        return expires > minimum

    def _read(self, path: Path, *, private: bool) -> str:
        if path.is_symlink() or not path.is_file():
            raise ProviderError(f"OpenVPN PKI file is unavailable: {path}")
        if private and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ProviderError(f"OpenVPN private material has unsafe permissions: {path}")
        return path.read_text()

    def read_ca_certificate(self) -> str:
        return self._read(self.ca_certificate_path, private=False)

    def read_tls_crypt_key(self) -> str:
        return self._read(self.tls_crypt_path, private=True)
