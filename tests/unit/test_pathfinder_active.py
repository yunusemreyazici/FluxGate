from __future__ import annotations

import errno
import ipaddress
import json
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import ValidationError
from typer.testing import CliRunner

import fluxgate.cli.pathfinder as pathfinder_cli
from fluxgate.cli.app import app
from fluxgate.core.config import (
    AppConfig,
    PathfinderConfig,
    PathfinderFailoverConfig,
    PathfinderProbeConfig,
    load_config,
)
from fluxgate.core.errors import PathfinderAuthorizationError, PathfinderError
from fluxgate.core.manifest import ManifestServer, ServerManifest, build_manifest
from fluxgate.core.models import Client, FluxGateState
from fluxgate.identity import ServerIdentityManager
from fluxgate.pathfinder.active import ActivePathfinder
from fluxgate.pathfinder.active_models import (
    ActivePathfinderReport,
    AuthorizationSource,
    CandidateScore,
    FailoverAction,
    FailoverContext,
    ProbeAttempt,
    ProbeObservation,
    ProbeOutcome,
    ProbePlan,
    ProbeStep,
    ScoreComponent,
    VerificationState,
)
from fluxgate.pathfinder.authorization import authorize_manifest
from fluxgate.pathfinder.failover import decide_failover
from fluxgate.pathfinder.models import (
    CandidateAssessment,
    ClientCapabilities,
    ConnectionCandidate,
    ConnectionMode,
    FeatureCapability,
    IPFamily,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
)
from fluxgate.pathfinder.probing import SocketProbeExecutor, build_probe_plan
from fluxgate.pathfinder.scoring import ScoringPolicy, score_candidate
from fluxgate.pathfinder.selection import rank_candidates, select_candidate


def candidate(
    candidate_id: str,
    *,
    endpoint: str = "localhost",
    port: int = 443,
    transport: PathfinderTransport = PathfinderTransport.TCP,
    security: PathfinderSecurity = PathfinderSecurity.TLS,
    socket_protocol: str = "tcp",
    provider: PathfinderProvider = PathfinderProvider.SINGBOX,
    protocol: PathfinderProtocol = PathfinderProtocol.VLESS,
    connection_mode: ConnectionMode = ConnectionMode.LOCAL_PROXY,
    ip_families: tuple[IPFamily, ...] = (IPFamily.IPV4,),
    required_features: tuple[FeatureCapability, ...] = (),
) -> ConnectionCandidate:
    return ConnectionCandidate.model_validate(
        {
            "candidate_id": candidate_id,
            "provider": provider,
            "protocol": protocol,
            "transport": transport,
            "security": security,
            "connection_mode": connection_mode,
            "endpoint": endpoint,
            "port": port,
            "socket_protocol": socket_protocol,
            "ip_families": ip_families,
            "required_features": required_features,
        }
    )


def capabilities() -> ClientCapabilities:
    return ClientCapabilities(
        supported_providers=(PathfinderProvider.SINGBOX,),
        supported_protocols=(PathfinderProtocol.VLESS,),
        supported_transports=(PathfinderTransport.TCP, PathfinderTransport.UDP),
        supported_security=(PathfinderSecurity.TLS, PathfinderSecurity.WIREGUARD),
        supported_connection_modes=(ConnectionMode.LOCAL_PROXY,),
        supported_ip_families=(IPFamily.IPV4,),
    )


def full_capabilities() -> ClientCapabilities:
    return ClientCapabilities(
        supported_providers=tuple(PathfinderProvider),
        supported_protocols=tuple(PathfinderProtocol),
        supported_transports=tuple(PathfinderTransport),
        supported_security=tuple(PathfinderSecurity),
        supported_connection_modes=tuple(ConnectionMode),
        supported_ip_families=(IPFamily.IPV4, IPFamily.IPV6),
        supported_features=tuple(FeatureCapability),
    )


def udp_candidates() -> tuple[ConnectionCandidate, ...]:
    return (
        candidate(
            "provider:wireguard",
            provider=PathfinderProvider.WIREGUARD,
            protocol=PathfinderProtocol.WIREGUARD,
            transport=PathfinderTransport.UDP,
            security=PathfinderSecurity.WIREGUARD,
            socket_protocol="udp",
            connection_mode=ConnectionMode.SYSTEM_TUNNEL,
            required_features=(FeatureCapability.UDP,),
        ),
        candidate(
            "provider:amneziawg",
            provider=PathfinderProvider.AMNEZIAWG,
            protocol=PathfinderProtocol.AMNEZIAWG,
            transport=PathfinderTransport.UDP,
            security=PathfinderSecurity.WIREGUARD,
            socket_protocol="udp",
            connection_mode=ConnectionMode.SYSTEM_TUNNEL,
            required_features=(FeatureCapability.UDP, FeatureCapability.AMNEZIAWG_3_1),
        ),
        candidate(
            "provider:openvpn",
            provider=PathfinderProvider.OPENVPN,
            protocol=PathfinderProtocol.OPENVPN,
            transport=PathfinderTransport.UDP,
            security=PathfinderSecurity.TLS,
            socket_protocol="udp",
            connection_mode=ConnectionMode.SYSTEM_TUNNEL,
            required_features=(FeatureCapability.UDP,),
        ),
        candidate(
            "profile:hysteria2",
            provider=PathfinderProvider.SINGBOX,
            protocol=PathfinderProtocol.HYSTERIA2,
            transport=PathfinderTransport.QUIC,
            security=PathfinderSecurity.TLS,
            socket_protocol="udp",
            required_features=(FeatureCapability.UDP, FeatureCapability.QUIC),
        ),
    )


def inventory(
    *items: ConnectionCandidate,
    authorized_addresses: tuple[str, ...] = ("127.0.0.1", "::1"),
):
    manifest = ServerManifest(server=ManifestServer(identity="localhost"), candidates=tuple(items))
    return authorize_manifest(
        manifest,
        source=AuthorizationSource.LOCAL_STATE,
        trusted_addresses=authorized_addresses,
    )


def attempt(
    outcome: ProbeOutcome,
    *,
    latency: float = 10.0,
    attempt_number: int = 1,
) -> ProbeAttempt:
    success = outcome == ProbeOutcome.SUCCESS
    return ProbeAttempt(
        attempt=attempt_number,
        outcome=outcome,
        verification=VerificationState.VERIFIED if success else VerificationState.FAILED,
        dns_succeeded=outcome not in {ProbeOutcome.DNS_FAILURE, ProbeOutcome.TIMEOUT},
        tcp_connected=success,
        tls_verified=success,
        total_latency_ms=latency,
        summary=outcome.value,
    )


def observation(candidate_id: str, value: ProbeAttempt) -> ProbeObservation:
    return ProbeObservation(
        candidate_id=candidate_id,
        outcome=value.outcome,
        verification=value.verification,
        attempts=(value,),
        summary=value.summary,
    )


def scored_candidate(
    candidate_id: str,
    points: int,
    outcome: ProbeOutcome = ProbeOutcome.SUCCESS,
) -> CandidateScore:
    value = attempt(outcome)
    return CandidateScore(
        candidate_id=candidate_id,
        compatible=True,
        eligible=outcome == ProbeOutcome.SUCCESS,
        score=points,
        components=(ScoreComponent(name="controlled", points=points, reason="controlled score"),),
        observation=observation(candidate_id, value),
    )


def active_report(*scores: CandidateScore) -> ActivePathfinderReport:
    ranked = rank_candidates(tuple(scores))
    return ActivePathfinderReport(
        assessments=tuple(
            CandidateAssessment(
                candidate_id=item.candidate_id,
                compatible=True,
                required_capabilities=(),
            )
            for item in scores
        ),
        observations=tuple(item.observation for item in scores),
        ranked_candidates=ranked,
        selection=select_candidate(ranked),
    )


def test_probe_authorization_accepts_owned_inventory_and_rejects_third_party_targets() -> None:
    owned = candidate("owned")
    assert inventory(owned).candidates == (owned,)

    third_party = candidate("third-party", endpoint="example.net")
    manifest = ServerManifest(
        server=ManifestServer(identity="vpn.example.test"), candidates=(third_party,)
    )
    with pytest.raises(PathfinderAuthorizationError, match="unauthorized endpoint"):
        authorize_manifest(manifest, source=AuthorizationSource.LOCAL_STATE)


def test_empty_local_inventory_is_safe_and_reports_no_viable_candidate() -> None:
    authorized = authorize_manifest(
        ServerManifest(server=ManifestServer(identity="")),
        source=AuthorizationSource.LOCAL_STATE,
    )
    report = ActivePathfinder().probe(
        authorized,
        full_capabilities(),
        PathfinderProbeConfig(),
    )
    assert report.observations == ()
    assert report.ranked_candidates == ()
    assert report.selection.selected_candidate_id is None
    assert report.selection.alternatives == ()
    decision = decide_failover(report, FailoverContext(), PathfinderFailoverConfig())
    assert decision.action == FailoverAction.NO_VIABLE_CANDIDATE


def test_signed_inventory_requires_pinned_server_binding_and_valid_targets() -> None:
    server_id = uuid4()
    manifest = ServerManifest(
        server=ManifestServer(identity="vpn.example.test", server_id=server_id),
        candidates=(candidate("owned", endpoint="vpn.example.test"),),
    )
    authorized = authorize_manifest(
        manifest,
        source=AuthorizationSource.SIGNED_MANIFEST,
        trusted_server_id=server_id,
        trusted_endpoint="vpn.example.test",
        trusted_addresses=("192.0.2.10",),
    )
    assert authorized.server_id == server_id
    assert authorized.authorized_addresses == ("192.0.2.10",)
    with pytest.raises(PathfinderAuthorizationError, match="pinned server trust"):
        authorize_manifest(
            manifest,
            source=AuthorizationSource.SIGNED_MANIFEST,
            trusted_server_id=uuid4(),
            trusted_endpoint="vpn.example.test",
            trusted_addresses=("192.0.2.10",),
        )

    with pytest.raises(PathfinderAuthorizationError, match="independently pinned"):
        authorize_manifest(
            manifest,
            source=AuthorizationSource.SIGNED_MANIFEST,
            trusted_server_id=server_id,
        )
    with pytest.raises(PathfinderAuthorizationError, match="does not match"):
        authorize_manifest(
            manifest,
            source=AuthorizationSource.SIGNED_MANIFEST,
            trusted_server_id=server_id,
            trusted_endpoint="other.example.test",
            trusted_addresses=("192.0.2.10",),
        )
    with pytest.raises(PathfinderAuthorizationError, match="requires an independently pinned"):
        authorize_manifest(
            manifest,
            source=AuthorizationSource.SIGNED_MANIFEST,
            trusted_server_id=server_id,
            trusted_endpoint="vpn.example.test",
        )


@pytest.mark.parametrize("endpoint", ["https://example.com", "bad host", "host/path", "\n"])
def test_authorization_rejects_malformed_endpoints(endpoint: str) -> None:
    manifest = ServerManifest(
        server=ManifestServer(identity=endpoint),
        candidates=(),
    )
    with pytest.raises(PathfinderAuthorizationError, match="malformed"):
        authorize_manifest(manifest, source=AuthorizationSource.LOCAL_STATE)


def test_candidate_model_rejects_invalid_ports_before_authorization() -> None:
    payload = candidate("valid").model_dump()
    for port in (0, 65536):
        payload["port"] = port
        with pytest.raises(ValidationError):
            ConnectionCandidate.model_validate(payload)


def test_authorization_rejects_inconsistent_capabilities_and_bounds_inventory() -> None:
    inconsistent = candidate(
        "inconsistent",
        socket_protocol="udp",
    )
    with pytest.raises(PathfinderAuthorizationError, match="inconsistent transport"):
        inventory(inconsistent)

    mislabeled_wireguard = candidate(
        "mislabeled-wireguard",
        provider=PathfinderProvider.WIREGUARD,
        protocol=PathfinderProtocol.WIREGUARD,
    )
    with pytest.raises(PathfinderAuthorizationError, match="unauthorized capability shape"):
        inventory(mislabeled_wireguard)

    no_family = candidate("no-family", ip_families=())
    with pytest.raises(PathfinderAuthorizationError, match="no authorized IP family"):
        inventory(no_family)

    too_many = tuple(candidate(f"candidate-{index}") for index in range(65))
    with pytest.raises(PathfinderAuthorizationError, match="at most 64"):
        inventory(*too_many)


def test_authorization_enforces_literal_ip_family_for_ipv4_and_ipv6() -> None:
    ipv4 = candidate("ipv4", endpoint="127.0.0.1", ip_families=(IPFamily.IPV4,))
    authorized_ipv4 = authorize_manifest(
        ServerManifest(server=ManifestServer(identity="127.0.0.1"), candidates=(ipv4,)),
        source=AuthorizationSource.LOCAL_STATE,
    )
    assert authorized_ipv4.candidates == (ipv4,)
    assert authorized_ipv4.authorized_addresses == ("127.0.0.1",)

    ipv6 = candidate("ipv6", endpoint="::1", ip_families=(IPFamily.IPV6,))
    authorized_ipv6 = authorize_manifest(
        ServerManifest(server=ManifestServer(identity="::1"), candidates=(ipv6,)),
        source=AuthorizationSource.LOCAL_STATE,
    )
    assert authorized_ipv6.candidates == (ipv6,)
    assert authorized_ipv6.authorized_addresses == ("::1",)

    with pytest.raises(PathfinderAuthorizationError, match="only its own address"):
        authorize_manifest(
            ServerManifest(server=ManifestServer(identity="127.0.0.1"), candidates=(ipv4,)),
            source=AuthorizationSource.LOCAL_STATE,
            trusted_addresses=("10.0.0.1",),
        )

    mismatched = ipv6.model_copy(update={"ip_families": (IPFamily.IPV4,)})
    with pytest.raises(PathfinderAuthorizationError, match="excludes its literal"):
        authorize_manifest(
            ServerManifest(
                server=ManifestServer(identity="::1"),
                candidates=(mismatched,),
            ),
            source=AuthorizationSource.LOCAL_STATE,
        )


def test_probe_planning_is_capability_driven_and_udp_is_conservative() -> None:
    tls = build_probe_plan(candidate("tls"), authorized_addresses=("127.0.0.1",))
    assert tls.steps == (ProbeStep.DNS, ProbeStep.TCP_CONNECT, ProbeStep.TLS_HANDSHAKE)
    udp = build_probe_plan(
        candidate(
            "udp",
            transport=PathfinderTransport.UDP,
            security=PathfinderSecurity.WIREGUARD,
            socket_protocol="udp",
        ),
        authorized_addresses=("127.0.0.1",),
    )
    assert udp.steps == (ProbeStep.DNS,)
    result = SocketProbeExecutor().execute(
        udp,
        attempt=1,
        connect_timeout=0.2,
        candidate_timeout=0.5,
        tls_ca_file=None,
    )
    assert result.outcome == ProbeOutcome.PROBE_UNSUPPORTED
    assert result.verification == VerificationState.UNVERIFIED
    assert result.dns_succeeded is True

    with pytest.raises(ValidationError, match="supported DNS/TCP/TLS sequence"):
        ProbePlan(
            candidate_id="misordered",
            endpoint="localhost",
            port=443,
            ip_families=(IPFamily.IPV4,),
            steps=(ProbeStep.DNS, ProbeStep.TLS_HANDSHAKE, ProbeStep.TCP_CONNECT),
            tls_server_name="localhost",
        )


def test_udp_only_inventory_is_ranked_but_not_selected_or_called_nonviable() -> None:
    items = udp_candidates()
    report = ActivePathfinder().probe(
        inventory(*items),
        full_capabilities(),
        PathfinderProbeConfig(max_parallel_probes=4),
    )
    assert all(item.outcome == ProbeOutcome.PROBE_UNSUPPORTED for item in report.observations)
    assert all(item.compatible and not item.eligible for item in report.ranked_candidates)
    assert report.selection.selected_candidate_id is None
    assert set(report.selection.alternatives) == {item.candidate_id for item in items}
    assert "4 compatible candidate(s) remain unverified" in report.selection.reason

    decision = decide_failover(report, FailoverContext(), PathfinderFailoverConfig())
    assert decision.action == FailoverAction.NO_VERIFIED_CANDIDATE
    assert decision.target_candidate_id is None


def test_mixed_tcp_udp_inventory_selects_verified_tcp_and_preserves_udp_alternatives() -> None:
    class SemanticExecutor:
        def __init__(self) -> None:
            self.plans: list[ProbePlan] = []

        def execute(self, plan, **kwargs) -> ProbeAttempt:
            self.plans.append(plan)
            if ProbeStep.TCP_CONNECT in plan.steps:
                return attempt(ProbeOutcome.SUCCESS, attempt_number=kwargs["attempt"])
            return ProbeAttempt(
                attempt=kwargs["attempt"],
                outcome=ProbeOutcome.PROBE_UNSUPPORTED,
                verification=VerificationState.UNVERIFIED,
                dns_succeeded=True,
                summary="no generic UDP application probe",
            )

    tcp = candidate("profile:tcp")
    udp = udp_candidates()
    executor = SemanticExecutor()
    report = ActivePathfinder(executor).probe(
        inventory(tcp, *udp),
        full_capabilities(),
        PathfinderProbeConfig(max_parallel_probes=4),
    )
    assert report.selection.selected_candidate_id == tcp.candidate_id
    assert set(report.selection.alternatives) == {item.candidate_id for item in udp}
    by_id = {item.candidate_id: item for item in report.ranked_candidates}
    assert by_id[tcp.candidate_id].eligible
    assert all(not by_id[item.candidate_id].eligible for item in udp)
    assert all(plan.authorized_addresses == ("127.0.0.1", "::1") for plan in executor.plans)


@contextmanager
def tcp_server(
    *,
    tls_context: ssl.SSLContext | None = None,
    delay: float = 0.0,
    family: socket.AddressFamily = socket.AF_INET,
):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    except OSError:
        listener.close()
        pytest.skip("sandbox or platform does not permit the isolated localhost listener")
    listener.listen(5)
    listener.settimeout(1.0)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                if delay:
                    time.sleep(delay)
                if tls_context is not None:
                    with tls_context.wrap_socket(connection, server_side=True):
                        pass
        except (OSError, ssl.SSLError):
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        listener.close()
        thread.join(timeout=1.0)


def make_tls_identity(root: Path, hostname: str = "localhost") -> tuple[Path, Path, Path]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pathfinder Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    try:
        subject_alt_name: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        subject_alt_name = x509.DNSName(hostname)
    server = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([subject_alt_name]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = root / "ca.crt", root / "server.crt", root / "server.key"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def test_explicitly_authorized_private_tcp_connect_success_and_refusal() -> None:
    executor = SocketProbeExecutor()
    with tcp_server() as port:
        plan = ProbePlan(
            candidate_id="tcp",
            endpoint="127.0.0.1",
            port=port,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("127.0.0.1",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        )
        succeeded = executor.execute(
            plan,
            attempt=1,
            connect_timeout=0.5,
            candidate_timeout=1.0,
            tls_ca_file=None,
        )
    assert succeeded.outcome == ProbeOutcome.SUCCESS
    assert succeeded.tcp_connected is True

    closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    refused = executor.execute(
        plan.model_copy(update={"port": closed_port}),
        attempt=1,
        connect_timeout=0.2,
        candidate_timeout=0.5,
        tls_ca_file=None,
    )
    assert refused.outcome == ProbeOutcome.CONNECTION_REFUSED

    with tcp_server(family=socket.AF_INET6) as ipv6_port:
        ipv6 = executor.execute(
            ProbePlan(
                candidate_id="tcp-v6",
                endpoint="::1",
                port=ipv6_port,
                ip_families=(IPFamily.IPV6,),
                authorized_addresses=("::1",),
                steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
            ),
            attempt=1,
            connect_timeout=0.5,
            candidate_timeout=1.0,
            tls_ca_file=None,
        )
    assert ipv6.outcome == ProbeOutcome.SUCCESS
    assert ipv6.tcp_connected is True


def test_socket_probe_reports_dns_failure_and_tcp_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = ProbePlan(
        candidate_id="tcp",
        endpoint="localhost",
        port=443,
        ip_families=(IPFamily.IPV4,),
        authorized_addresses=("127.0.0.1",),
        steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
    )

    def fail_resolution(*args, **kwargs):
        raise socket.gaierror("controlled DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)
    failed_dns = SocketProbeExecutor().execute(
        plan,
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert failed_dns.outcome == ProbeOutcome.DNS_FAILURE

    resolver_baseline = sum(
        thread.name == "fluxgate-pathfinder-resolver" for thread in threading.enumerate()
    )
    release_resolution = threading.Event()

    def stall_resolution(*args, **kwargs):
        release_resolution.wait(timeout=1.0)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", stall_resolution)
    started = time.monotonic()
    timed_out_dns = SocketProbeExecutor().execute(
        plan,
        attempt=1,
        connect_timeout=0.02,
        candidate_timeout=0.02,
        tls_ca_file=None,
    )
    release_resolution.set()
    resolver_deadline = time.monotonic() + 1.0
    while (
        sum(thread.name == "fluxgate-pathfinder-resolver" for thread in threading.enumerate())
        > resolver_baseline
        and time.monotonic() < resolver_deadline
    ):
        time.sleep(0.01)
    assert time.monotonic() - started < 0.1
    assert timed_out_dns.outcome == ProbeOutcome.TIMEOUT
    assert timed_out_dns.dns_succeeded is False

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        ],
    )

    class TimedOutSocket:
        def settimeout(self, value: float) -> None:
            assert 0 < value <= 0.1

        def connect(self, address) -> None:
            raise TimeoutError("controlled timeout")

        def close(self) -> None:
            pass

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: TimedOutSocket())
    timed_out = SocketProbeExecutor().execute(
        plan,
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert timed_out.outcome == ProbeOutcome.TIMEOUT


def test_dns_timeout_workers_are_globally_bounded_and_capacity_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()

    def blocked_resolution(*args, **kwargs):
        release.wait(timeout=2.0)
        return []

    baseline = sum(
        thread.name == "fluxgate-pathfinder-resolver" for thread in threading.enumerate()
    )
    monkeypatch.setattr(socket, "getaddrinfo", blocked_resolution)
    plan = ProbePlan(
        candidate_id="dns-stress",
        endpoint="localhost",
        port=443,
        ip_families=(IPFamily.IPV4,),
        authorized_addresses=("127.0.0.1",),
        steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
    )
    outcomes = [
        SocketProbeExecutor()
        .execute(
            plan,
            attempt=1,
            connect_timeout=0.001,
            candidate_timeout=0.001,
            tls_ca_file=None,
        )
        .outcome
        for _ in range(40)
    ]
    active = sum(thread.name == "fluxgate-pathfinder-resolver" for thread in threading.enumerate())
    assert set(outcomes) == {ProbeOutcome.TIMEOUT}
    assert active - baseline <= 32

    release.set()
    deadline = time.monotonic() + 1.0
    while (
        sum(thread.name == "fluxgate-pathfinder-resolver" for thread in threading.enumerate())
        > baseline
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert (
        sum(thread.name == "fluxgate-pathfinder-resolver" for thread in threading.enumerate())
        == baseline
    )

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror("controlled")),
    )
    assert (
        SocketProbeExecutor()
        .execute(
            plan,
            attempt=1,
            connect_timeout=0.1,
            candidate_timeout=0.1,
            tls_ca_file=None,
        )
        .outcome
        == ProbeOutcome.DNS_FAILURE
    )


def test_socket_probe_uses_only_authorized_address_families_and_closes_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 443, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
        ],
    )

    class RecordingSocket:
        def __init__(self) -> None:
            self.address = None
            self.closed = False

        def settimeout(self, value: float) -> None:
            pass

        def connect(self, address) -> None:
            self.address = address

        def close(self) -> None:
            self.closed = True

    created: list[RecordingSocket] = []

    def create_socket(*args, **kwargs):
        value = RecordingSocket()
        created.append(value)
        return value

    monkeypatch.setattr(socket, "socket", create_socket)
    result = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="ipv4-only",
            endpoint="server.example",
            port=443,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("127.0.0.1",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert result.outcome == ProbeOutcome.SUCCESS
    assert len(created) == 1
    assert created[0].address == ("127.0.0.1", 443)
    assert created[0].closed


def test_hostname_resolution_cannot_redirect_probe_to_unauthorized_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("169.254.169.254", 443),
            )
        ],
    )
    connect_calls = 0

    def forbidden_socket(*args, **kwargs):
        nonlocal connect_calls
        connect_calls += 1
        raise AssertionError("socket creation must occur only after destination authorization")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    result = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="ssrf-regression",
            endpoint="vpn.example.test",
            port=443,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("203.0.113.10",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert result.outcome == ProbeOutcome.DESTINATION_UNAUTHORIZED
    assert result.dns_succeeded is True
    assert result.tcp_connected is False
    assert connect_calls == 0
    assert "169.254.169.254" not in result.summary


def test_resolver_cannot_redirect_authorized_ip_to_another_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", 80))
        ],
    )
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("resolver-controlled port reached socket creation")
        ),
    )
    result = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="port-binding",
            endpoint="vpn.example.test",
            port=443,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("203.0.113.10",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert result.outcome == ProbeOutcome.DESTINATION_UNAUTHORIZED


@pytest.mark.parametrize(
    ("family", "resolved"),
    [
        (socket.AF_INET, "127.0.0.1"),
        (socket.AF_INET, "10.0.0.1"),
        (socket.AF_INET, "169.254.169.254"),
        (socket.AF_INET6, "::1"),
        (socket.AF_INET6, "fe80::1"),
    ],
)
def test_unpinned_private_and_special_addresses_are_rejected_before_socket_creation(
    monkeypatch: pytest.MonkeyPatch,
    family: socket.AddressFamily,
    resolved: str,
) -> None:
    socket_address = (resolved, 443) if family == socket.AF_INET else (resolved, 443, 0, 0)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", socket_address)
        ],
    )
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unauthorized destination reached socket creation")
        ),
    )
    result = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="special-address",
            endpoint="vpn.example.test",
            port=443,
            ip_families=(IPFamily.IPV4, IPFamily.IPV6),
            authorized_addresses=("192.0.2.10", "2001:db8::10"),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert result.outcome == ProbeOutcome.DESTINATION_UNAUTHORIZED


def test_mixed_dns_answers_use_only_deterministic_authorized_concrete_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.20", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", 443)),
        ],
    )

    class RecordingSocket:
        def __init__(self) -> None:
            self.connected: tuple[str, int] | None = None
            self.closed = False

        def settimeout(self, value: float) -> None:
            pass

        def connect(self, address: tuple[str, int]) -> None:
            self.connected = address

        def close(self) -> None:
            self.closed = True

    created: list[RecordingSocket] = []

    def recording_socket(*args, **kwargs):
        item = RecordingSocket()
        created.append(item)
        return item

    monkeypatch.setattr(socket, "socket", recording_socket)
    result = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="mixed",
            endpoint="vpn.example.test",
            port=443,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("203.0.113.20", "203.0.113.10"),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert result.outcome == ProbeOutcome.SUCCESS
    assert len(created) == 1
    assert created[0].connected == ("203.0.113.10", 443)
    assert created[0].closed


def test_authorized_ipv6_is_concrete_and_family_mismatch_never_connects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 443, 0, 0))
        ],
    )
    connected: list[tuple[str, int, int, int]] = []

    class IPv6Socket:
        def settimeout(self, value: float) -> None:
            pass

        def connect(self, address: tuple[str, int, int, int]) -> None:
            connected.append(address)

        def close(self) -> None:
            pass

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: IPv6Socket())
    authorized = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="ipv6-authorized",
            endpoint="vpn.example.test",
            port=443,
            ip_families=(IPFamily.IPV6,),
            authorized_addresses=("::1",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert authorized.outcome == ProbeOutcome.SUCCESS
    assert connected == [("::1", 443, 0, 0)]

    connected.clear()
    family_mismatch = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="ipv6-family-mismatch",
            endpoint="vpn.example.test",
            port=443,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("::1",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert family_mismatch.outcome == ProbeOutcome.DESTINATION_UNAUTHORIZED
    assert connected == []


def test_local_hostname_without_address_pin_fails_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        ],
    )
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("local hostname without a pin reached socket creation")
        ),
    )
    report = ActivePathfinder().probe(
        inventory(candidate("local-unpinned"), authorized_addresses=()),
        capabilities(),
        PathfinderProbeConfig(max_parallel_probes=1),
    )
    assert report.observations[0].outcome == ProbeOutcome.DESTINATION_UNAUTHORIZED
    assert report.selection.selected_candidate_id is None


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), ProbeOutcome.CONNECTION_REFUSED),
        (TimeoutError("timeout"), ProbeOutcome.TIMEOUT),
        (OSError(errno.ENETUNREACH, "unreachable"), ProbeOutcome.NETWORK_UNREACHABLE),
        (OSError(errno.EHOSTUNREACH, "unreachable"), ProbeOutcome.NETWORK_UNREACHABLE),
        (OSError(errno.ECONNRESET, "reset"), ProbeOutcome.CONNECT_FAILURE),
    ],
)
def test_tcp_error_classification_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    error: OSError,
    expected: ProbeOutcome,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        ],
    )

    class FailedSocket:
        closed = False

        def settimeout(self, value: float) -> None:
            pass

        def connect(self, address) -> None:
            raise error

        def close(self) -> None:
            self.closed = True

    failed = FailedSocket()
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: failed)
    result = SocketProbeExecutor().execute(
        ProbePlan(
            candidate_id="failed",
            endpoint="localhost",
            port=443,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("127.0.0.1",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT),
        ),
        attempt=1,
        connect_timeout=0.1,
        candidate_timeout=0.2,
        tls_ca_file=None,
    )
    assert result.outcome == expected
    assert failed.closed


def test_local_tls_success_hostname_mismatch_untrusted_and_timeout(tmp_path: Path) -> None:
    ca, cert, key = make_tls_identity(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    executor = SocketProbeExecutor()

    with tcp_server(tls_context=context) as port:
        plan = ProbePlan(
            candidate_id="tls",
            endpoint="localhost",
            port=port,
            ip_families=(IPFamily.IPV4,),
            authorized_addresses=("127.0.0.1",),
            steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT, ProbeStep.TLS_HANDSHAKE),
            tls_server_name="localhost",
        )
        verified = executor.execute(
            plan,
            attempt=1,
            connect_timeout=0.5,
            candidate_timeout=1.0,
            tls_ca_file=ca,
        )
    assert verified.outcome == ProbeOutcome.SUCCESS, verified.summary
    assert verified.tls_verified is True

    with tcp_server(tls_context=context) as port:
        mismatch = executor.execute(
            plan.model_copy(update={"port": port, "tls_server_name": "wrong.example"}),
            attempt=1,
            connect_timeout=0.5,
            candidate_timeout=1.0,
            tls_ca_file=ca,
        )
    assert mismatch.outcome == ProbeOutcome.TLS_VERIFICATION_FAILURE

    with tcp_server(tls_context=context) as port:
        untrusted = executor.execute(
            plan.model_copy(update={"port": port}),
            attempt=1,
            connect_timeout=0.5,
            candidate_timeout=1.0,
            tls_ca_file=None,
        )
    assert untrusted.outcome == ProbeOutcome.TLS_VERIFICATION_FAILURE

    with tcp_server(delay=0.2) as port:
        timed_out = executor.execute(
            plan.model_copy(update={"port": port}),
            attempt=1,
            connect_timeout=0.05,
            candidate_timeout=0.1,
            tls_ca_file=ca,
        )
    assert timed_out.outcome == ProbeOutcome.TIMEOUT

    ip_ca, ip_cert, ip_key = make_tls_identity(tmp_path, hostname="127.0.0.1")
    ip_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ip_context.load_cert_chain(ip_cert, ip_key)
    with tcp_server(tls_context=ip_context) as port:
        ip_verified = executor.execute(
            ProbePlan(
                candidate_id="tls-ip",
                endpoint="127.0.0.1",
                port=port,
                ip_families=(IPFamily.IPV4,),
                authorized_addresses=("127.0.0.1",),
                steps=(ProbeStep.DNS, ProbeStep.TCP_CONNECT, ProbeStep.TLS_HANDSHAKE),
                tls_server_name="127.0.0.1",
            ),
            attempt=1,
            connect_timeout=0.5,
            candidate_timeout=1.0,
            tls_ca_file=ip_ca,
        )
    assert ip_verified.outcome == ProbeOutcome.SUCCESS
    assert ip_verified.tls_verified is True


class ControlledExecutor:
    def __init__(self, delays: dict[str, float] | None = None) -> None:
        self.delays = delays or {}
        self.active = 0
        self.maximum_active = 0
        self.calls = 0
        self.lock = threading.Lock()

    def execute(self, plan, **kwargs) -> ProbeAttempt:
        with self.lock:
            self.active += 1
            self.calls += 1
            self.maximum_active = max(self.maximum_active, self.active)
        try:
            time.sleep(self.delays.get(plan.candidate_id, 0.01))
            return attempt(ProbeOutcome.SUCCESS, attempt_number=kwargs["attempt"])
        finally:
            with self.lock:
                self.active -= 1


def test_active_orchestrator_bounds_concurrency_and_hung_probe_does_not_hide_fast_result() -> None:
    items = tuple(candidate(f"candidate-{index}") for index in range(5))
    executor = ControlledExecutor({"candidate-0": 0.2})
    result = ActivePathfinder(executor).probe(
        inventory(*items),
        capabilities(),
        PathfinderProbeConfig(
            connect_timeout_seconds=0.02,
            candidate_timeout_seconds=0.05,
            max_parallel_probes=2,
        ),
    )
    assert executor.maximum_active <= 2
    by_id = {item.candidate_id: item for item in result.observations}
    assert by_id["candidate-0"].outcome == ProbeOutcome.TIMEOUT
    assert by_id["candidate-1"].outcome == ProbeOutcome.SUCCESS
    deadline = time.monotonic() + 1.0
    while executor.active and time.monotonic() < deadline:
        time.sleep(0.01)
    assert executor.active == 0


def test_active_orchestrator_stress_never_exceeds_configured_parallelism() -> None:
    items = tuple(candidate(f"candidate-{index}") for index in range(40))
    executor = ControlledExecutor()
    result = ActivePathfinder(executor).probe(
        inventory(*items),
        capabilities(),
        PathfinderProbeConfig(
            connect_timeout_seconds=0.2,
            candidate_timeout_seconds=1.0,
            max_parallel_probes=4,
        ),
    )
    assert executor.maximum_active == 4
    assert executor.calls == 40
    assert all(item.outcome == ProbeOutcome.SUCCESS for item in result.observations)
    assert executor.active == 0


def test_late_executor_success_is_not_accepted_past_candidate_deadline() -> None:
    items = tuple(candidate(f"candidate-{index}") for index in range(10))
    executor = ControlledExecutor({"candidate-0": 0.1})
    result = ActivePathfinder(executor).probe(
        inventory(*items),
        capabilities(),
        PathfinderProbeConfig(
            connect_timeout_seconds=0.02,
            candidate_timeout_seconds=0.05,
            max_parallel_probes=2,
        ),
    )
    by_id = {item.candidate_id: item for item in result.observations}
    assert by_id["candidate-0"].outcome == ProbeOutcome.TIMEOUT
    assert by_id["candidate-1"].outcome == ProbeOutcome.SUCCESS


def test_retries_share_one_overall_candidate_budget() -> None:
    class RetryingExecutor:
        def __init__(self) -> None:
            self.budgets: list[float] = []

        def execute(self, plan, **kwargs) -> ProbeAttempt:
            budget = kwargs["candidate_timeout"]
            self.budgets.append(budget)
            time.sleep(min(0.02, budget))
            return attempt(ProbeOutcome.TIMEOUT, attempt_number=kwargs["attempt"])

    executor = RetryingExecutor()
    started = time.monotonic()
    result = ActivePathfinder(executor).probe(
        inventory(candidate("retry")),
        capabilities(),
        PathfinderProbeConfig(
            connect_timeout_seconds=0.02,
            candidate_timeout_seconds=0.05,
            max_parallel_probes=1,
            retry_count=3,
        ),
    )
    elapsed = time.monotonic() - started
    assert result.observations[0].outcome == ProbeOutcome.TIMEOUT
    assert 1 <= len(executor.budgets) <= 3
    assert executor.budgets == sorted(executor.budgets, reverse=True)
    assert elapsed < 0.15


def test_invalid_tls_ca_fails_before_probe_execution(tmp_path: Path) -> None:
    invalid_ca = tmp_path / "invalid-ca.pem"
    invalid_ca.write_text("not a certificate\n")
    executor = ControlledExecutor()
    with pytest.raises(PathfinderError, match="not a valid certificate bundle"):
        ActivePathfinder(executor).probe(
            inventory(candidate("tls")),
            capabilities(),
            PathfinderProbeConfig(),
            tls_ca_file=invalid_ca,
        )
    assert executor.calls == 0


def test_probe_configuration_is_bounded_and_round_trips(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="connect timeout"):
        PathfinderProbeConfig(
            connect_timeout_seconds=2.0,
            candidate_timeout_seconds=1.0,
        )
    for field, value in (("max_parallel_probes", 0), ("retry_count", 4)):
        with pytest.raises(ValidationError):
            PathfinderProbeConfig.model_validate({field: value})

    expected = PathfinderConfig(
        probe=PathfinderProbeConfig(
            connect_timeout_seconds=0.75,
            candidate_timeout_seconds=2.5,
            max_parallel_probes=3,
            retry_count=1,
            authorized_server_addresses=("127.0.0.1", "2001:db8::1"),
        ),
        failover=PathfinderFailoverConfig(
            failure_threshold=3,
            minimum_improvement=40,
            cooldown_seconds=90.0,
        ),
    )
    config_path = tmp_path / "fluxgate.toml"
    config_path.write_text(AppConfig(pathfinder=expected).as_toml())
    assert load_config(config_path).pathfinder == expected

    normalized = PathfinderProbeConfig(
        authorized_server_addresses=("2001:0db8:0:0:0:0:0:1", "127.0.0.1")
    )
    assert normalized.authorized_server_addresses == ("127.0.0.1", "2001:db8::1")
    for addresses in (
        ("vpn.example.test",),
        ("192.0.2.0/24",),
        ("fe80::1%lo0",),
        ("2001:db8::1", "2001:0db8:0:0:0:0:0:1"),
        tuple(f"192.0.2.{index}" for index in range(1, 18)),
    ):
        with pytest.raises(ValidationError):
            PathfinderProbeConfig(authorized_server_addresses=addresses)


def test_scoring_is_deterministic_latency_sensitive_and_unsupported_is_ineligible() -> None:
    assessment = CandidateAssessment(
        candidate_id="healthy", compatible=True, required_capabilities=()
    )
    fast = observation("healthy", attempt(ProbeOutcome.SUCCESS, latency=5.0))
    slow = observation("healthy", attempt(ProbeOutcome.SUCCESS, latency=200.0))
    assert score_candidate(assessment, fast) == score_candidate(assessment, fast)
    assert score_candidate(assessment, fast).score > score_candidate(assessment, slow).score

    unsupported_attempt = ProbeAttempt(
        attempt=1,
        outcome=ProbeOutcome.PROBE_UNSUPPORTED,
        verification=VerificationState.UNVERIFIED,
        dns_succeeded=True,
        summary="unverified",
    )
    unsupported = score_candidate(assessment, observation("healthy", unsupported_attempt))
    failed = score_candidate(assessment, observation("healthy", attempt(ProbeOutcome.TIMEOUT)))
    assert not unsupported.eligible
    assert score_candidate(assessment, fast).score > failed.score

    ranked = rank_candidates((failed, score_candidate(assessment, fast)))
    assert ranked[0].eligible
    assert ranked[0].observation.outcome == ProbeOutcome.SUCCESS


def test_scoring_bucket_boundaries_and_non_finite_values_are_rejected() -> None:
    assessment = CandidateAssessment(
        candidate_id="boundary", compatible=True, required_capabilities=()
    )
    below = score_candidate(
        assessment,
        observation("boundary", attempt(ProbeOutcome.SUCCESS, latency=24.999)),
    )
    at_boundary = score_candidate(
        assessment,
        observation("boundary", attempt(ProbeOutcome.SUCCESS, latency=25.0)),
    )
    assert below.score == at_boundary.score + 1

    for value in (float("inf"), float("-inf"), float("nan")):
        with pytest.raises(ValidationError):
            ProbeAttempt(
                attempt=1,
                outcome=ProbeOutcome.SUCCESS,
                verification=VerificationState.VERIFIED,
                total_latency_ms=value,
                summary="invalid latency",
            )
    for value in (0.0, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="finite and positive"):
            ScoringPolicy(latency_bucket_ms=value)


def test_selection_preserves_alternatives_no_viable_state_and_deterministic_ties() -> None:
    scores = []
    for candidate_id in ("b", "a"):
        assessment = CandidateAssessment(
            candidate_id=candidate_id, compatible=True, required_capabilities=()
        )
        scores.append(
            score_candidate(
                assessment,
                observation(candidate_id, attempt(ProbeOutcome.SUCCESS, latency=10.0)),
            )
        )
    ranked = rank_candidates(tuple(scores))
    decision = select_candidate(ranked)
    assert decision.selected_candidate_id == "a"
    assert decision.alternatives == ("b",)

    failed = tuple(scored_candidate(item.candidate_id, 0, ProbeOutcome.TIMEOUT) for item in ranked)
    assert select_candidate(failed).selected_candidate_id is None
    assert set(select_candidate(failed).alternatives) == {"a", "b"}


def report_for_failover() -> ActivePathfinderReport:
    return active_report(
        scored_candidate("current", 280),
        scored_candidate("better", 300),
    )


def test_failover_retains_health_applies_threshold_margin_and_cooldown() -> None:
    report = report_for_failover()
    policy = PathfinderFailoverConfig(
        failure_threshold=2, minimum_improvement=25, cooldown_seconds=30.0
    )
    healthy = decide_failover(
        report,
        FailoverContext(
            current_candidate_id="current", consecutive_failures=0, seconds_since_switch=60
        ),
        policy,
    )
    assert healthy.action == FailoverAction.STAY

    failed_report = active_report(
        scored_candidate("current", 0, ProbeOutcome.TIMEOUT),
        scored_candidate("better", 300),
    )
    below_threshold = decide_failover(
        failed_report,
        FailoverContext(
            current_candidate_id="current", consecutive_failures=1, seconds_since_switch=60
        ),
        policy,
    )
    assert below_threshold.action == FailoverAction.STAY
    cooling = decide_failover(
        failed_report,
        FailoverContext(
            current_candidate_id="current", consecutive_failures=2, seconds_since_switch=5
        ),
        policy,
    )
    assert cooling.action == FailoverAction.STAY
    switching = decide_failover(
        failed_report,
        FailoverContext(
            current_candidate_id="current", consecutive_failures=2, seconds_since_switch=60
        ),
        policy,
    )
    assert switching.action == FailoverAction.SWITCH
    assert switching.target_candidate_id == "better"

    substantial = active_report(
        scored_candidate("current", 250),
        scored_candidate("better", 300),
    )
    improved = decide_failover(
        substantial,
        FailoverContext(
            current_candidate_id="current", consecutive_failures=0, seconds_since_switch=60
        ),
        policy,
    )
    assert improved.action == FailoverAction.SWITCH
    assert improved.target_candidate_id == "better"


def test_failover_missing_current_candidate_obeys_failure_threshold() -> None:
    report = report_for_failover()
    policy = PathfinderFailoverConfig(
        failure_threshold=2, minimum_improvement=25, cooldown_seconds=30.0
    )
    below_threshold = decide_failover(
        report,
        FailoverContext(
            current_candidate_id="missing", consecutive_failures=1, seconds_since_switch=60
        ),
        policy,
    )
    assert below_threshold.action == FailoverAction.STAY
    assert below_threshold.target_candidate_id == "missing"

    at_threshold = decide_failover(
        report,
        FailoverContext(
            current_candidate_id="missing", consecutive_failures=2, seconds_since_switch=60
        ),
        policy,
    )
    assert at_threshold.action == FailoverAction.SWITCH
    assert at_threshold.target_candidate_id == "better"


def test_no_viable_failover_and_structured_cli_output_are_secret_free(tmp_path: Path) -> None:
    item = candidate("safe-public-id")
    executor = ControlledExecutor()
    report = ActivePathfinder(executor).probe(
        inventory(item), capabilities(), PathfinderProbeConfig(max_parallel_probes=1)
    )
    failed_report = active_report(scored_candidate("safe-public-id", 0, ProbeOutcome.TIMEOUT))
    decision = decide_failover(
        failed_report,
        FailoverContext(current_candidate_id="safe-public-id", consecutive_failures=5),
        PathfinderFailoverConfig(),
    )
    assert decision.action == FailoverAction.NO_VIABLE_CANDIDATE

    report_path = tmp_path / "report.json"
    report_path.write_text(report.model_dump_json())
    result = CliRunner().invoke(app, ["pathfinder", "rank", "--report", str(report_path), "--json"])
    assert result.exit_code == 0
    payload = result.stdout.lower()
    assert json.loads(result.stdout)["schema_version"] == 1
    for secret in ("private_key", "password", "credential", "test-only-secret"):
        assert secret not in payload


def test_reports_and_cli_outputs_exclude_recognizable_state_secrets(tmp_path: Path) -> None:
    sentinels = (
        "WG_PRIVATE_SENTINEL_4Qp9",
        "AWG_PRIVATE_SENTINEL_7Lm2",
        "OPENVPN_PRIVATE_SENTINEL_8Rt3",
        "TROJAN_PASSWORD_SENTINEL_1Xv6",
        "HYSTERIA_PASSWORD_SENTINEL_5Ns4",
        "VLESS_UUID_SENTINEL_2Bc8",
        "TLS_PRIVATE_SENTINEL_9Df1",
    )
    state = FluxGateState(
        clients=[
            Client(
                name="secret-client",
                provider_credentials={
                    "wireguard": {"private_key": sentinels[0]},
                    "amneziawg": {"private_key": sentinels[1]},
                    "openvpn": {"private_key": sentinels[2]},
                },
                profile_credentials={
                    "trojan": {"password": sentinels[3]},
                    "hysteria2": {"password": sentinels[4]},
                    "vless": {"uuid": sentinels[5]},
                    "tls": {"private_key": sentinels[6]},
                },
            )
        ],
        providers={"wireguard": {"enabled": True}},
    )
    config = AppConfig.model_validate({"server": {"domain": "localhost"}})
    manifest = build_manifest(config, state)
    report = ActivePathfinder().probe(
        authorize_manifest(manifest, source=AuthorizationSource.LOCAL_STATE),
        full_capabilities(),
        PathfinderProbeConfig(max_parallel_probes=1),
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(report.model_dump_json())
    config_dir = tmp_path / "config"
    environment = {"FLUXGATE_CONFIG_DIR": str(config_dir)}

    outputs = [report.model_dump_json()]
    for arguments in (
        ["pathfinder", "rank", "--report", str(report_path)],
        ["pathfinder", "rank", "--report", str(report_path), "--json"],
        ["pathfinder", "select", "--report", str(report_path)],
        ["pathfinder", "select", "--report", str(report_path), "--json"],
        ["pathfinder", "failover", "--report", str(report_path)],
        ["pathfinder", "failover", "--report", str(report_path), "--json"],
    ):
        result = CliRunner().invoke(app, arguments, env=environment)
        assert result.exit_code == 0, result.output
        outputs.append(result.output)
    combined = "\n".join(outputs)
    for sentinel in sentinels:
        assert sentinel not in combined


def test_report_cli_recomputes_scores_and_redacts_malformed_input(tmp_path: Path) -> None:
    fast_assessment = CandidateAssessment(
        candidate_id="a-fast", compatible=True, required_capabilities=()
    )
    slow_assessment = CandidateAssessment(
        candidate_id="z-slow", compatible=True, required_capabilities=()
    )
    fast = score_candidate(
        fast_assessment,
        observation("a-fast", attempt(ProbeOutcome.SUCCESS, latency=5.0)),
    )
    slow = score_candidate(
        slow_assessment,
        observation("z-slow", attempt(ProbeOutcome.SUCCESS, latency=500.0)),
    )
    report = ActivePathfinderReport(
        assessments=(fast_assessment, slow_assessment),
        observations=(fast.observation, slow.observation),
        ranked_candidates=rank_candidates((fast, slow)),
        selection=select_candidate(rank_candidates((fast, slow))),
    )
    payload = json.loads(report.model_dump_json())
    payload["ranked_candidates"][0]["score"] += 10_000
    payload["ranked_candidates"][0]["components"][0]["points"] += 10_000
    report_path = tmp_path / "edited-report.json"
    report_path.write_text(json.dumps(payload))
    result = CliRunner().invoke(
        app,
        ["pathfinder", "rank", "--report", str(report_path), "--json"],
    )
    assert result.exit_code == 0, result.output
    normalized = json.loads(result.stdout)
    assert normalized["selection"]["selected_candidate_id"] == "a-fast"
    assert normalized["ranked_candidates"][0]["score"] < 10_000

    sentinel = "MALFORMED_REPORT_SECRET_6Hy3"
    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps({"schema_version": 1, "secret": sentinel}))
    failed = CliRunner().invoke(app, ["pathfinder", "rank", "--report", str(malformed)])
    assert failed.exit_code == 1
    assert "malformed or unsupported" in failed.output
    assert sentinel not in failed.output


def test_active_cli_refuses_unsigned_manifest_before_network_io(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(
        ServerManifest(
            server=ManifestServer(identity="localhost"),
            candidates=(candidate("owned"),),
        ).render()
    )
    client = tmp_path / "capabilities.json"
    client.write_text(capabilities().model_dump_json())
    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "probe",
            "--manifest",
            str(manifest),
            "--capabilities",
            str(client),
        ],
    )
    assert result.exit_code == 1
    assert "requires --local or --manifest, --signature, --trust and --expected-server" in (
        result.output
    )


def signed_probe_inputs(
    provider_context,
    tmp_path: Path,
    endpoint: str = "authorized.example.test",
):
    manager = ServerIdentityManager(provider_context.paths)
    identity = manager.ensure()
    manifest_bytes = ServerManifest(
        server=ManifestServer(
            identity=endpoint,
            server_id=identity.metadata.server_id,
        ),
        candidates=(candidate("owned", endpoint=endpoint),),
    ).render()
    manifest = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig"
    trust = tmp_path / "trust.json"
    client = tmp_path / "capabilities.json"
    manifest.write_bytes(manifest_bytes)
    signature.write_bytes(manager.sign(manifest_bytes, identity))
    trust.write_bytes(identity.trust.render())
    client.write_text(capabilities().model_dump_json())
    return manifest, signature, trust, client


def signed_probe_arguments(
    manifest: Path,
    signature: Path,
    trust: Path,
    client: Path,
    expected_server: str = "authorized.example.test",
) -> list[str]:
    return [
        "pathfinder",
        "probe",
        "--manifest",
        str(manifest),
        "--signature",
        str(signature),
        "--trust",
        str(trust),
        "--expected-server",
        expected_server,
        "--capabilities",
        str(client),
    ]


def test_signed_cli_accepts_bounded_ipv4_ipv6_address_pins(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, signature, trust, client = signed_probe_inputs(provider_context, tmp_path)
    captured: list[tuple[str, ...]] = []

    def controlled_probe(self, inventory, capabilities, config, **kwargs):
        captured.append(inventory.authorized_addresses)
        return active_report(scored_candidate("owned", 260))

    monkeypatch.setattr(ActivePathfinder, "probe", controlled_probe)
    result = CliRunner().invoke(
        app,
        [
            *signed_probe_arguments(manifest, signature, trust, client),
            "--expected-address",
            "2001:0db8:0:0:0:0:0:1",
            "--expected-address",
            "192.0.2.10",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured == [("192.0.2.10", "2001:db8::1")]
    help_result = CliRunner().invoke(app, ["pathfinder", "probe", "--help"])
    assert help_result.exit_code == 0
    assert "--expected-address" in help_result.output


def test_signed_cli_literal_ip_endpoint_authorizes_only_itself(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, signature, trust, client = signed_probe_inputs(
        provider_context, tmp_path, endpoint="192.0.2.10"
    )
    captured: list[tuple[str, ...]] = []

    def controlled_probe(self, inventory, capabilities, config, **kwargs):
        captured.append(inventory.authorized_addresses)
        return active_report(scored_candidate("owned", 260))

    monkeypatch.setattr(ActivePathfinder, "probe", controlled_probe)
    result = CliRunner().invoke(
        app,
        [
            *signed_probe_arguments(
                manifest,
                signature,
                trust,
                client,
                expected_server="192.0.2.10",
            ),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured == [("192.0.2.10",)]


def test_signed_cli_dns_redirect_is_typed_and_never_creates_socket(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, signature, trust, client = signed_probe_inputs(provider_context, tmp_path)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("169.254.169.254", 443),
            )
        ],
    )
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("DNS redirect reached socket creation")
        ),
    )
    result = CliRunner().invoke(
        app,
        [
            *signed_probe_arguments(manifest, signature, trust, client),
            "--expected-address",
            "203.0.113.10",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["observations"][0]["outcome"] == "destination_unauthorized"
    assert payload["observations"][0]["attempts"][0]["tcp_connected"] is False


def test_signed_cli_rejects_malformed_duplicate_and_excessive_address_pins(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, signature, trust, client = signed_probe_inputs(provider_context, tmp_path)

    def unexpected_probe(*args, **kwargs):
        raise AssertionError("invalid address pins must fail before network probing")

    monkeypatch.setattr(ActivePathfinder, "probe", unexpected_probe)
    base = signed_probe_arguments(manifest, signature, trust, client)
    cases = (
        ["--expected-address", "vpn.example.test"],
        ["--expected-address", "192.0.2.0/24"],
        [
            "--expected-address",
            "2001:db8::1",
            "--expected-address",
            "2001:0db8:0:0:0:0:0:1",
        ],
        [item for index in range(1, 18) for item in ("--expected-address", f"192.0.2.{index}")],
    )
    for arguments in cases:
        result = CliRunner().invoke(app, [*base, *arguments])
        assert result.exit_code == 1
    missing = CliRunner().invoke(app, base)
    assert missing.exit_code == 1
    assert "requires an independently pinned server address" in missing.output


def test_local_inventory_uses_configured_address_pins_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    data_dir = tmp_path / "data"
    config_dir.mkdir()
    monkeypatch.setenv("FLUXGATE_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("FLUXGATE_DATA_DIR", str(data_dir))
    document = ServerManifest(
        server=ManifestServer(identity="authorized.example.test"),
        candidates=(candidate("owned", endpoint="authorized.example.test"),),
    )
    monkeypatch.setattr(pathfinder_cli, "build_manifest", lambda config, state: document)

    configured = AppConfig(
        server={"domain": "authorized.example.test"},
        pathfinder=PathfinderConfig(
            probe=PathfinderProbeConfig(authorized_server_addresses=("10.0.0.10",))
        ),
    )
    (config_dir / "config.toml").write_text(configured.as_toml())
    authorized, _ = pathfinder_cli._load_active_inventory(
        local_inventory=True,
        manifest=None,
        signature=None,
        trust=None,
        expected_server=None,
        expected_addresses=(),
    )
    assert authorized.authorized_addresses == ("10.0.0.10",)

    unpinned = AppConfig(server={"domain": "authorized.example.test"})
    (config_dir / "config.toml").write_text(unpinned.as_toml())
    blocked, _ = pathfinder_cli._load_active_inventory(
        local_inventory=True,
        manifest=None,
        signature=None,
        trust=None,
        expected_server=None,
        expected_addresses=(),
    )
    assert blocked.authorized_addresses == ()

    client = tmp_path / "capabilities.json"
    client.write_text(capabilities().model_dump_json())
    combined = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "probe",
            "--local",
            "--expected-address",
            "10.0.0.10",
            "--capabilities",
            str(client),
        ],
    )
    assert combined.exit_code == 1
    assert "--local cannot be combined" in combined.output


def test_active_cli_rejects_signed_endpoint_redirect_before_network_io(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, signature, trust, client = signed_probe_inputs(provider_context, tmp_path)

    def unexpected_probe(*args, **kwargs):
        raise AssertionError("network probe must not run after endpoint authorization failure")

    monkeypatch.setattr(ActivePathfinder, "probe", unexpected_probe)
    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "probe",
            "--manifest",
            str(manifest),
            "--signature",
            str(signature),
            "--trust",
            str(trust),
            "--expected-server",
            "redirected.example.test",
            "--expected-address",
            "192.0.2.10",
            "--capabilities",
            str(client),
        ],
    )
    assert result.exit_code == 1
    assert "does not match the independently pinned server endpoint" in result.output


def test_persistent_state_schema_remains_v2() -> None:
    from fluxgate.core.models import FluxGateState

    assert FluxGateState().schema_version == 2
