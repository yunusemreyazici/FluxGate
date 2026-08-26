"""Capability-derived probe planning and standard-library execution."""

from __future__ import annotations

import errno
import ipaddress
import queue
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Protocol, cast

from fluxgate.pathfinder.active_models import (
    ProbeAttempt,
    ProbeOutcome,
    ProbePlan,
    ProbeStep,
    VerificationState,
)
from fluxgate.pathfinder.models import ConnectionCandidate, IPFamily, PathfinderSecurity


def build_probe_plan(
    candidate: ConnectionCandidate, *, authorized_addresses: tuple[str, ...]
) -> ProbePlan:
    """Derive safe generic probes from typed candidate capabilities, not protocol names."""
    steps = [ProbeStep.DNS]
    tls_server_name: str | None = None
    if candidate.socket_protocol == "tcp":
        steps.append(ProbeStep.TCP_CONNECT)
        if candidate.security == PathfinderSecurity.TLS:
            steps.append(ProbeStep.TLS_HANDSHAKE)
            tls_server_name = candidate.endpoint
    return ProbePlan(
        candidate_id=candidate.candidate_id,
        endpoint=candidate.endpoint,
        port=candidate.port,
        ip_families=candidate.ip_families,
        authorized_addresses=authorized_addresses,
        steps=tuple(steps),
        tls_server_name=tls_server_name,
    )


def create_tls_context(tls_ca_file: Path | None) -> ssl.SSLContext:
    """Create a verifying client context and optionally add a private CA to system trust."""
    context = ssl.create_default_context()
    if tls_ca_file is not None:
        context.load_verify_locations(cafile=str(tls_ca_file))
    return context


class ProbeExecutor(Protocol):
    def execute(
        self,
        plan: ProbePlan,
        *,
        attempt: int,
        connect_timeout: float,
        candidate_timeout: float,
        tls_ca_file: Path | None,
    ) -> ProbeAttempt: ...


class SocketProbeExecutor:
    """Execute bounded DNS, TCP, and verified TLS probes without application credentials."""

    _resolver_slots = threading.BoundedSemaphore(32)

    @classmethod
    def _resolve(
        cls,
        endpoint: str,
        port: int,
        socket_type: socket.SocketKind,
        timeout: float,
    ) -> list[tuple[Any, ...]]:
        """Bound the otherwise non-cancellable platform resolver without leaking worker pools."""
        if not cls._resolver_slots.acquire(blocking=False):
            raise TimeoutError("bounded DNS resolver capacity is exhausted")
        results: queue.Queue[object] = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                results.put(
                    socket.getaddrinfo(
                        endpoint,
                        port,
                        family=socket.AF_UNSPEC,
                        type=socket_type,
                    )
                )
            except BaseException as error:
                results.put(error)
            finally:
                cls._resolver_slots.release()

        worker = threading.Thread(
            target=resolve,
            name="fluxgate-pathfinder-resolver",
            daemon=True,
        )
        worker.start()
        worker.join(timeout=max(0.0, timeout))
        if worker.is_alive():
            raise TimeoutError("DNS resolution timed out")
        result = results.get_nowait()
        if isinstance(result, BaseException):
            raise result
        return cast(list[tuple[Any, ...]], result)

    @staticmethod
    def _failure(
        *,
        attempt: int,
        outcome: ProbeOutcome,
        summary: str,
        started: float,
        dns_succeeded: bool | None = None,
        tcp_connected: bool | None = None,
        tls_verified: bool | None = None,
        dns_latency_ms: float | None = None,
        connect_latency_ms: float | None = None,
    ) -> ProbeAttempt:
        return ProbeAttempt(
            attempt=attempt,
            outcome=outcome,
            verification=VerificationState.FAILED,
            dns_succeeded=dns_succeeded,
            tcp_connected=tcp_connected,
            tls_verified=tls_verified,
            dns_latency_ms=dns_latency_ms,
            connect_latency_ms=connect_latency_ms,
            total_latency_ms=(time.monotonic() - started) * 1000,
            summary=summary,
        )

    @staticmethod
    def _connect_outcome(errors: list[OSError]) -> tuple[ProbeOutcome, str]:
        if any(isinstance(error, TimeoutError) for error in errors):
            return ProbeOutcome.TIMEOUT, "TCP connection timed out"
        if any(isinstance(error, ConnectionRefusedError) for error in errors):
            return ProbeOutcome.CONNECTION_REFUSED, "TCP connection was refused"
        if any(error.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH} for error in errors):
            return ProbeOutcome.NETWORK_UNREACHABLE, "network or host is unreachable"
        return ProbeOutcome.CONNECT_FAILURE, "TCP connection failed"

    def execute(
        self,
        plan: ProbePlan,
        *,
        attempt: int,
        connect_timeout: float,
        candidate_timeout: float,
        tls_ca_file: Path | None,
    ) -> ProbeAttempt:
        started = time.monotonic()
        deadline = started + candidate_timeout
        socket_type = (
            socket.SOCK_STREAM if ProbeStep.TCP_CONNECT in plan.steps else socket.SOCK_DGRAM
        )
        dns_started = time.monotonic()
        try:
            addresses = self._resolve(
                plan.endpoint,
                plan.port,
                socket_type,
                min(connect_timeout, max(0.0, deadline - time.monotonic())),
            )
        except TimeoutError:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.TIMEOUT,
                summary="DNS resolution timed out",
                started=started,
                dns_succeeded=False,
            )
        except socket.gaierror:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.DNS_FAILURE,
                summary="DNS resolution failed",
                started=started,
                dns_succeeded=False,
            )
        dns_latency = (time.monotonic() - dns_started) * 1000
        if not addresses:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.DNS_FAILURE,
                summary="DNS resolution returned no addresses",
                started=started,
                dns_succeeded=False,
                dns_latency_ms=dns_latency,
            )
        allowed_families = {
            family
            for family, enabled in (
                (socket.AF_INET, IPFamily.IPV4 in plan.ip_families),
                (socket.AF_INET6, IPFamily.IPV6 in plan.ip_families),
            )
            if enabled
        }
        addresses = [address for address in addresses if address[0] in allowed_families]
        if not addresses:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.DESTINATION_UNAUTHORIZED,
                summary=(
                    "DNS resolution succeeded but returned no independently authorized destination"
                ),
                started=started,
                dns_succeeded=True,
                tcp_connected=False if ProbeStep.TCP_CONNECT in plan.steps else None,
                dns_latency_ms=dns_latency,
            )
        if ProbeStep.TCP_CONNECT not in plan.steps:
            return ProbeAttempt(
                attempt=attempt,
                outcome=ProbeOutcome.PROBE_UNSUPPORTED,
                verification=VerificationState.UNVERIFIED,
                dns_succeeded=True,
                dns_latency_ms=dns_latency,
                total_latency_ms=(time.monotonic() - started) * 1000,
                summary=(
                    "endpoint resolved, but no safe generic application-level probe is available"
                ),
            )

        authorized = set(plan.authorized_addresses)
        concrete: dict[tuple[int, int, tuple[str, ...]], tuple[Any, ...]] = {}
        for address in addresses:
            socket_address = address[4]
            if (
                not isinstance(socket_address, tuple)
                or len(socket_address) < 2
                or socket_address[1] != plan.port
                or not isinstance(socket_address[0], str)
            ):
                continue
            try:
                resolved = ipaddress.ip_address(socket_address[0])
            except ValueError:
                continue
            if (address[0] == socket.AF_INET and resolved.version != 4) or (
                address[0] == socket.AF_INET6 and resolved.version != 6
            ):
                continue
            if str(resolved) not in authorized:
                continue
            key = (
                resolved.version,
                int(resolved),
                tuple(str(item) for item in socket_address[1:]),
            )
            concrete.setdefault(key, address)
        addresses = [concrete[key] for key in sorted(concrete)]
        if not addresses:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.DESTINATION_UNAUTHORIZED,
                summary=(
                    "DNS resolution succeeded but returned no independently authorized destination"
                ),
                started=started,
                dns_succeeded=True,
                tcp_connected=False,
                dns_latency_ms=dns_latency,
            )

        connection: socket.socket | None = None
        connection_errors: list[OSError] = []
        connect_started = time.monotonic()
        for family, kind, protocol, _, address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                connection_errors.append(TimeoutError("candidate timeout"))
                break
            candidate_socket = socket.socket(family, kind, protocol)
            try:
                candidate_socket.settimeout(min(connect_timeout, remaining))
                candidate_socket.connect(address)
                connection = candidate_socket
                break
            except OSError as error:
                connection_errors.append(error)
                candidate_socket.close()
            except BaseException:
                candidate_socket.close()
                raise
        connect_latency = (time.monotonic() - connect_started) * 1000
        if connection is None:
            outcome, summary = self._connect_outcome(connection_errors)
            return self._failure(
                attempt=attempt,
                outcome=outcome,
                summary=summary,
                started=started,
                dns_succeeded=True,
                tcp_connected=False,
                dns_latency_ms=dns_latency,
                connect_latency_ms=connect_latency,
            )
        if ProbeStep.TLS_HANDSHAKE not in plan.steps:
            connection.close()
            return ProbeAttempt(
                attempt=attempt,
                outcome=ProbeOutcome.SUCCESS,
                verification=VerificationState.VERIFIED,
                dns_succeeded=True,
                tcp_connected=True,
                dns_latency_ms=dns_latency,
                connect_latency_ms=connect_latency,
                total_latency_ms=(time.monotonic() - started) * 1000,
                summary="TCP connection succeeded",
            )

        handshake_started = time.monotonic()
        secured: ssl.SSLSocket | None = None
        try:
            context = create_tls_context(tls_ca_file)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("candidate timeout")
            connection.settimeout(min(connect_timeout, remaining))
            secured = context.wrap_socket(
                connection,
                server_hostname=plan.tls_server_name,
                do_handshake_on_connect=False,
            )
            secured.do_handshake()
            handshake_latency = (time.monotonic() - handshake_started) * 1000
            return ProbeAttempt(
                attempt=attempt,
                outcome=ProbeOutcome.SUCCESS,
                verification=VerificationState.VERIFIED,
                dns_succeeded=True,
                tcp_connected=True,
                tls_verified=True,
                dns_latency_ms=dns_latency,
                connect_latency_ms=connect_latency,
                handshake_latency_ms=handshake_latency,
                total_latency_ms=(time.monotonic() - started) * 1000,
                summary="TCP connection and verified TLS handshake succeeded",
            )
        except ssl.SSLCertVerificationError as error:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.TLS_VERIFICATION_FAILURE,
                summary=f"TLS certificate verification failed: {error.verify_message}",
                started=started,
                dns_succeeded=True,
                tcp_connected=True,
                tls_verified=False,
                dns_latency_ms=dns_latency,
                connect_latency_ms=connect_latency,
            )
        except TimeoutError:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.TIMEOUT,
                summary="TLS handshake timed out",
                started=started,
                dns_succeeded=True,
                tcp_connected=True,
                tls_verified=False,
                dns_latency_ms=dns_latency,
                connect_latency_ms=connect_latency,
            )
        except ssl.SSLError:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.TLS_HANDSHAKE_FAILURE,
                summary="TLS handshake failed",
                started=started,
                dns_succeeded=True,
                tcp_connected=True,
                tls_verified=False,
                dns_latency_ms=dns_latency,
                connect_latency_ms=connect_latency,
            )
        except OSError:
            return self._failure(
                attempt=attempt,
                outcome=ProbeOutcome.TLS_HANDSHAKE_FAILURE,
                summary="network connection failed during TLS handshake",
                started=started,
                dns_succeeded=True,
                tcp_connected=True,
                tls_verified=False,
                dns_latency_ms=dns_latency,
                connect_latency_ms=connect_latency,
            )
        finally:
            if secured is not None:
                secured.close()
            else:
                connection.close()
