"""Explicit supported protocol/transport/security compatibility."""

from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import (
    ProfileCapabilities,
    ProtocolName,
    ProtocolSpec,
    SecurityName,
    SocketProtocol,
    TransportName,
)

PROTOCOL_SPECS = {
    ProtocolName.VLESS: ProtocolSpec(
        protocol=ProtocolName.VLESS,
        transports=(TransportName.TCP,),
        security_modes=(SecurityName.TLS,),
        capabilities=ProfileCapabilities(socket_protocol=SocketProtocol.TCP, requires_tls=True),
    ),
    ProtocolName.TROJAN: ProtocolSpec(
        protocol=ProtocolName.TROJAN,
        transports=(TransportName.TCP,),
        security_modes=(SecurityName.TLS,),
        capabilities=ProfileCapabilities(socket_protocol=SocketProtocol.TCP, requires_tls=True),
    ),
    ProtocolName.HYSTERIA2: ProtocolSpec(
        protocol=ProtocolName.HYSTERIA2,
        transports=(TransportName.QUIC,),
        security_modes=(SecurityName.TLS,),
        capabilities=ProfileCapabilities(socket_protocol=SocketProtocol.UDP, requires_tls=True),
    ),
}


def protocol_spec(protocol: ProtocolName) -> ProtocolSpec:
    try:
        return PROTOCOL_SPECS[protocol]
    except KeyError as error:
        raise FluxGateError(f"unsupported protocol: {protocol}") from error
