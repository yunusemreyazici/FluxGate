import pytest

from fluxgate.core.errors import FluxGateError, StateError
from fluxgate.core.models import ProviderDetection
from fluxgate.providers.wireguard import WireGuardProvider


def available() -> ProviderDetection:
    return ProviderDetection(available=True, binaries={"wg": True, "wg-quick": True, "nft": True})


def unavailable() -> ProviderDetection:
    return ProviderDetection(
        available=False, binaries={"wg": False, "wg-quick": False, "nft": False}
    )


def assert_fresh_host_rolled_back(provider, context) -> None:
    assert not provider.config_path.exists()
    assert not provider.private_key_path.exists()
    assert not provider.public_key_path.exists()
    assert not context.state.path.exists()
    assert not context.services.active
    assert not context.services.enabled
    assert not context.firewall.present
    assert not context.forwarding.present


@pytest.mark.parametrize(
    "failure_step", ["package", "key", "config", "forwarding", "firewall", "service", "state"]
)
def test_fresh_enable_failure_rolls_back_every_completed_step(
    provider_context, monkeypatch, failure_step: str
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", unavailable if failure_step == "package" else available)

    if failure_step == "package":
        monkeypatch.setattr(
            provider_context.packages,
            "install",
            lambda packages: (_ for _ in ()).throw(RuntimeError("package failure")),
        )
    elif failure_step == "key":
        original_run = provider_context.runner.run

        def fail_key(args, **kwargs):
            if tuple(args) == ("wg", "genkey"):
                raise RuntimeError("key failure")
            return original_run(args, **kwargs)

        monkeypatch.setattr(provider_context.runner, "run", fail_key)
    elif failure_step == "config":
        from fluxgate.providers.wireguard import provider as provider_module

        monkeypatch.setattr(
            provider_module,
            "atomic_write",
            lambda path, content, mode: (_ for _ in ()).throw(RuntimeError("config failure")),
        )
    elif failure_step == "forwarding":
        monkeypatch.setattr(
            provider_context.forwarding,
            "ensure",
            lambda: (_ for _ in ()).throw(RuntimeError("forwarding failure")),
        )
    elif failure_step == "firewall":
        monkeypatch.setattr(
            provider_context.firewall,
            "ensure_nat",
            lambda source, outbound: (_ for _ in ()).throw(RuntimeError("firewall failure")),
        )
    elif failure_step == "service":
        monkeypatch.setattr(
            provider_context.services,
            "enable_now",
            lambda unit: (_ for _ in ()).throw(RuntimeError("service failure")),
        )
    elif failure_step == "state":
        monkeypatch.setattr(
            provider_context.state,
            "save",
            lambda state: (_ for _ in ()).throw(StateError("state failure")),
        )

    with pytest.raises(FluxGateError, match="operation failed"):
        provider.enable()
    assert_fresh_host_rolled_back(provider, provider_context)


def test_drift_restart_failure_restores_previous_config(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    original = provider.config_path.read_bytes()
    provider.config_path.write_text(
        provider.config_path.read_text().replace("ListenPort = 51820", "ListenPort = 51999")
    )
    drifted = provider.config_path.read_bytes()
    calls = 0

    def fail_once(unit: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("restart failure")
        provider_context.services.active = True

    monkeypatch.setattr(provider_context.services, "restart", fail_once)
    with pytest.raises(FluxGateError, match="restart failure"):
        provider.enable()
    assert provider.config_path.read_bytes() == drifted
    assert provider.config_path.read_bytes() != original
    assert provider_context.services.active


def test_disable_state_failure_restores_service_firewall_and_forwarding(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    config_before = provider.config_path.read_bytes()
    monkeypatch.setattr(
        provider_context.state,
        "save",
        lambda state: (_ for _ in ()).throw(StateError("disable state failure")),
    )
    with pytest.raises(FluxGateError, match="disable state failure"):
        provider.disable()
    assert provider_context.services.active
    assert provider_context.services.enabled
    assert provider_context.firewall.present
    assert provider_context.forwarding.present
    assert provider.config_path.read_bytes() == config_before
