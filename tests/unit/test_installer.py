from pathlib import Path


def test_installer_prepares_command_link_before_atomic_release_switch() -> None:
    script = (Path(__file__).parents[2] / "scripts" / "install.sh").read_text()
    create_command = 'ln -s "$expected_link" "$bin_path"'
    switch_release = 'mv -Tf "$next_link" "$install_root/current"'
    assert 'next_link="$install_root/current.new.$$"' in script
    assert 'rm -f "$next_link"' in script
    assert '"$(readlink "$install_root/current")" = "$release"' in script
    assert create_command in script
    assert script.index(create_command) < script.index(switch_release)
    assert script.index(switch_release) < script.index(
        "complete=true", script.index(switch_release)
    )
    assert "ln -sfn" not in script
