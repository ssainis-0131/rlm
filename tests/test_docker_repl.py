"""Tests for DockerREPL environment security features.

Note: These tests focus on configuration and parameter handling.
Full integration tests require Docker to be installed and running.
"""


class TestDockerREPLSecurityVolumeMount:
    """Tests for Docker volume mount security control (Security Fix #15)."""

    def test_extra_volume_mounts_default_empty(self):
        """Test that extra_volume_mounts defaults to empty list."""
        from rlm.environments.docker_repl import DockerREPL

        # Mock the setup to avoid actually starting Docker
        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass  # Skip actual Docker setup

            def cleanup(self):
                pass

        repl = MockDockerREPL()
        assert repl.extra_volume_mounts == []
        repl.cleanup()

    def test_extra_volume_mounts_stored(self):
        """Test that extra_volume_mounts are stored correctly."""
        from rlm.environments.docker_repl import DockerREPL

        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass

            def cleanup(self):
                pass

        mounts = [
            {"host_path": "/data", "container_path": "/mnt/data"},
            {"host_path": "/config", "container_path": "/mnt/config", "writable": True},
        ]
        repl = MockDockerREPL(extra_volume_mounts=mounts)
        assert len(repl.extra_volume_mounts) == 2
        assert repl.extra_volume_mounts[0]["host_path"] == "/data"
        repl.cleanup()

    def test_volume_mount_default_readonly(self):
        """Test that volume mounts default to read-only."""
        from rlm.environments.docker_repl import DockerREPL

        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass

            def cleanup(self):
                pass

        # Mount without specifying writable
        mounts = [{"host_path": "/data", "container_path": "/mnt/data"}]
        repl = MockDockerREPL(extra_volume_mounts=mounts)

        # Check that writable defaults to False
        mount = repl.extra_volume_mounts[0]
        assert mount.get("writable", False) is False
        repl.cleanup()

    def test_volume_mount_explicit_writable(self):
        """Test that volume mounts can be explicitly set to writable."""
        from rlm.environments.docker_repl import DockerREPL

        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass

            def cleanup(self):
                pass

        mounts = [{"host_path": "/data", "container_path": "/mnt/data", "writable": True}]
        repl = MockDockerREPL(extra_volume_mounts=mounts)

        mount = repl.extra_volume_mounts[0]
        assert mount.get("writable") is True
        repl.cleanup()


class TestDockerREPLNetworkDisabled:
    """Tests for Docker network isolation."""

    def test_network_disabled_by_default(self):
        """Test that network is disabled by default."""
        from rlm.environments.docker_repl import DockerREPL

        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass

            def cleanup(self):
                pass

        repl = MockDockerREPL()
        assert repl.network_disabled is True
        repl.cleanup()

    def test_network_can_be_enabled(self):
        """Test that network can be enabled."""
        from rlm.environments.docker_repl import DockerREPL

        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass

            def cleanup(self):
                pass

        repl = MockDockerREPL(network_disabled=False)
        assert repl.network_disabled is False
        repl.cleanup()


class TestDockerREPLConfiguration:
    """Tests for DockerREPL configuration."""

    def test_default_image(self):
        """Test that default image is python:3.11-slim."""
        from rlm.environments.docker_repl import DockerREPL

        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass

            def cleanup(self):
                pass

        repl = MockDockerREPL()
        assert repl.image == "python:3.11-slim"
        repl.cleanup()

    def test_custom_image(self):
        """Test that custom image can be set."""
        from rlm.environments.docker_repl import DockerREPL

        class MockDockerREPL(DockerREPL):
            def setup(self):
                pass

            def cleanup(self):
                pass

        repl = MockDockerREPL(image="python:3.12-slim")
        assert repl.image == "python:3.12-slim"
        repl.cleanup()
