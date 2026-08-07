from pathlib import Path


def test_container_healthcheck_uses_wayfinder_root() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text()

    assert "urlopen('http://127.0.0.1:8000/', timeout=3)" in dockerfile
    assert "127.0.0.1:8000/app" not in dockerfile
