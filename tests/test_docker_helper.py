"""Pruebas para DockerHelper (modules.docker_helper).

Valida la traduccion de lenguaje natural a comandos Docker, el soporte de
identificadores reales con guiones/puntos, el rechazo de palabras reservadas y
puertos fuera de rango, y la alineacion con CommandPolicy/SecurityLayer.
"""
import pytest

from modules.command_policy import CommandPolicy
from modules.docker_helper import DockerHelper
from modules.security_layer import SecurityLayer


@pytest.fixture
def helper():
    return DockerHelper()


def test_bare_queries_match_status_stats_and_images(helper):
    assert helper.parse_natural_language("status")[0] == "status"
    assert helper.parse_natural_language("estado")[0] == "status"
    assert helper.parse_natural_language("stats")[0] == "stats"
    assert helper.parse_natural_language("recursos")[0] == "stats"
    assert helper.parse_natural_language("imagenes")[0] == "images"
    assert helper.parse_natural_language("imágenes")[0] == "images"
    assert "docker ps -a" in helper.get_docker_command("status")
    assert "docker stats --no-stream" in helper.get_docker_command("stats")
    assert "docker images" in helper.get_docker_command("imagenes")


@pytest.mark.parametrize(
    "query,expected",
    [
        ("para my-nginx-1", "docker stop my-nginx-1"),
        ("reinicia home-assistant.prod", "docker restart home-assistant.prod"),
        ("elimina contenedor redis_cache-2", "docker rm -f redis_cache-2"),
        ("logs de api-gateway_v2", "docker logs --tail 50 api-gateway_v2"),
        ("muestra los logs del contenedor web-app.1", "docker logs --tail 50 web-app.1"),
    ],
)
def test_hyphenated_and_dotted_container_names(helper, query, expected):
    assert helper.get_docker_command(query) == expected


def test_run_known_template_with_custom_port(helper):
    cmd = helper.get_docker_command("levanta nextcloud en puerto 9090")
    assert cmd is not None
    assert cmd.startswith("docker run -d --name nextcloud -p 9090:80")
    assert "-v nextcloud_data:/var/www/html" in cmd


def test_run_hyphenated_service_phrase_not_truncated(helper):
    cmd = helper.get_docker_command("levanta el servicio my-custom-api en puerto 3000")
    assert cmd == "docker run -d --name my-custom-api -p 3000:80 my-custom-api"


@pytest.mark.parametrize(
    "invalid_query",
    [
        "en puerto 8080",
        "puerto 8080",
        "levanta nextcloud en puerto 0",
        "levanta nextcloud en puerto 70000",
        "para contenedor",
        "logs de",
        "levanta nginx; rm -rf /",
        "para $(whoami)",
        "logs nginx | cat",
    ],
)
def test_invalid_or_unsafe_queries_return_none(helper, invalid_query):
    assert helper.get_docker_command(invalid_query) is None


def test_generated_mutating_docker_commands_require_confirmation(helper):
    layer = SecurityLayer.__new__(SecurityLayer)
    layer.console = None
    layer.lang = "es"

    for query in (
        "levanta nextcloud en puerto 8080",
        "para nginx",
        "reinicia jellyfin",
        "elimina portainer",
    ):
        cmd = helper.get_docker_command(query)
        assert cmd is not None
        risk, _ = layer.classify_risk(cmd)
        assert risk != SecurityLayer.RISK_LOW
        assert CommandPolicy.is_command_safe(cmd) is False
