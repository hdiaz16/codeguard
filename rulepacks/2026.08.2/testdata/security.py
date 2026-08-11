# Fixture de semgrep --test — no es código del producto.
import subprocess

import yaml


def ejecutar_comando(comando):
    # ruleid: python-subprocess-shell
    subprocess.run(comando, shell=True)


def ejecutar_comando_seguro():
    # ok: python-subprocess-shell
    subprocess.run(["ls", "-l"], check=True)


def cargar_config(texto):
    # ruleid: python-yaml-unsafe-load
    return yaml.load(texto)


def cargar_config_segura(texto):
    # ok: python-yaml-unsafe-load
    return yaml.safe_load(texto)
