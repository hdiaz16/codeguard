# Fixture de semgrep --test — no es código del producto.
# Casos positivos (ruleid) y negativos (ok) para las reglas python-* y
# hardcoded-credential-generico de seguridad-ext.yaml.

import hashlib
import json
import pickle
import random

import defusedxml.ElementTree
import jwt
import requests
import sqlalchemy
import xml.etree.ElementTree
from flask import request

# ruleid: python-debug-en-prod
DEBUG = True


def sql_concat(cur, id_usuario, nombre):
    # ruleid: python-sql-concat
    cur.execute("SELECT id, nombre FROM usuarios WHERE id = %s" % id_usuario)
    # ruleid: python-sql-concat
    cur.execute("SELECT id, nombre FROM usuarios WHERE id = " + id_usuario)
    # ruleid: python-sql-concat
    cur.execute("SELECT id, nombre FROM usuarios WHERE nombre = {}".format(nombre))
    # ruleid: python-sql-concat
    cur.execute(f"SELECT id, nombre FROM usuarios WHERE id = {id_usuario}")
    # ruleid: python-sql-concat
    consulta = sqlalchemy.text(f"SELECT id FROM usuarios WHERE id = {id_usuario}")
    # ok: python-sql-concat
    cur.execute("SELECT id, nombre FROM usuarios WHERE id = %s", (id_usuario,))
    return consulta


def deserializar(carga):
    # ruleid: python-pickle-load
    objeto = pickle.loads(carga)
    # ok: python-pickle-load
    datos = json.loads(carga)
    return objeto, datos


def leer_token(token_crudo, clave):
    # ruleid: python-jwt-no-verify
    reclamos = jwt.decode(token_crudo, options={"verify_signature": False})
    # ruleid: python-jwt-no-verify
    cabecera = jwt.get_unverified_header(token_crudo)
    # ok: python-jwt-no-verify
    validos = jwt.decode(token_crudo, clave, algorithms=["HS256"])
    return reclamos, cabecera, validos


def resumen(datos):
    # ruleid: python-crypto-debil
    inseguro = hashlib.md5(datos)
    # ok: python-crypto-debil
    seguro = hashlib.sha256(datos)
    return inseguro, seguro


def generar_valores():
    # ruleid: python-random-inseguro
    token_reinicio = random.randint(100000, 999999)
    # ok: python-random-inseguro
    espera = random.uniform(0.5, 1.5)
    return token_reinicio, espera


def consultar(url):
    # ruleid: python-tls-verify-off
    respuesta = requests.get(url, verify=False)
    # ok: python-tls-verify-off
    segura = requests.get(url, timeout=5)
    return respuesta, segura


def analizar_xml(ruta):
    # ruleid: python-xxe
    arbol = xml.etree.ElementTree.parse(ruta)
    # ok: python-xxe
    arbol_seguro = defusedxml.ElementTree.parse(ruta)
    return arbol, arbol_seguro


def extraer(zf, destino, miembro):
    # ruleid: python-zip-slip
    zf.extractall(destino)
    # ok: python-zip-slip
    zf.extract(miembro, destino)


def arrancar(app):
    # ruleid: python-debug-en-prod
    app.run(host="127.0.0.1", debug=True)
    # ok: python-debug-en-prod
    app.run(host="127.0.0.1", port=8000)


def proxy_abierto():
    url_destino = request.args.get("url")
    # ruleid: python-ssrf
    return requests.get(url_destino, timeout=5)


def estado_interno():
    # ok: python-ssrf
    return requests.get("https://api.interna.ejemplo.com/estado", timeout=5)


def credenciales():
    # ruleid: hardcoded-credential-generico
    db_password = "hunter2hunter2"
    # ok: hardcoded-credential-generico
    nombre_password_env = "APP_DB_PASSWORD"
    return db_password, nombre_password_env
