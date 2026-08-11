# Fixture de semgrep --test — no es código del producto.
# Casos de prueba del pilar calidad (stem calidad-ext), lenguaje Python.
import pytest


def calcular():
    return 7


def abrir(ruta):
    return open(ruta)


def registrar(mensaje):
    return mensaje


# --- python-except-broad -----------------------------------------------------
def cargar(ruta):
    # ruleid: python-except-broad
    try:
        return abrir(ruta)
    except Exception:
        return None


def cargar_con_traza(ruta):
    # ok: python-except-broad
    try:
        return abrir(ruta)
    except Exception:
        registrar("fallo al cargar")
        raise


def cargar_tolerante(ruta):
    # ok: python-except-broad
    try:
        return abrir(ruta)
    except OSError:
        return None


# --- python-test-saltado -----------------------------------------------------
# ruleid: python-test-saltado
@pytest.mark.skip(reason="falla intermitente en el runner")
def test_pendiente():
    assert calcular() == 3


# ok: python-test-saltado
@pytest.mark.skip(reason="CG-777: reactivar tras migrar la base")
def test_documentado():
    assert calcular() == 5


# --- assert-siempre-verdadero-py ---------------------------------------------
def test_humo():
    # ruleid: assert-siempre-verdadero-py
    assert True


def test_real():
    # ok: assert-siempre-verdadero-py
    assert calcular() == 7


# --- parametros-excesivos-py -------------------------------------------------
# ruleid: parametros-excesivos-py
def crear_pedido(cliente, articulo, cantidad, destino, prioridad, canal):
    return (cliente, articulo, cantidad, destino, prioridad, canal)


# ok: parametros-excesivos-py
def crear_nota(cliente, articulo, cantidad):
    return (cliente, articulo, cantidad)


# --- anidamiento-profundo-py -------------------------------------------------
def revisar(a, b, c, d):
    # ruleid: anidamiento-profundo-py
    if a:
        if b:
            if c:
                if d:
                    return True
    return False


def revisar_plano(a, b, c):
    # ok: anidamiento-profundo-py
    if a:
        if b:
            if c:
                return True
    return False


# --- python-mutable-default --------------------------------------------------
# ruleid: python-mutable-default
def acumular(etiqueta, acumulado=[]):
    acumulado.append(etiqueta)
    return acumulado


# ok: python-mutable-default
def acumular_seguro(etiqueta, acumulado=None):
    if acumulado is None:
        acumulado = []
    acumulado.append(etiqueta)
    return acumulado


# --- todo-sin-ticket (regla generic, se prueba en este archivo) ---------------
# ruleid: todo-sin-ticket
# TODO: redondear con Decimal antes de sumar
UMBRAL = 10

# ok: todo-sin-ticket
# TODO(CG-123): mover el umbral a configuración
LIMITE = 20
