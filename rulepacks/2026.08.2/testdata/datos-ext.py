# Fixture de semgrep --test — no es código del producto.
# Casos de prueba del pilar datos (stem datos-ext), lenguaje Python.
from datetime import datetime, timezone


# --- fixtures-datos-reales (regla generic, se prueba en este archivo) ----------
# ruleid: fixtures-datos-reales
CORREO_SEMILLA = "laura.mtz@dominioreal.com"
# ok: fixtures-datos-reales
CORREO_PRUEBA = "laura.mtz@example.com"


# --- python-dinero-float --------------------------------------------------------
def convertir_importes(fila):
    # ruleid: python-dinero-float
    precio_unitario = float(fila["precio"])
    # ok: python-dinero-float
    latitud = float(fila["latitud"])
    return precio_unitario, latitud


# --- python-datetime-naive ------------------------------------------------------
def marcar_tiempos():
    # ruleid: python-datetime-naive
    creado = datetime.now()
    # ok: python-datetime-naive
    actualizado = datetime.now(timezone.utc)
    return creado, actualizado


# --- log-dato-sensible ------------------------------------------------------------
def registrar_acceso(logger, usuario, password):
    # ruleid: log-dato-sensible
    logger.info("intento fallido", password)
    # ok: log-dato-sensible
    logger.info("acceso correcto", usuario.id)


# --- pii-en-telemetria-py ---------------------------------------------------------
def identificar_sesion(sentry_sdk, analytics, correo, plan):
    # ruleid: pii-en-telemetria-py
    sentry_sdk.set_user({"email": correo})
    # ruleid: pii-en-telemetria-py
    analytics.track("alta", {"telefono_contacto": correo})
    # ok: pii-en-telemetria-py
    analytics.track("alta", {"plan": plan})


# --- pii-en-url ------------------------------------------------------------------------
def construir_urls(correo, uid):
    # ruleid: pii-en-url
    busqueda = f"https://interno.example/usuarios?email={correo}"
    # ok: pii-en-url
    ficha = f"https://interno.example/usuarios?id={uid}"
    return busqueda, ficha


# --- escrituras-sin-transaccion -----------------------------------------------------
def guardar_pedido(repo, pedido, reserva):
    # ruleid: escrituras-sin-transaccion
    repo.save(pedido)
    repo.delete(reserva)


def guardar_pedido_atomico(store, transaction, pedido, reserva):
    with transaction.atomic():
        # ok: escrituras-sin-transaccion
        store.save(pedido)
        store.delete(reserva)


# --- sql-truncate-o-drop -----------------------------------------------------------
def limpiar_sesiones(cursor):
    # ruleid: sql-truncate-o-drop
    cursor.execute("TRUNCATE TABLE sesiones_caducadas")
    # ok: sql-truncate-o-drop
    cursor.execute("DELETE FROM sesiones_caducadas WHERE edad_dias > 30")
