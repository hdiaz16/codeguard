# Fixture de semgrep --test — no es código del producto.


def buscar_usuarios(nombre):
    # ruleid: orm-raw-interpolado
    return Usuario.objects.raw(f"SELECT id FROM app_usuario WHERE nombre = '{nombre}'")


def buscar_usuarios_bien(uid):
    # ok: orm-raw-interpolado
    return Usuario.objects.raw("SELECT id FROM app_usuario WHERE id = %s", [uid])


def establecer_sesion(resp, token):
    # ruleid: cookie-sin-httponly-python
    resp.set_cookie("sesion", token)
    return resp


def establecer_sesion_bien(resp, token):
    # ok: cookie-sin-httponly-python
    resp.set_cookie("sesion", token, httponly=True, secure=True, samesite="Lax")
    return resp
