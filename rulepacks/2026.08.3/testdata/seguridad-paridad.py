# Fixture de semgrep --test — no es código del producto.
# Casos positivos (ruleid) y negativos (ok) de seguridad-paridad.yaml (python).

import bleach
from flask import render_template_string
from markupsafe import Markup

from django.utils.safestring import mark_safe


def render(datos_del_usuario, plantilla_del_usuario):
    # ruleid: python-xss
    a = mark_safe(datos_del_usuario)
    # ruleid: python-xss
    b = Markup(datos_del_usuario)
    # ruleid: python-xss
    c = render_template_string(plantilla_del_usuario, x=1)
    return a, b, c


def render_seguro(datos_del_usuario):
    # ok: python-xss
    a = mark_safe("<b>texto fijo del programador</b>")
    # ok: python-xss
    b = Markup("<i>tambien fijo</i>")
    # ok: python-xss
    c = mark_safe(bleach.clean(datos_del_usuario))
    # ok: python-xss
    d = render_template_string("<p>{{ x }}</p>", x=datos_del_usuario)
    return a, b, c, d
