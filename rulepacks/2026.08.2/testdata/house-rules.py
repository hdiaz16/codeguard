# Fixture de semgrep --test — no es código del producto.
import ast

def procesar(entrada):
    # ruleid: python-eval
    return eval(entrada)

def procesar_seguro(entrada):
    # ok: python-eval
    return ast.literal_eval(entrada)
