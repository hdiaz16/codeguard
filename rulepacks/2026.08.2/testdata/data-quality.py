# Fixture de semgrep --test — no es código del producto.


def cargar_clientes(pedidos):
    resultados = []
    for pedido in pedidos:
        # ruleid: python-orm-en-bucle
        cliente = Cliente.objects.get(id=pedido.cliente_id)
        resultados.append(cliente)
    return resultados


def cargar_clientes_en_lote(ids):
    # ok: python-orm-en-bucle
    return Cliente.objects.filter(id__in=ids)


def guardar_configuracion(ruta, datos):
    # ruleid: python-except-pass
    try:
        escribir_archivo(ruta, datos)
    except OSError:
        pass


def guardar_todo(ruta, datos):
    # ruleid: python-except-pass
    try:
        escribir_archivo(ruta, datos)
    except:
        pass


def guardar_con_alias(ruta, datos):
    # ruleid: python-except-pass
    try:
        escribir_archivo(ruta, datos)
    except OSError as exc:
        pass


def guardar_configuracion_bien(ruta, datos):
    # ok: python-except-pass
    try:
        escribir_archivo(ruta, datos)
    except OSError as exc:
        registrar_error(exc)
