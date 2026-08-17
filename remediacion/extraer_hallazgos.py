# Extrae los 461 hallazgos del HTML de la auditoría a JSON y Markdown.
import json
import re
import html as h
from pathlib import Path

SRC = Path(r"C:\Users\Hector Diaz\.claude\projects\C--Users-Hector-Diaz-Desktop-codeguard\eb519b2d-6df5-4f0d-babd-c88624ed3606\tool-results\artifact-affc9e7e-1786749210-9cf3.html")
OUT_DIR = Path(r"C:\Users\Hector Diaz\Desktop\codeguard\remediacion")

texto = SRC.read_text(encoding="utf-8")

patron = re.compile(
    r'<details class="f" data-sev="(?P<sev>[^"]+)" data-cat="(?P<cat>[^"]+)">'
    r'<summary>.*?<span class="ref">(?P<ref>[^<]+)</span>'
    r'<span class="tit">(?P<tit>.*?)</span>'
    r'<span class="cat">[^<]*</span></summary>'
    r'<div class="cuerpo"><p>(?P<desc>.*?)</p>'
    r'(?:<p class="rec"><strong>Recomendaci\xf3n:</strong>\s*(?P<rec>.*?)</p>)?'
    r'</div></details>',
    re.DOTALL,
)

def limpiar(s):
    if s is None:
        return ""
    s = re.sub(r"<[^>]+>", "", s)
    return h.unescape(s).strip()

hallazgos = []
for i, m in enumerate(patron.finditer(texto), 1):
    ref = limpiar(m.group("ref"))
    archivo, _, linea = ref.rpartition(":")
    hallazgos.append({
        "id": f"H{i:03d}",
        "severidad": m.group("sev"),
        "categoria": m.group("cat"),
        "archivo": archivo or ref,
        "linea": int(linea) if linea.isdigit() else None,
        "titulo": limpiar(m.group("tit")),
        "descripcion": limpiar(m.group("desc")),
        "recomendacion": limpiar(m.group("rec")),
        "estado": "pendiente",  # pendiente | confirmado | descartado | corregido | validado
        "veredicto_validacion": "",
    })

OUT_DIR.mkdir(exist_ok=True)
(OUT_DIR / "hallazgos.json").write_text(
    json.dumps(hallazgos, ensure_ascii=False, indent=1), encoding="utf-8")

# Resumen por severidad y categoría
from collections import Counter
sev = Counter(x["severidad"] for x in hallazgos)
cat = Counter(x["categoria"] for x in hallazgos)
arch = Counter(x["archivo"] for x in hallazgos)
print(f"total={len(hallazgos)}")
print("severidad:", dict(sev))
print("categoria:", dict(cat))
print("top archivos:", arch.most_common(10))
