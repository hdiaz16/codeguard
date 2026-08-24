# Corpus de pruebas del rulepack

Cada regla del pack demuestra aquí que caza lo que promete — y que no caza lo
que no. `--validate` (el otro paso del CI) sólo prueba que las reglas
*compilan*; cinco reglas vivieron muertas meses porque nada probaba que
*funcionaran*. Este corpus es ese candado.

## Convenciones

- Un archivo por (archivo de reglas × lenguaje), con el **mismo stem**:
  las reglas de `semgrep/seguridad-ext.yaml` se prueban en
  `testdata/seguridad-ext.py`, `testdata/seguridad-ext.go`, etc. Así es como
  `semgrep --test` asocia pruebas con reglas.
- La anotación va en un comentario **inmediatamente encima** de la línea:
  `# ruleid: <id>` = esta línea DEBE matchear; `# ok: <id>` = esta NO debe.
  Toda regla necesita al menos un `ruleid:` y un `ok:` — el CI exige que
  ninguna regla viva sin caso positivo.
- Los fixtures son código deliberadamente malo pero **sintácticamente
  válido** (semgrep tiene que poder parsearlos), con comentarios en español.
- **Nada con formato de secreto real**: gitleaks corre fail-closed sobre cada
  commit de este repo y no admite baseline. `Password=changeme` matchea los
  patrones igual que uno de verdad.

## Por qué este directorio y no otro

- Vive **junto a** `semgrep/`, no dentro: el motor pasa `semgrep/` completo
  como `--config`, y un fixture `.yaml` ahí dentro se parsearía como REGLAS.
- Se llama `testdata` para que el toolchain de Go ignore los `.go` de aquí
  (no compilan como parte del módulo, ni falta que hace).
- No viaja en el instalador: `build-dist.ps1` lo poda del paquete.

## Correr en local

```powershell
$env:PYTHONUTF8 = "1"   # sin esto, los acentos tumban a semgrep en Windows
semgrep scan --test --config rulepacks/2026.08.2/semgrep rulepacks/2026.08.2/testdata --metrics=off --disable-version-check
```

Ojo: `--config` con un archivo suelto (en vez del directorio) revienta con
`IndexError: tuple index out of range` — bug de semgrep, usa el directorio.
