# Campaña de fuzz de los parsers de salida de herramientas externas (W6,
# defecto #2 de GPT: `go test ./...` NO fuzzea; hay que invocar cada FuzzXxx).
#
# El contrato que vigila: ningún parser hace panic ante entrada arbitraria. Un
# panic tumba el motor y con él la capa; una salida hostil no puede tener ese
# poder. Corre en NIGHTLY, no como gate de PR: el fuzzing no es determinista ni
# barato, y el gate de PR sí lo es (misma decisión del plan que los mutantes).
#
# Un crash deja su entrada en <pkg>/testdata/fuzz/<Fuzz>/<hash>: eso es una
# SEMILLA DE REGRESIÓN — `go test` la reproduce sin -fuzz. El job imprime esas
# semillas en el log (y Go además imprime el input y el comando de reproducción)
# para que un humano las commitee.
#Requires -Version 7
$ErrorActionPreference = 'Stop'

$tiempo = if ($env:FUZZTIME) { $env:FUZZTIME } else { '60s' }

# (paquete, objetivo). Cada FuzzXxx se corre por separado: go test -fuzz solo
# admite UN objetivo a la vez.
$objetivos = @(
  @{ pkg = './internal/engines/linters';     name = 'FuzzHallazgosESLint' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzHallazgosBiome' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzHallazgosMypy' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzHallazgosPMD' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzParseBanditJSON' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzParseGosecJSON' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzHallazgosDelJSONDeVet' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzHallazgosDelTextoDeVet' }
  @{ pkg = './internal/engines/linters';     name = 'FuzzDotnetVulnInterpretar' }
  @{ pkg = './internal/engines/staticcheck'; name = 'FuzzInterpretar' }
  @{ pkg = './internal/engines/govulncheck'; name = 'FuzzInterpretar' }
)

$fallos = @()
foreach ($o in $objetivos) {
  Write-Host "== fuzz $($o.name) en $($o.pkg) ($tiempo) =="
  & go test $o.pkg '-run=^$' "-fuzz=^$($o.name)$" "-fuzztime=$tiempo"
  if ($LASTEXITCODE -ne 0) { $fallos += "$($o.pkg)::$($o.name)" }
}

if ($fallos.Count -gt 0) {
  Write-Host "== SEMILLAS DE CRASH (commitéalas como regresión) =="
  Get-ChildItem -Recurse -File -Path (Join-Path (Get-Location) 'internal') |
    Where-Object { $_.FullName -match 'testdata[\\/]+fuzz[\\/]' } |
    ForEach-Object {
      Write-Host "--- $($_.FullName) ---"
      Get-Content -Raw $_.FullName
    }
  throw "fuzz encontró crashes en: $($fallos -join ', ')"
}
Write-Host "fuzz: sin crashes en $($objetivos.Count) objetivo(s)"
