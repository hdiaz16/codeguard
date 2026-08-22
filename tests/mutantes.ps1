# Mutación curada: cada mutante de la lista DEBE morir (su test se pone rojo
# con la mutación aplicada). Un mutante que sobrevive significa que el test que
# protege ese invariante ya no lo protege — y eso es un defecto del test, no
# del mutante.
#
# Decisión del plan (remediacion/PLAN-CALIDAD-MUNDIAL.md, punto 7 firmado):
# esto corre en NIGHTLY, no como gate de PR. El gate de PR es determinista;
# la campaña de mutantes es la vigilancia de fondo.
#
# La lista vive en tests/mutantes.json: {id, porque, archivo, busca, reemplaza,
# paquete, test}. `busca` debe aparecer EXACTAMENTE UNA vez en el archivo: si
# el código cambió y ya no aparece (o aparece dos veces), el mutante se reporta
# como DESACTUALIZADO y el job falla — un mutante rancio vigila a nadie.
#Requires -Version 7
# (PS 5.1 escribiría los archivos revertidos con BOM y los rompería en silencio;
# pwsh 7 usa UTF-8 sin BOM por defecto, que es lo que el repo espera.)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$mutantes = Get-Content tests/mutantes.json -Raw | ConvertFrom-Json
$fallos = 0

foreach ($m in $mutantes) {
    $original = Get-Content $m.archivo -Raw
    $partes = $original -split [regex]::Escape($m.busca)
    if ($partes.Count -ne 2) {
        Write-Host "DESACTUALIZADO: $($m.id) — 'busca' aparece $($partes.Count - 1) veces en $($m.archivo); actualiza el mutante"
        $fallos++
        continue
    }
    Write-Host "aplicando: $($m.id)"
    try {
        Set-Content -NoNewline -Path $m.archivo -Value ($original.Replace($m.busca, $m.reemplaza))
        & go test $m.paquete -run $m.test -count=1 2>&1 | Out-Null
        $codigo = $LASTEXITCODE
    }
    finally {
        Set-Content -NoNewline -Path $m.archivo -Value $original
    }
    if ($codigo -eq 0) {
        Write-Host "SOBREVIVIO: $($m.id) — $($m.test) no caza la mutacion. $($m.porque)"
        $fallos++
    }
    else {
        Write-Host "  muerto: $($m.id) (el test lo cazo)"
    }
}

# El árbol tiene que quedar exactamente como estaba.
& go build ./... 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "::error::el arbol quedo roto tras revertir los mutantes"
    exit 2
}
$sucio = git status --porcelain
if ($sucio) {
    Write-Host "::error::quedaron archivos modificados tras revertir:`n$sucio"
    exit 2
}

if ($fallos -gt 0) {
    Write-Host "$fallos mutante(s) sobrevivieron o estan desactualizados"
    exit 1
}
Write-Host "todos los mutantes murieron: los invariantes siguen vigilados"
