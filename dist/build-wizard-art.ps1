# =============================================================================
# CodeGuard - arte del instalador (identidad MONTANA: pizarra, niebla, nieve)
# La escena de marca: una LUNA nitida (geometrica, con terminador de eclipse)
# saliendo sobre una cordillera con filo de nieve, bruma a la deriva.
# Nada de blobs difusos: esto es un paisaje alpino, no un chatbot.
#
#   wizard-banner.bmp    328x628  bienvenida/final (claro)
#   wizard-small.bmp     110x116  (el wizard la oculta; se genera por si acaso)
#   welcome-bg.bmp       500x360  fondo full-bleed de la bienvenida
#   splash\splash-NN.bmp 300x340  80 fotogramas: la luna SUBE, la bruma deriva,
#                                 el halo respira; entra de negro, sale a blanco
# =============================================================================
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$dist = $PSScriptRoot

# paleta MONTANA (cmd\daemon\frontend\widget.html)
$nieblaA   = @(142, 151, 158)   # #8e979e
$nieblaB   = @( 86,  95, 102)   # #565f66
$nieve     = @(230, 235, 239)   # #e6ebef
$pizarraBg = [System.Drawing.Color]::FromArgb(16, 18, 22)     # #101216
$pizarraBg2= [System.Drawing.Color]::FromArgb(23, 26, 31)     # #171a1f
$textoNieve= [System.Drawing.Color]::FromArgb(232, 237, 242)  # #e8edf2
$textoBruma= [System.Drawing.Color]::FromArgb(125, 133, 144)  # #7d8590
$claroB    = [System.Drawing.Color]::FromArgb(213, 220, 225)
$tintaOscura = [System.Drawing.Color]::FromArgb(34, 39, 44)
$brumaOscura = [System.Drawing.Color]::FromArgb(90, 101, 112)

function New-Grafico($bmp) {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    return $g
}

function Draw-FondoGrad($g, $w, $h, $cTop, $cBot) {
    $rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $cTop, $cBot, 90.0)
    $g.FillRectangle($grad, $rect)
    $grad.Dispose()
}

function Draw-Estrellas($g, $w, $h, $n, $semilla) {
    $rnd = New-Object System.Random($semilla)
    for ($i = 0; $i -lt $n; $i++) {
        $x = $rnd.Next(0, $w); $y = $rnd.Next(0, $h)
        $a = $rnd.Next(18, 55)
        $b = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb($a, 239, 243, 246))
        $s = if ($rnd.Next(0, 10) -gt 8) { 2 } else { 1 }
        $g.FillEllipse($b, $x, $y, $s, $s)
        $b.Dispose()
    }
}

# El orbe plasma (widget.html): blob organico que morphea con dos armonicos,
# nucleo de niebla y destello de nieve. $wob regula la deformacion.
function New-Blob($cx, $cy, $r, $fase, $w1, $w2) {
    $pts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
    for ($a = 0; $a -lt 360; $a += 6) {
        $t = $a * [math]::PI / 180
        $rr = $r * (1 + $w1 * [math]::Sin(3 * $t + $fase) + $w2 * [math]::Sin(5 * $t - 1.7 * $fase))
        $pts.Add([System.Drawing.PointF]::new($cx + $rr * [math]::Cos($t), $cy + $rr * [math]::Sin($t)))
    }
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddPolygon($pts.ToArray())
    return $path
}

function Draw-PlasmaOrb($g, $cx, $cy, $r, $fase, $alfaHalo, $wob) {
    foreach ($capa in @(@(2.3, 0.30), @(1.7, 0.55), @(1.3, 0.9))) {
        $rr = $r * $capa[0]
        $halo = New-Object System.Drawing.Drawing2D.GraphicsPath
        $halo.AddEllipse($cx - $rr, $cy - $rr, $rr * 2, $rr * 2)
        $hb = New-Object System.Drawing.Drawing2D.PathGradientBrush($halo)
        $hb.CenterColor = [System.Drawing.Color]::FromArgb([int]($alfaHalo * $capa[1]), $nieblaA[0], $nieblaA[1], $nieblaA[2])
        $hb.SurroundColors = @([System.Drawing.Color]::FromArgb(0, $nieblaA[0], $nieblaA[1], $nieblaA[2]))
        $g.FillEllipse($hb, $cx - $rr, $cy - $rr, $rr * 2, $rr * 2)
        $hb.Dispose(); $halo.Dispose()
    }

    $core = New-Blob $cx $cy $r $fase (0.05 * $wob) (0.03 * $wob)
    $rc = [System.Drawing.RectangleF]::new($cx - $r * 1.2, $cy - $r * 1.2, $r * 2.4, $r * 2.4)
    $gradCore = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rc,
        [System.Drawing.Color]::FromArgb(255, $nieblaA[0], $nieblaA[1], $nieblaA[2]),
        [System.Drawing.Color]::FromArgb(255, $nieblaB[0], $nieblaB[1], $nieblaB[2]),
        45.0)
    $g.FillPath($gradCore, $core)
    $gradCore.Dispose(); $core.Dispose()

    $spark = New-Blob ($cx - $r * 0.08) ($cy - $r * 0.1) ($r * 0.52) (-$fase) (0.07 * $wob) (0.04 * $wob)
    $sb = New-Object System.Drawing.Drawing2D.PathGradientBrush($spark)
    $sb.CenterPoint = [System.Drawing.PointF]::new($cx - $r * 0.12, $cy - $r * 0.15)
    $sb.CenterColor = [System.Drawing.Color]::FromArgb(215, 255, 255, 255)
    $sb.SurroundColors = @([System.Drawing.Color]::FromArgb(0, $nieve[0], $nieve[1], $nieve[2]))
    $g.FillPath($sb, $spark)
    $sb.Dispose(); $spark.Dispose()
}

# Cordillera triangulada. Cada capa: @(baseY, amp, freq, faseX, r, g, b, alfa,
# alfaNieve) - alfaNieve > 0 dibuja el filo de nieve sobre la cresta.
function tri($t) { $f = $t - [math]::Floor($t); return 1 - 2 * [math]::Abs($f - 0.5) }

function Draw-Cordillera($g, $w, $h, $capas) {
    foreach ($c in $capas) {
        $cresta = New-Object System.Collections.Generic.List[System.Drawing.PointF]
        for ($x = -2; $x -le $w + 2; $x += 4) {
            $y = $c[0] - $c[1] * (0.65 * (tri($x * $c[2] + $c[3])) + 0.35 * (tri($x * $c[2] * 2.6 + $c[3] * 1.7)))
            $cresta.Add([System.Drawing.PointF]::new($x, $y))
        }
        $pts = New-Object System.Collections.Generic.List[System.Drawing.PointF]
        $pts.Add([System.Drawing.PointF]::new(-2, $h + 2))
        $pts.AddRange($cresta)
        $pts.Add([System.Drawing.PointF]::new($w + 2, $h + 2))

        $b = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb($c[7], $c[4], $c[5], $c[6]))
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $path.AddPolygon($pts.ToArray())
        $g.FillPath($b, $path)
        $b.Dispose(); $path.Dispose()

        if ($c.Length -ge 9 -and $c[8] -gt 0) {
            $pluma = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb($c[8], $nieve[0], $nieve[1], $nieve[2]), 1.3)
            $g.DrawLines($pluma, $cresta.ToArray())
            $pluma.Dispose()
        }
    }
}

function Draw-Bruma($g, $w, $y, $drift, $alfa) {
    $rr = [System.Drawing.RectangleF]::new(-$w * 0.3 + $drift, $y - 14, $w * 1.6, 28)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddEllipse($rr)
    $hb = New-Object System.Drawing.Drawing2D.PathGradientBrush($path)
    $hb.CenterColor = [System.Drawing.Color]::FromArgb($alfa, $nieve[0], $nieve[1], $nieve[2])
    $hb.SurroundColors = @([System.Drawing.Color]::FromArgb(0, $nieve[0], $nieve[1], $nieve[2]))
    $g.FillPath($hb, $path)
    $hb.Dispose(); $path.Dispose()
}

$fmt = New-Object System.Drawing.StringFormat
$fmt.Alignment = [System.Drawing.StringAlignment]::Center
# acentos via [char]: PowerShell 5.1 lee .ps1 sin BOM como ANSI y los rompe
$lema = "si el commit pasa aqu$([char]0xED), pasa all$([char]0xE1)"
$marca = "C O D E G U A R D"

# ── banner 328x628 claro ─────────────────────────────────────────────────────
$W = 328; $H = 628
$bmp = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = New-Grafico $bmp
Draw-FondoGrad $g $W $H ([System.Drawing.Color]::White) $claroB
Draw-PlasmaOrb $g ($W / 2) ($H * 0.33) 56 0.9 70 0.55

$fMarca = New-Object System.Drawing.Font("Segoe UI Semibold", 15)
$bTinta = New-Object System.Drawing.SolidBrush($tintaOscura)
$g.DrawString($marca, $fMarca, $bTinta, [System.Drawing.RectangleF]::new(0, [single]($H * 0.52), [single]$W, 34), $fmt)
$fSub   = New-Object System.Drawing.Font("Segoe UI", 9.5)
$bBruma = New-Object System.Drawing.SolidBrush($brumaOscura)
$g.DrawString($lema, $fSub, $bBruma, [System.Drawing.RectangleF]::new(0, [single]($H * 0.52 + 38), [single]$W, 24), $fmt)

Draw-Cordillera $g $W $H @(
    @(($H - 34), 24, 0.012, 0.5, 90, 101, 112, 26, 0),
    @(($H - 14), 17, 0.019, 2.2, 90, 101, 112, 38, 0)
)
$g.Dispose()
$bmp.Save((Join-Path $dist "wizard-banner.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp)
$bmp.Dispose()

# ── emblema 110x116 (el wizard lo oculta; queda por compatibilidad) ──────────
$W = 110; $H = 116
$bmp = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = New-Grafico $bmp
$blanco = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$g.FillRectangle($blanco, 0, 0, $W, $H)
$blanco.Dispose()
Draw-PlasmaOrb $g ($W / 2) ($H / 2) 26 0.9 45 0.4
$g.Dispose()
$bmp.Save((Join-Path $dist "wizard-small.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp)
$bmp.Dispose()

# ── fondo full-bleed de la bienvenida (texto va en etiquetas nativas) ────────
$W = 500; $H = 360
$bmp = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = New-Grafico $bmp
$blanco = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$g.FillRectangle($blanco, 0, 0, $W, $H)
$blanco.Dispose()
Draw-PlasmaOrb $g ($W / 2) 100 42 0.9 55 0.45
Draw-Cordillera $g $W $H @(
    @(($H - 12), 16, 0.010, 0.8, 90, 101, 112, 16, 0),
    @(($H - 2), 12, 0.017, 2.9, 90, 101, 112, 24, 0)
)
$g.Dispose()
$bmp.Save((Join-Path $dist "welcome-bg.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp)
$bmp.Dispose()

# ── splash: 80 fotogramas 300x340 a ~25 fps (~3.2 s) ─────────────────────────
# La luna SUBE lentamente sobre la cordillera, el halo respira y la bruma
# deriva. 0-9 entra de negro · 68-79 funde a blanco (el color del asistente).
$splashDir = Join-Path $dist "splash"
if (Test-Path $splashDir) { Remove-Item $splashDir -Recurse -Force }
New-Item -ItemType Directory -Force $splashDir | Out-Null

$W = 300; $H = 340; $TOTAL = 80
$fTit  = New-Object System.Drawing.Font("Segoe UI Semibold", 13)
$fLema = New-Object System.Drawing.Font("Segoe UI", 8.5)
$bNieve = New-Object System.Drawing.SolidBrush($textoNieve)
$bBrumaS = New-Object System.Drawing.SolidBrush($textoBruma)

for ($i = 0; $i -lt $TOTAL; $i++) {
    $bmp = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $g = New-Grafico $bmp
    Draw-FondoGrad $g $W $H $pizarraBg $pizarraBg2
    Draw-Estrellas $g $W $H 26 7

    $cy = 124 - $i * 0.16                                  # el orbe asciende
    $halo = 95 + 25 * [math]::Sin($i * 0.12)               # el halo respira
    $fase = 0.42 * $i                                      # morph sereno
    $r = 48 * (1 + 0.045 * [math]::Sin($i * 0.14))         # respiracion
    Draw-PlasmaOrb $g ($W / 2) $cy $r $fase $halo 0.6

    Draw-Cordillera $g $W $H @(
        @(310, 26, 0.012, 0.3, 42, 48, 58, 255, 55),
        @(326, 22, 0.017, 1.9, 28, 33, 41, 255, 32),
        @(342, 16, 0.023, 4.1, 18, 21, 27, 255, 0)
    )
    Draw-Bruma $g $W 302 (20 * [math]::Sin($i * 0.09)) 26
    Draw-Bruma $g $W 318 (-14 * [math]::Sin($i * 0.07 + 1.2)) 18

    $g.DrawString($marca, $fTit, $bNieve, [System.Drawing.RectangleF]::new(0, 202, [single]$W, 30), $fmt)
    $g.DrawString($lema, $fLema, $bBrumaS, [System.Drawing.RectangleF]::new(0, 238, [single]$W, 20), $fmt)

    if ($i -lt 10) {
        $a = [int](255 * (1 - $i / 9.0))
        $velo = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb($a, 6, 8, 10))
        $g.FillRectangle($velo, 0, 0, $W, $H); $velo.Dispose()
    } elseif ($i -ge 68) {
        $a = [int](255 * (($i - 67) / 12.0)); if ($a -gt 255) { $a = 255 }
        $velo = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb($a, 255, 255, 255))
        $g.FillRectangle($velo, 0, 0, $W, $H); $velo.Dispose()
    }

    $g.Dispose()
    $bmp.Save((Join-Path $splashDir ("splash-{0:d2}.bmp" -f $i)), [System.Drawing.Imaging.ImageFormat]::Bmp)
    $bmp.Dispose()
}

$fMarca.Dispose(); $fSub.Dispose(); $fTit.Dispose(); $fLema.Dispose()
$bTinta.Dispose(); $bBruma.Dispose(); $bNieve.Dispose(); $bBrumaS.Dispose(); $fmt.Dispose()
Write-Host "arte MONTANA v2: luna nitida, crestas con nieve y $TOTAL fotogramas" -ForegroundColor Green
