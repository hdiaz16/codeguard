package linters

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// raizCaptura es el directorio donde vivían los proyectos de juguete con los
// que se capturaron las salidas de abajo (SDK 10.0.204). Hace de raíz del repo
// en los tests: MSBuild reporta paths absolutos y canonizados —aunque el
// directorio de trabajo se le pase con alias 8.3— así que recortarlos contra
// esta base es exactamente el trabajo que hace dnbRelativizar en producción.
const raizCaptura = `C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad`

// Capturado con `dotnet build --no-restore --nologo -v quiet -clp:NoSummary
// -t:Rebuild ...` sobre un proyecto con un `return a + b` sin punto y coma.
// Tal cual, incluido el resumen: -clp:NoSummary NO lo suprime en `dotnet build`
// y el error aparece DOS VECES.
const capturaErrorCompilador = `C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj\Roto.cs(7,21): error CS1002: ; expected [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj\ErrProj.csproj]

Build FAILED.

C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj\Roto.cs(7,21): error CS1002: ; expected [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj\ErrProj.csproj]
    0 Warning(s)
    1 Error(s)

Time Elapsed 00:00:05.31
`

// Capturado sobre un proyecto con AnalysisMode=All y EnforceCodeStyleInBuild:
// una variable asignada y no usada (CS0219 del compilador) y cuatro avisos de
// los analizadores Roslyn, uno de ellos en un subdirectorio. Con el resumen
// repitiendo las cinco líneas, como arriba.
const capturaAvisosAnalizadores = `C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(7,13): warning CS0219: The variable 'sinUsar' is assigned but its value is never used [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(8,9): warning CA1806: Saludo calls Trim but does not use the new string instance that the method returns. Pass the instance as an argument to another method, assign the instance to a variable, or remove the call if it is unnecessary. (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1806) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Servicios\Otro.cs(5,17): warning CA1822: Member 'Hacer' does not access instance data and can be marked as static (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1822) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(8,9): warning CA1062: In externally visible method 'string Avisos.Saludo(string nombre)', validate parameter 'nombre' is non-null before using it. If appropriate, throw an 'ArgumentNullException' when the argument is 'null'. (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1062) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(5,19): warning CA1822: Member 'Saludo' does not access instance data and can be marked as static (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1822) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]

Build succeeded.

C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(7,13): warning CS0219: The variable 'sinUsar' is assigned but its value is never used [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(8,9): warning CA1806: Saludo calls Trim but does not use the new string instance that the method returns. Pass the instance as an argument to another method, assign the instance to a variable, or remove the call if it is unnecessary. (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1806) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Servicios\Otro.cs(5,17): warning CA1822: Member 'Hacer' does not access instance data and can be marked as static (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1822) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(8,9): warning CA1062: In externally visible method 'string Avisos.Saludo(string nombre)', validate parameter 'nombre' is non-null before using it. If appropriate, throw an 'ArgumentNullException' when the argument is 'null'. (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1062) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\Avisos.cs(5,19): warning CA1822: Member 'Saludo' does not access instance data and can be marked as static (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1822) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\warnproj\WarnProj.csproj]
    5 Warning(s)
    0 Error(s)

Time Elapsed 00:00:04.77
`

// Capturado borrando obj/ y compilando con --no-restore: el código es
// NETSDK1004 (no el NETSDK1064 que se suponía), el path del "archivo" es un
// .targets del SDK y el mensaje nombra project.assets.json. El proyecto puede
// estar perfecto o estar roto: desde aquí NO SE SABE, y eso es lo que hay que
// decir.
const capturaSinRestore = `C:\Program Files\dotnet\sdk\10.0.204\Sdks\Microsoft.NET.Sdk\targets\Microsoft.PackageDependencyResolution.targets(266,5): error NETSDK1004: Assets file 'C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj_norestore\obj\project.assets.json' not found. Run a NuGet package restore to generate this file. [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj_norestore\ErrProj.csproj]

Build FAILED.

C:\Program Files\dotnet\sdk\10.0.204\Sdks\Microsoft.NET.Sdk\targets\Microsoft.PackageDependencyResolution.targets(266,5): error NETSDK1004: Assets file 'C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj_norestore\obj\project.assets.json' not found. Run a NuGet package restore to generate this file. [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\errproj_norestore\ErrProj.csproj]
    0 Warning(s)
    1 Error(s)

Time Elapsed 00:00:00.52
`

// Capturado sobre <TargetFrameworks>net9.0;net10.0</TargetFrameworks>: los DOS
// avisos llegan una vez por framework, con el sufijo
// "MultiTfm.csproj::TargetFramework=net9.0". Son dos posiciones del código, no
// cuatro hallazgos.
const capturaMultiTarget = `C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\Doble.cs(7,13): warning CS0219: The variable 'sinUsar' is assigned but its value is never used [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\MultiTfm.csproj::TargetFramework=net10.0]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\Doble.cs(5,16): warning CA1822: Member 'Sumar' does not access instance data and can be marked as static (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1822) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\MultiTfm.csproj::TargetFramework=net10.0]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\Doble.cs(7,13): warning CS0219: The variable 'sinUsar' is assigned but its value is never used [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\MultiTfm.csproj::TargetFramework=net9.0]
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\Doble.cs(5,16): warning CA1822: Member 'Sumar' does not access instance data and can be marked as static (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1822) [C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\multitfm\MultiTfm.csproj::TargetFramework=net9.0]

Build succeeded.
    4 Warning(s)
    0 Error(s)

Time Elapsed 00:00:04.44
`

// Capturado sobre el proyecto con Newtonsoft.Json 9.0.1: los diagnósticos DEL
// PROYECTO no traen (línea,columna) sino " : warning NUxxxx:". Los NU190x son
// los avisos de vulnerabilidad de NuGet, que reporta DotnetVuln con el GHSA y
// la severidad real.
const capturaDiagnosticosDeProyecto = `C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\vulnproj\VulnProj.csproj : warning NU1510: PackageReference System.Text.Encodings.Web will not be pruned. Consider removing this package from your dependencies, as it is likely unnecessary.
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\vulnproj\VulnProj.csproj : warning NU1903: Package 'Newtonsoft.Json' 9.0.1 has a known high severity vulnerability, https://github.com/advisories/GHSA-5crp-9r3c-p9vr
C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\vulnproj\VulnProj.csproj : warning NU1904: Package 'System.Text.Encodings.Web' 4.5.0 has a known critical severity vulnerability, https://github.com/advisories/GHSA-ghhp-997w-qr28

Build succeeded.
    3 Warning(s)
    0 Error(s)

Time Elapsed 00:00:01.19
`

func TestErrorDeCompiladorBloqueaYSeRelativiza(t *testing.T) {
	diags := dnbParsear(capturaErrorCompilador)
	// El resumen de MSBuild repite el error: si esto sale 2, cada compilación
	// fallida contaría el doble de bloqueantes.
	if len(diags) != 1 {
		t.Fatalf("esperaba 1 diagnóstico (el resumen repite el mismo), hay %d: %+v", len(diags), diags)
	}
	fs := dnbTraducir(diags, []string{raizCaptura})
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, hay %d", len(fs))
	}
	f := fs[0]
	if f.RuleKey != "CS1002" {
		t.Errorf("RuleKey = %q, esperaba CS1002", f.RuleKey)
	}
	if f.Severity != finding.Error || !f.Blocking {
		t.Errorf("severidad/bloqueo = %v/%v, esperaba error+bloqueante (§7: la compilación es compuerta)", f.Severity, f.Blocking)
	}
	if f.File != "errproj/Roto.cs" || f.Line != 7 {
		t.Errorf("posición = %s:%d, esperaba errproj/Roto.cs:7", f.File, f.Line)
	}
	if f.Message != "; expected" {
		t.Errorf("mensaje = %q, esperaba %q (el sufijo [proyecto] no es parte del mensaje)", f.Message, "; expected")
	}
	if f.Pillar != finding.Quality || f.Source != finding.Deterministic || !f.Verified {
		t.Errorf("pilar/fuente = %v/%v, verificado=%v", f.Pillar, f.Source, f.Verified)
	}
	if !strings.Contains(f.Why, "CI") {
		t.Errorf("el porqué debe decir que el CI lo rechazará igual: %q", f.Why)
	}
}

func TestAvisosDeAnalizadoresNoBloquean(t *testing.T) {
	diags := dnbParsear(capturaAvisosAnalizadores)
	if len(diags) != 5 {
		t.Fatalf("esperaba 5 diagnósticos, hay %d: %+v", len(diags), diags)
	}
	fs := dnbTraducir(diags, []string{raizCaptura})
	if len(fs) != 5 {
		t.Fatalf("esperaba 5 hallazgos, hay %d", len(fs))
	}
	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		if f.Severity != finding.Warning || f.Blocking {
			t.Errorf("%s: severidad/bloqueo = %v/%v, esperaba aviso no bloqueante (sin -warnaserror)", f.RuleKey, f.Severity, f.Blocking)
		}
		porRegla[f.RuleKey] = f
	}
	for _, esperada := range []string{"CS0219", "CA1806", "CA1822", "CA1062"} {
		if _, ok := porRegla[esperada]; !ok {
			t.Errorf("falta el hallazgo de %s; reglas vistas: %v", esperada, porRegla)
		}
	}
	// El aviso del subdirectorio prueba que el recorte conserva la ruta interna.
	var enSubdir bool
	for _, f := range fs {
		if f.File == "warnproj/Servicios/Otro.cs" {
			enSubdir = true
		}
	}
	if !enSubdir {
		t.Error("el aviso de Servicios/Otro.cs debe conservar el subdirectorio")
	}
	if pista := porRegla["CA1806"].FixHint; !strings.Contains(pista, "quality-rules/ca1806") {
		t.Errorf("la pista de un CA debe llevar a su ficha: %q", pista)
	}
	if pista := porRegla["CS0219"].FixHint; strings.Contains(pista, "quality-rules") {
		t.Errorf("CS0219 es del compilador, no una regla CA: %q", pista)
	}
}

// El caso que da sentido al motor: sin restore MSBuild devuelve un error que no
// habla del código. Reportarlo como hallazgo sería inventar un problema; peor
// aún sería devolver cero hallazgos y dejar creer que el proyecto está limpio.
func TestSinRestoreSeDegradaSinInventarHallazgos(t *testing.T) {
	diags := dnbParsear(capturaSinRestore)
	fatal := dnbFatal(diags)
	if fatal == nil {
		t.Fatal("NETSDK1004 debe reconocerse como análisis imposible, no como hallazgo")
	}
	if fatal.Codigo != "NETSDK1004" {
		t.Errorf("código fatal = %q, esperaba NETSDK1004", fatal.Codigo)
	}
	remedio := dnbRemedio(fatal.Codigo)
	if !strings.Contains(remedio, "dotnet restore") {
		t.Errorf("el remedio tiene que decir qué hacer: %q", remedio)
	}
	if !strings.Contains(remedio, "--no-restore") {
		t.Errorf("el remedio debe explicar por qué el hook usa --no-restore: %q", remedio)
	}
	// Y la red por debajo de la lista de códigos: el nombre del archivo no se
	// traduce, así que un código nuevo para el mismo hueco sigue cazándose.
	soloTexto := []dnbDiag{{
		Nivel: "error", Codigo: "NETSDK9999",
		Mensaje: "Assets file 'C:\\x\\obj\\project.assets.json' not found.",
	}}
	if dnbFatal(soloTexto) == nil {
		t.Error("un código desconocido que nombra project.assets.json también es análisis imposible")
	}
	// Un error de compilación de verdad NO es fatal: es el hallazgo bloqueante.
	if dnbFatal(dnbParsear(capturaErrorCompilador)) != nil {
		t.Error("CS1002 es un hallazgo, no una degradación")
	}
}

func TestMultiTargetNoDuplicaElMismoAviso(t *testing.T) {
	fs := dnbTraducir(dnbParsear(capturaMultiTarget), []string{raizCaptura})
	if len(fs) != 2 {
		t.Fatalf("esperaba 2 hallazgos (una posición del código = un hallazgo, aunque haya dos TFM), hay %d: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.File != "multitfm/Doble.cs" {
			t.Errorf("archivo = %q, esperaba multitfm/Doble.cs", f.File)
		}
		if strings.Contains(f.Message, "TargetFramework=") {
			t.Errorf("el sufijo del proyecto no debe quedar en el mensaje: %q", f.Message)
		}
	}
}

func TestDiagnosticosDeProyectoYNU190xQueYaReportaDotnetVuln(t *testing.T) {
	diags := dnbParsear(capturaDiagnosticosDeProyecto)
	if len(diags) != 3 {
		t.Fatalf("esperaba 3 diagnósticos, hay %d: %+v", len(diags), diags)
	}
	fs := dnbTraducir(diags, []string{raizCaptura})
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo (NU1903/NU1904 los reporta dotnet-vuln), hay %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleKey != "NU1510" {
		t.Errorf("RuleKey = %q, esperaba NU1510", f.RuleKey)
	}
	// Sin (línea,columna): el diagnóstico es del proyecto entero.
	if f.File != "vulnproj/VulnProj.csproj" || f.Line != 1 {
		t.Errorf("posición = %s:%d, esperaba vulnproj/VulnProj.csproj:1", f.File, f.Line)
	}
}

// MSBuild canoniza los paths aunque el directorio de trabajo llegue con alias
// 8.3, así que hay que probar las dos formas de la raíz — la lección que dejó
// staticcheck, que hace justo lo contrario.
func TestRelativizarPruebaLasDosFormasDeLaRaiz(t *testing.T) {
	corto := `C:\Users\HECTOR~1.BOD\AppData\Local\Temp\claude\proy`
	largo := `C:\Users\hector.diaz.BODESA\AppData\Local\Temp\claude\proy`
	got := dnbRelativizar(largo+`\src\A.cs`, []string{corto, largo})
	if got != "src/A.cs" {
		t.Errorf("dnbRelativizar = %q, esperaba src/A.cs", got)
	}
	// Windows compara paths sin distinguir mayúsculas.
	got = dnbRelativizar(strings.ToUpper(largo)+`\SRC\A.CS`, []string{largo})
	if got != "SRC/A.CS" {
		t.Errorf("dnbRelativizar (mayúsculas) = %q, esperaba SRC/A.CS", got)
	}
	// Lo que no cuelga de la raíz —los .targets del SDK— se deja tal cual:
	// mejor un path raro que uno inventado.
	fuera := `C:\Program Files\dotnet\sdk\10.0.204\Sdks\x.targets`
	if got := dnbRelativizar(fuera, []string{largo}); got != filepath.ToSlash(fuera) {
		t.Errorf("dnbRelativizar fuera de la raíz = %q, esperaba %q", got, filepath.ToSlash(fuera))
	}
}

// El monorepo corporativo típico no tiene .csproj en la raíz sino en backend/;
// es el fallo que tsc arrastró durante meses con el tsconfig.json.
func TestProyectosEncuentraElCsprojMasCercano(t *testing.T) {
	root := t.TempDir()
	escribir := func(rel, contenido string) {
		t.Helper()
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("backend/Api/Api.csproj", "<Project/>")
	escribir("backend/Api/Controllers/Home.cs", "class H {}")
	escribir("backend/Core/Core.csproj", "<Project/>")
	escribir("backend/Core/Modelo.cs", "class M {}")
	escribir("scripts/suelto.cs", "class S {}") // sin .csproj arriba: nada que compilar
	escribir("backend/Api/obj/Debug/Api.AssemblyInfo.cs", "// generado")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/Api/Controllers/Home.cs", Status: "M"},
		{Path: "backend/Core/Modelo.cs", Status: "A"},
		{Path: "scripts/suelto.cs", Status: "M"},
		{Path: "backend/Api/obj/Debug/Api.AssemblyInfo.cs", Status: "M"},
		{Path: "frontend/src/app.ts", Status: "M"},
	}}
	got := DotnetBuild{}.proyectos(in)
	esperado := []string{"backend/Api/Api.csproj", "backend/Core/Core.csproj"}
	if len(got) != len(esperado) || got[0] != esperado[0] || got[1] != esperado[1] {
		t.Fatalf("proyectos = %v, esperaba %v (el .cs sin .csproj y el de obj/ no compilan nada)", got, esperado)
	}
	if !(DotnetBuild{}).Applies(in) {
		t.Fatal("con dos proyectos C# tocados, Applies debe ser verdadero")
	}
	// Un archivo borrado no obliga a compilar nada por sí solo.
	soloBorrado := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/Core/Modelo.cs", Status: "D"},
	}}
	if (DotnetBuild{}).Applies(soloBorrado) {
		t.Error("un .cs borrado no debe disparar la compilación")
	}
}

func TestCsprojEnLaRaizSigueFuncionando(t *testing.T) {
	root := t.TempDir()
	for rel, contenido := range map[string]string{"App.csproj": "<Project/>", "Program.cs": "class P {}"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{{Path: "Program.cs", Status: "M"}}}
	got := DotnetBuild{}.proyectos(in)
	if len(got) != 1 || got[0] != "App.csproj" {
		t.Fatalf("proyectos = %v, esperaba [App.csproj]", got)
	}
}

// Sin seguir los ProjectReference, un acierto de caché de Api escondería el
// error que Core acaba de introducir: dotnet build compila los dos.
func TestAmbitoSigueLosProjectReference(t *testing.T) {
	root := t.TempDir()
	escribir := func(rel, contenido string) {
		t.Helper()
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("backend/Api/Api.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\Core\Core.csproj" />
  </ItemGroup>
</Project>`)
	// Core referencia a Comun: la transitividad importa igual.
	escribir("backend/Core/Core.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\..\libs\Comun\Comun.csproj" />
  </ItemGroup>
</Project>`)
	escribir("libs/Comun/Comun.csproj", `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\..\backend\Api\Api.csproj" />
  </ItemGroup>
</Project>`) // ciclo: no debe colgar

	got := dnbAmbito(root, "backend/Api/Api.csproj")
	esperado := []string{"backend/Api/Api.csproj", "backend/Core/Core.csproj", "libs/Comun/Comun.csproj"}
	if len(got) != len(esperado) {
		t.Fatalf("ámbito = %v, esperaba %v", got, esperado)
	}
	for i := range esperado {
		if got[i] != esperado[i] {
			t.Fatalf("ámbito = %v, esperaba %v", got, esperado)
		}
	}
}

// ── integración con el dotnet real ──────────────────────────────────────────

func tfmInstalado(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("dotnet", "--version").Output()
	if err != nil {
		t.Skipf("no se pudo preguntar la versión del SDK: %v", err)
	}
	mayor := strings.SplitN(strings.TrimSpace(string(out)), ".", 2)[0]
	if mayor == "" {
		t.Skipf("versión de SDK ilegible: %q", out)
	}
	return "net" + mayor + ".0"
}

func proyectoCSDeJuguete(t *testing.T, cuerpo string) string {
	t.Helper()
	root := t.TempDir()
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Library</OutputType>
    <TargetFramework>` + tfmInstalado(t) + `</TargetFramework>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
  </PropertyGroup>
</Project>`
	if err := os.WriteFile(filepath.Join(root, "Juguete.csproj"), []byte(csproj), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Codigo.cs"), []byte(cuerpo), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// EL CONTROL DEL ARREGLO DEL SILENCIO, con el SDK de verdad.
//
// El motor pide silencio a MSBuild a propósito (`-v quiet -clp:NoSummary
// --nologo`), y medido con el SDK 8.0.300 un proyecto que compila devuelve código
// 0 y CERO bytes. Como no hay salida que examinar, ahora se exige la otra prueba
// de que compiló: el artefacto recién escrito en el directorio privado.
//
// Este test es el que impide que esa exigencia se vuelva un falso positivo. Si
// fuera falsa —porque el artefacto no vaya donde creo, o porque su fecha no sirva—
// TODOS los proyectos de C# que compilan limpios quedarían como capa degradada en
// cada commit. Y el test de integración que ya existía no lo cubre: su versión
// "buena" del código deja el aviso CS0219 a propósito, así que siempre pasa por el
// camino CON hallazgos. El proyecto sin NI UN diagnóstico no lo ejercitaba nadie.
func TestIntegracionUnProyectoCSLimpioNoSeDegrada(t *testing.T) {
	if testing.Short() {
		t.Skip("compila un proyecto de verdad: fuera del modo corto")
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		t.Skip("sin SDK de .NET en esta máquina")
	}
	// Sin variables sin usar y sin nada que los analizadores puedan comentar: la
	// salida de MSBuild tiene que quedar completamente vacía.
	root := proyectoCSDeJuguete(t, "public class Bien\n{\n    public int Sumar(int a, int b)\n"+
		"    {\n        return a + b;\n    }\n}\n")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	restore := exec.CommandContext(ctx, "dotnet", "restore")
	restore.Dir = root
	if out, err := restore.CombinedOutput(); err != nil {
		t.Skipf("dotnet restore no funcionó aquí (¿sin red?): %v\n%s", err, out)
	}

	fs, err := dnbCompilar(ctx, root, "Juguete.csproj")
	if err != nil {
		t.Fatalf("el proyecto compila sin un solo diagnóstico y el motor se declaró "+
			"incapaz. Con esto, todo proyecto de C# limpio queda como capa degradada "+
			"en cada commit: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("un proyecto limpio no tiene hallazgos, y salieron %d: %+v", len(fs), fs)
	}

	// Segunda corrida: el artefacto ya existe de la primera, así que si la prueba
	// mirara sólo "¿hay un ensamblado?" pasaría siempre — incluso sin compilar. Lo
	// que se exige es que sea de ESTA corrida, y -t:Rebuild lo garantiza.
	if fs, err = dnbCompilar(ctx, root, "Juguete.csproj"); err != nil {
		t.Fatalf("segunda compilación del proyecto limpio: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("la segunda corrida inventó %d hallazgos: %+v", len(fs), fs)
	}
}

func TestIntegracionCompilaErroresYAvisosReales(t *testing.T) {
	if testing.Short() {
		t.Skip("compila un proyecto de verdad: fuera del modo corto")
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		t.Skip("sin SDK de .NET en esta máquina")
	}
	root := proyectoCSDeJuguete(t, "public class Roto\n{\n    public int Sumar(int a, int b)\n    {\n        return a + b\n    }\n}\n")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Antes del restore: análisis imposible, y NI UN hallazgo inventado.
	fs, err := dnbCompilar(ctx, root, "Juguete.csproj")
	if err == nil {
		t.Fatalf("sin restore el motor debe degradarse, devolvió %d hallazgos", len(fs))
	}
	if len(fs) != 0 {
		t.Errorf("una degradación no puede traer hallazgos, trajo %d", len(fs))
	}
	if !strings.Contains(err.Error(), "dotnet restore") {
		t.Errorf("el error debe decir qué hacer: %v", err)
	}

	restore := exec.CommandContext(ctx, "dotnet", "restore")
	restore.Dir = root
	if out, err := restore.CombinedOutput(); err != nil {
		t.Skipf("dotnet restore no funcionó aquí (¿sin red?): %v\n%s", err, out)
	}

	fs, err = dnbCompilar(ctx, root, "Juguete.csproj")
	if err != nil {
		t.Fatalf("dnbCompilar tras el restore: %v", err)
	}
	var bloqueantes int
	for _, f := range fs {
		if f.Blocking {
			bloqueantes++
			if f.File != "Codigo.cs" {
				t.Errorf("archivo del error = %q, esperaba Codigo.cs", f.File)
			}
			if !strings.HasPrefix(f.RuleKey, "CS") {
				t.Errorf("RuleKey = %q, esperaba un diagnóstico CS del compilador", f.RuleKey)
			}
		}
	}
	if bloqueantes == 0 {
		t.Fatalf("el `return a + b` sin punto y coma debe dar un error bloqueante; hallazgos: %+v", fs)
	}

	// Arreglado el error, quedan los avisos: y tienen que APARECER aunque el
	// proyecto ya se haya compilado antes — es lo que un build incremental se
	// tragaría en silencio.
	bueno := "public class Bien\n{\n    public int Sumar(int a, int b)\n    {\n        int sinUsar = 42;\n        return a + b;\n    }\n}\n"
	if err := os.WriteFile(filepath.Join(root, "Codigo.cs"), []byte(bueno), 0o644); err != nil {
		t.Fatal(err)
	}
	if fs, err = dnbCompilar(ctx, root, "Juguete.csproj"); err != nil {
		t.Fatalf("dnbCompilar del código válido: %v", err)
	}
	if !contieneRegla(fs, "CS0219") {
		t.Fatalf("esperaba el aviso CS0219 de la variable sin usar; hallazgos: %+v", fs)
	}
	// Segunda corrida idéntica: MSBuild diría "al día" y no imprimiría nada,
	// así que -t:Rebuild es lo único que impide devolver "limpio" sin mirar.
	fs2, err := dnbCompilar(ctx, root, "Juguete.csproj")
	if err != nil {
		t.Fatalf("segunda compilación: %v", err)
	}
	if !contieneRegla(fs2, "CS0219") {
		t.Fatalf("la segunda corrida perdió los avisos: un build incremental los oculta y eso se leería como proyecto limpio; hallazgos: %+v", fs2)
	}
	for _, f := range fs2 {
		if f.Blocking {
			t.Errorf("un aviso de analizador no debe bloquear: %+v", f)
		}
	}
}

func contieneRegla(fs []finding.Finding, regla string) bool {
	for _, f := range fs {
		if f.RuleKey == regla {
			return true
		}
	}
	return false
}
