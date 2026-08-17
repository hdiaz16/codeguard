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

// Capturado con `dotnet list package --vulnerable --include-transitive --format
// json` (SDK 10.0.204) sobre un .csproj con Newtonsoft.Json 9.0.1 y
// System.Text.Encodings.Web 4.5.0. Tal cual. Ojo a lo que NO hay: ni un campo
// con el identificador del aviso (sale de la URL) ni la versión corregida.
const capturaVulnerables = `{
  "version": 1,
  "parameters": "--vulnerable --include-transitive",
  "sources": [
    "https://api.nuget.org/v3/index.json",
    "C:/Program Files (x86)/Microsoft SDKs/NuGetPackages/"
  ],
  "projects": [
    {
      "path": "C:/Users/hector.diaz.BODESA/AppData/Local/Temp/claude/C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal/21867769-946e-43a7-a2eb-657c824f2799/scratchpad/vulnproj/VulnProj.csproj",
      "frameworks": [
        {
          "framework": "net10.0",
          "topLevelPackages": [
            {
              "id": "Newtonsoft.Json",
              "requestedVersion": "9.0.1",
              "resolvedVersion": "9.0.1",
              "vulnerabilities": [
                {
                  "severity": "High",
                  "advisoryurl": "https://github.com/advisories/GHSA-5crp-9r3c-p9vr"
                }
              ]
            },
            {
              "id": "System.Text.Encodings.Web",
              "requestedVersion": "4.5.0",
              "resolvedVersion": "4.5.0",
              "vulnerabilities": [
                {
                  "severity": "Critical",
                  "advisoryurl": "https://github.com/advisories/GHSA-ghhp-997w-qr28"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
`

// Capturado sobre Api.csproj, que sólo tiene un ProjectReference a Core: el CVE
// entra por debajo y llega en "transitivePackages", SIN requestedVersion —
// nadie pidió ese paquete. Es el hueco que más cuesta ver a ojo.
const capturaTransitiva = `{
  "version": 1,
  "parameters": "--vulnerable --include-transitive",
  "sources": [
    "https://api.nuget.org/v3/index.json",
    "C:/Program Files (x86)/Microsoft SDKs/NuGetPackages/"
  ],
  "projects": [
    {
      "path": "C:/Users/hector.diaz.BODESA/AppData/Local/Temp/claude/C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal/21867769-946e-43a7-a2eb-657c824f2799/scratchpad/mono/backend/Api/Api.csproj",
      "frameworks": [
        {
          "framework": "net10.0",
          "transitivePackages": [
            {
              "id": "Newtonsoft.Json",
              "resolvedVersion": "9.0.1",
              "vulnerabilities": [
                {
                  "severity": "High",
                  "advisoryurl": "https://github.com/advisories/GHSA-5crp-9r3c-p9vr"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
`

// Capturado sobre un proyecto SIN paquetes vulnerables. Aquí está la trampa: el
// proyecto limpio se serializa como {"path": ...} y NADA MÁS — sin
// "frameworks". Exactamente igual que un proyecto que no se pudo analizar.
const capturaLimpia = `{
  "version": 1,
  "parameters": "--vulnerable --include-transitive",
  "sources": [
    "https://api.nuget.org/v3/index.json",
    "C:/Program Files (x86)/Microsoft SDKs/NuGetPackages/"
  ],
  "projects": [
    {
      "path": "C:/Users/hector.diaz.BODESA/AppData/Local/Temp/claude/C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal/21867769-946e-43a7-a2eb-657c824f2799/scratchpad/multitfm/MultiTfm.csproj"
    }
  ]
}
`

// Capturado apuntando el origen de paquetes a un sitio que NuGet rechaza. El
// comando SALE CON CÓDIGO 0, el JSON es válido, el proyecto aparece en la lista
// y no tiene ni un CVE. Lo único que delata que no se miró nada es "problems".
// Es tipoFatal de semgrep otra vez: "0 hallazgos" y "no pude mirar" con la
// misma pinta.
const capturaProblemaDeOrigen = `{
  "version": 1,
  "parameters": "--vulnerable --include-transitive",
  "problems": [
    {
      "project": "C:/Users/hector.diaz.BODESA/AppData/Local/Temp/claude/C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal/21867769-946e-43a7-a2eb-657c824f2799/scratchpad/vulnproj/VulnProj.csproj",
      "level": "error",
      "text": "You are running the 'list package' operation with an 'HTTP' source, 'http://127.0.0.1:9/v3/index.json [http://127.0.0.1:9/v3/index.json]'. NuGet requires HTTPS sources. To use HTTP sources, you must explicitly set 'allowInsecureConnections' to true in your NuGet.Config file. Refer to https://aka.ms/nuget-https-everywhere for more information."
    }
  ],
  "sources": [
    "http://127.0.0.1:9/v3/index.json"
  ],
  "projects": [
    {
      "path": "C:/Users/hector.diaz.BODESA/AppData/Local/Temp/claude/C--Users-hector-diaz-BODESA-Desktop-01-Proyectos-GitHub-Personal/21867769-946e-43a7-a2eb-657c824f2799/scratchpad/vulnproj/VulnProj.csproj"
    }
  ]
}
`

// Capturado sobre un proyecto con un PackageReference inexistente: el restore
// implícito falla y no hay ni clave "projects". Código de salida: 0.
const capturaRestoreFallido = `{
   "version": 1,
   "problems": [
      {
         "text": "Restore failed. Run ` + "`dotnet restore`" + ` for more details on the issue.",
         "level": "error"
      }
   ]
}
`

func TestCVEsDePaqueteDeclaradoMapeanSeveridadYPolitica(t *testing.T) {
	// En CI el CVE crítico/alto bloquea (política §7, como trivy y govulncheck).
	fs, err := (DotnetVuln{BlockCritical: true}).interpretar([]byte(capturaVulnerables), t.TempDir(), "vulnproj/VulnProj.csproj")
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperaba 2 hallazgos, hay %d: %+v", len(fs), fs)
	}
	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
		if f.Engine != "dotnet-vuln" || f.Pillar != finding.Security {
			t.Errorf("%s: motor/pilar = %q/%v, esperaba dotnet-vuln/security", f.RuleKey, f.Engine, f.Pillar)
		}
		if f.File != "vulnproj/VulnProj.csproj" || f.Line != 1 {
			t.Errorf("%s: posición = %s:%d, esperaba el manifiesto en la línea 1", f.RuleKey, f.File, f.Line)
		}
		if f.Severity != finding.Error || !f.Blocking {
			t.Errorf("%s: severidad/bloqueo = %v/%v, en CI un High/Critical bloquea", f.RuleKey, f.Severity, f.Blocking)
		}
	}
	// El identificador sale del último segmento de la URL: el JSON no lo trae.
	alto, ok := porRegla["GHSA-5crp-9r3c-p9vr"]
	if !ok {
		t.Fatalf("falta el GHSA de Newtonsoft.Json; reglas: %v", porRegla)
	}
	if !strings.Contains(alto.Message, "Newtonsoft.Json 9.0.1") {
		t.Errorf("el mensaje debe nombrar paquete y versión resuelta: %q", alto.Message)
	}
	if !strings.Contains(alto.Message, "declarada en este proyecto") {
		t.Errorf("un paquete de primer nivel no es transitivo: %q", alto.Message)
	}
	if !strings.Contains(alto.FixHint, "dotnet add package Newtonsoft.Json") {
		t.Errorf("la pista debe decir cómo subirlo: %q", alto.FixHint)
	}
	if _, ok := porRegla["GHSA-ghhp-997w-qr28"]; !ok {
		t.Fatalf("falta el GHSA crítico de System.Text.Encodings.Web; reglas: %v", porRegla)
	}

	// En local avisa: bloquear porque el índice de avisos cambió esta mañana,
	// sin que el commit toque la dependencia, enseña a saltarse el hook.
	fsLocal, err := (DotnetVuln{BlockCritical: false}).interpretar([]byte(capturaVulnerables), t.TempDir(), "vulnproj/VulnProj.csproj")
	if err != nil {
		t.Fatalf("interpretar (local): %v", err)
	}
	for _, f := range fsLocal {
		if f.Blocking {
			t.Errorf("%s: en local no debe bloquear", f.RuleKey)
		}
		if f.Severity != finding.Error {
			t.Errorf("%s: la severidad sigue siendo error aunque no bloquee, es %v", f.RuleKey, f.Severity)
		}
	}
}

func TestCVETransitivoSeMarcaComoTalYCambiaLaPista(t *testing.T) {
	fs, err := (DotnetVuln{BlockCritical: true}).interpretar([]byte(capturaTransitiva), t.TempDir(), "backend/Api/Api.csproj")
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, hay %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if !strings.Contains(f.Message, "transitiva") {
		t.Errorf("el mensaje debe decir que la arrastra otra dependencia: %q", f.Message)
	}
	if !strings.Contains(f.FixHint, "transitiva") || !strings.Contains(f.FixHint, "PackageReference directo") {
		t.Errorf("la pista de una transitiva no es 'actualiza este paquete': %q", f.FixHint)
	}
}

// Un proyecto limpio y un proyecto que no se pudo mirar se serializan igual, y
// los dos salen con código 0. Estos dos tests son las dos caras de esa moneda.
func TestProyectoLimpioNoEsDegradacion(t *testing.T) {
	fs, err := (DotnetVuln{}).interpretar([]byte(capturaLimpia), t.TempDir(), "multitfm/MultiTfm.csproj")
	if err != nil {
		t.Fatalf("un proyecto sin CVEs no es un fallo: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("esperaba 0 hallazgos, hay %d: %+v", len(fs), fs)
	}
}

func TestNoPuedoMirarNoEsCeroCVEs(t *testing.T) {
	for nombre, payload := range map[string]string{
		"origen inalcanzable": capturaProblemaDeOrigen,
		"restore fallido":     capturaRestoreFallido,
	} {
		fs, err := (DotnetVuln{}).interpretar([]byte(payload), t.TempDir(), "vulnproj/VulnProj.csproj")
		if err == nil {
			t.Errorf("%s: debía degradar el motor, devolvió %d hallazgos como si estuviera limpio", nombre, len(fs))
			continue
		}
		if len(fs) != 0 {
			t.Errorf("%s: una degradación no puede traer hallazgos", nombre)
		}
		if !strings.Contains(err.Error(), "vulnproj/VulnProj.csproj") {
			t.Errorf("%s: el error debe nombrar el proyecto: %v", nombre, err)
		}
	}
	// Y el mensaje tiene que decir qué hacer, no sólo que algo falló.
	_, err := (DotnetVuln{}).interpretar([]byte(capturaProblemaDeOrigen), t.TempDir(), "vulnproj/VulnProj.csproj")
	if err == nil || !strings.Contains(err.Error(), "dotnet restore") {
		t.Errorf("el error debe indicar el remedio: %v", err)
	}
}

func TestIdentificadorSaleDeLaURLDelAviso(t *testing.T) {
	casos := map[string]string{
		"https://github.com/advisories/GHSA-5crp-9r3c-p9vr":  "GHSA-5crp-9r3c-p9vr",
		"https://github.com/advisories/GHSA-ghhp-997w-qr28/": "GHSA-ghhp-997w-qr28",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-21907":    "CVE-2024-21907",
		// Forma desconocida: la URL entera. Un RuleKey feo es preferible a uno
		// inventado, que además rompería el fingerprint de supresión.
		"https://ejemplo.local/avisos/12345": "https://ejemplo.local/avisos/12345",
		"":                                   "nuget-advisory",
	}
	for url, esperado := range casos {
		if got := dnvIdentificador(url); got != esperado {
			t.Errorf("dnvIdentificador(%q) = %q, esperaba %q", url, got, esperado)
		}
	}
}

func TestLaLineaDelPackageReferenceHaceElHallazgoNavegable(t *testing.T) {
	root := t.TempDir()
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="9.0.1" />
    <PackageReference Include="System.Text.Encodings.Web" Version="4.5.0" />
  </ItemGroup>
</Project>
`
	if err := os.WriteFile(filepath.Join(root, "VulnProj.csproj"), []byte(csproj), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := (DotnetVuln{}).interpretar([]byte(capturaVulnerables), root, "VulnProj.csproj")
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	lineas := map[string]int{}
	for _, f := range fs {
		lineas[f.RuleKey] = f.Line
	}
	if lineas["GHSA-5crp-9r3c-p9vr"] != 6 {
		t.Errorf("Newtonsoft.Json debería apuntar a la línea 6, apunta a %d", lineas["GHSA-5crp-9r3c-p9vr"])
	}
	if lineas["GHSA-ghhp-997w-qr28"] != 7 {
		t.Errorf("System.Text.Encodings.Web debería apuntar a la línea 7, apunta a %d", lineas["GHSA-ghhp-997w-qr28"])
	}
}

// En el hook sólo corre cuando cambian las dependencias: el comando restaura y
// va a la RED (medido: con un origen inalcanzable se queda colgado minutos), y
// el presupuesto son 30 s compartidos entre todos los motores.
func TestSoloManifiestosIgnoraLosCambiosDeCodigo(t *testing.T) {
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
	escribir("backend/Api/Servicio.cs", "class S {}")
	escribir("backend/Api/packages.lock.json", "{}")

	soloCodigo := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/Api/Servicio.cs", Status: "M"},
	}}
	if got, err := (DotnetVuln{SoloManifiestos: true}).proyectos(soloCodigo); err != nil || len(got) != 0 {
		t.Errorf("en el hook, un .cs no debe disparar el escaneo de dependencias: %v (err: %v)", got, err)
	}
	// El CI sí: corre con cualquier .cs tocado.
	if got, err := (DotnetVuln{}).proyectos(soloCodigo); err != nil || len(got) != 1 || got[0] != "backend/Api/Api.csproj" {
		t.Errorf("en CI un .cs sí dispara el escaneo: %v (err: %v)", got, err)
	}
	// El lockfile vive junto al .csproj: se sube hasta él.
	lock := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/Api/packages.lock.json", Status: "M"},
	}}
	if got, err := (DotnetVuln{SoloManifiestos: true}).proyectos(lock); err != nil || len(got) != 1 || got[0] != "backend/Api/Api.csproj" {
		t.Errorf("packages.lock.json debe resolver a su .csproj: %v (err: %v)", got, err)
	}
	// El propio manifiesto.
	manifiesto := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/Api/Api.csproj", Status: "M"},
	}}
	if got, err := (DotnetVuln{SoloManifiestos: true}).proyectos(manifiesto); err != nil || len(got) != 1 || got[0] != "backend/Api/Api.csproj" {
		t.Errorf("un .csproj tocado es el propio proyecto: %v (err: %v)", got, err)
	}
	if !(DotnetVuln{SoloManifiestos: true}).Applies(manifiesto) {
		t.Error("Applies debe ser verdadero con un .csproj tocado")
	}
	// Y un manifiesto borrado no dispara nada.
	borrado := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/Api/Api.csproj", Status: "D"},
	}}
	if (DotnetVuln{SoloManifiestos: true}).Applies(borrado) {
		t.Error("un .csproj borrado no tiene dependencias que revisar")
	}
}

// ── integración con el dotnet real ──────────────────────────────────────────

func TestIntegracionDetectaElCVEDeNewtonsoftJson(t *testing.T) {
	if testing.Short() {
		t.Skip("consulta el índice de avisos de nuget.org: fuera del modo corto")
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		t.Skip("sin SDK de .NET en esta máquina")
	}
	root := t.TempDir()
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>` + tfmInstalado(t) + `</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="9.0.1" />
  </ItemGroup>
</Project>
`
	if err := os.WriteFile(filepath.Join(root, "Vuln.csproj"), []byte(csproj), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	restore := exec.CommandContext(ctx, "dotnet", "restore")
	restore.Dir = root
	if out, err := restore.CombinedOutput(); err != nil {
		t.Skipf("dotnet restore no funcionó aquí (¿sin red o sin acceso a nuget.org?): %v\n%s", err, out)
	}

	fs, err := (DotnetVuln{BlockCritical: true}).revisarProyecto(ctx, root, "Vuln.csproj")
	if err != nil {
		t.Skipf("dotnet list package --vulnerable no pudo consultar el índice (¿sin red?): %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("Newtonsoft.Json 9.0.1 tiene una vulnerabilidad alta conocida: el motor no encontró nada")
	}
	f := fs[0]
	if !strings.HasPrefix(f.RuleKey, "GHSA-") && !strings.HasPrefix(f.RuleKey, "CVE-") {
		t.Errorf("RuleKey = %q, esperaba un GHSA o un CVE", f.RuleKey)
	}
	if f.File != "Vuln.csproj" || f.Line != 6 {
		t.Errorf("posición = %s:%d, esperaba Vuln.csproj:6 (la línea del PackageReference)", f.File, f.Line)
	}
	if f.Pillar != finding.Security || f.Severity != finding.Error || !f.Blocking {
		t.Errorf("pilar/severidad/bloqueo = %v/%v/%v, esperaba security/error/bloqueante en CI", f.Pillar, f.Severity, f.Blocking)
	}
}
