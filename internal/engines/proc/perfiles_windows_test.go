//go:build windows

package proc

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const proxyMuerto = "http://127.0.0.1:9/"

// El fixture de perfiles (W4, t.115): un `cmd /c set` REAL bajo cada perfil,
// asertando lo que el hijo VE — no lo que la lista promete. Los canarios se
// siembran con t.Setenv: si alguno cruza a un perfil que no lo declara, el
// estrechamiento está roto. Y desde la tanda (c), los perfiles SIN red deben
// ver los proxies MUERTOS del egress-hint — nunca los del usuario.
func TestPerfilesVenExactamenteLoDeclarado(t *testing.T) {
	t.Setenv("CG_CANARIO_SECRETO", "jamas-debe-cruzar")
	t.Setenv("GOFLAGS", "-mod=mod") // el vector de envenenamiento: murió de TODOS los perfiles
	t.Setenv("NODE_PATH", "c:\\canario\\node")
	t.Setenv("MYPYPATH", "c:\\canario\\stubs")
	t.Setenv("HTTP_PROXY", "http://proxy-del-usuario:3128")
	t.Setenv("NO_PROXY", "interno.example")
	t.Setenv("GOCACHE", "c:\\canario\\gocache")
	t.Setenv("JAVA_HOME", "c:\\canario\\jdk")

	ver := func(t *testing.T, p Perfil) map[string]string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "cmd", "/c", "set")
		c.Env = EntornoDePerfil(p)
		s, err := Correr(ctx, c, 1<<20)
		if err != nil {
			t.Fatalf("cmd /c set falló: %v", err)
		}
		vistas := map[string]string{}
		for _, l := range strings.Split(string(s.Stdout), "\n") {
			if i := strings.IndexByte(l, '='); i > 0 {
				vistas[strings.ToUpper(strings.TrimSpace(l[:i]))] = strings.TrimRight(l[i+1:], "\r\n")
			}
		}
		return vistas
	}

	// nota: `cmd /c set` no lista variables con valor VACÍO, así que
	// NO_PROXY= (el hint) aparece como AUSENTE — lo que se asierta es que el
	// valor del usuario ("interno.example") no cruzó.
	casos := []struct {
		nombre string
		perfil Perfil
		dentro []string // deben verse (con cualquier valor)
		fuera  []string // no deben verse EN ABSOLUTO
		red    bool     // true = ve los proxies del usuario; false = los muertos
	}{
		{"basico", PerfilBasico, []string{"PATH", "TEMP", "USERPROFILE"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "NODE_PATH", "MYPYPATH", "GOCACHE", "JAVA_HOME"}, false},
		{"go", PerfilGo, []string{"PATH", "GOCACHE"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "NODE_PATH", "MYPYPATH", "JAVA_HOME"}, false},
		{"go-red", PerfilGoRed, []string{"PATH", "GOCACHE"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "NODE_PATH", "MYPYPATH", "JAVA_HOME"}, true},
		{"node", PerfilNode, []string{"PATH", "NODE_PATH"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "MYPYPATH", "GOCACHE", "JAVA_HOME"}, false},
		{"python", PerfilPython, []string{"PATH", "MYPYPATH", "PYTHONUTF8"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "NODE_PATH", "GOCACHE", "JAVA_HOME"}, false},
		{"dotnet", PerfilDotnet, []string{"PATH"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "NODE_PATH", "MYPYPATH", "GOCACHE", "JAVA_HOME"}, false},
		{"dotnet-red", PerfilDotnetRed, []string{"PATH"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "NODE_PATH", "MYPYPATH", "GOCACHE", "JAVA_HOME"}, true},
		{"java", PerfilJava, []string{"PATH", "JAVA_HOME"},
			[]string{"CG_CANARIO_SECRETO", "GOFLAGS", "NODE_PATH", "MYPYPATH", "GOCACHE"}, false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			vistas := ver(t, c.perfil)
			for _, v := range c.dentro {
				if _, ok := vistas[v]; !ok {
					t.Errorf("el perfil %s debía ver %s y no la ve", c.nombre, v)
				}
			}
			for _, v := range c.fuera {
				if val, ok := vistas[v]; ok {
					t.Errorf("el perfil %s VE %s=%q y no la declara — la variable cruzó", c.nombre, v, val)
				}
			}
			if c.red {
				if vistas["HTTP_PROXY"] != "http://proxy-del-usuario:3128" {
					t.Errorf("perfil con red %s debía ver el proxy DEL USUARIO, ve %q", c.nombre, vistas["HTTP_PROXY"])
				}
				if vistas["NO_PROXY"] != "interno.example" {
					t.Errorf("perfil con red %s debía conservar NO_PROXY del usuario, ve %q", c.nombre, vistas["NO_PROXY"])
				}
			} else {
				if vistas["HTTP_PROXY"] != proxyMuerto || vistas["HTTPS_PROXY"] != proxyMuerto {
					t.Errorf("perfil sin red %s debía ver los proxies MUERTOS, ve HTTP=%q HTTPS=%q",
						c.nombre, vistas["HTTP_PROXY"], vistas["HTTPS_PROXY"])
				}
				if v := vistas["NO_PROXY"]; v == "interno.example" {
					t.Errorf("perfil sin red %s conserva el NO_PROXY del usuario (%q): el hint no lo pisó", c.nombre, v)
				}
			}
		})
	}

	// La unión histórica (PerfilCompleto) conserva los proxies del usuario y
	// sigue sin GOFLAGS ni canarios.
	vistas := ver(t, PerfilCompleto)
	if _, ok := vistas["GOFLAGS"]; ok {
		t.Error("PerfilCompleto ve GOFLAGS: la unión histórica no lo debe llevar")
	}
	if _, ok := vistas["CG_CANARIO_SECRETO"]; ok {
		t.Error("PerfilCompleto ve el canario secreto")
	}
	if vistas["HTTP_PROXY"] != "http://proxy-del-usuario:3128" {
		t.Error("PerfilCompleto debía conservar los proxies del usuario")
	}
}

// El egress-hint MEDIDO con una herramienta real que respeta proxies:
// curl.exe (viene con Windows) bajo un perfil sin red debe fallar RÁPIDO
// (proxy muerto en loopback, sin backoff) — jamás alcanzar la red. Es el
// contrato del freno: frena herramientas legítimas; el net.Dial directo de
// un binario hostil lo cierra WFP/AppContainer (compuerta de flota), y ese
// límite queda dicho donde se decide.
func TestEgressHintFrenaAUnaHerramientaLegitima(t *testing.T) {
	if _, err := exec.LookPath("curl.exe"); err != nil {
		t.Skip("sin curl.exe en esta máquina")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	inicio := time.Now()
	c := exec.CommandContext(ctx, "curl.exe", "-s", "--max-time", "10", "http://example.com/")
	c.Env = EntornoDePerfil(PerfilBasico)
	s, err := Correr(ctx, c, 1<<20)
	if err == nil {
		t.Fatalf("curl bajo perfil sin red debía fallar y respondió %d bytes", len(s.Stdout))
	}
	if d := time.Since(inicio); d > 8*time.Second {
		t.Errorf("el freno tardó %v: el proxy muerto debía fallar en milisegundos, no colgar", d)
	}
}
