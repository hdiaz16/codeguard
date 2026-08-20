package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
)

// codeguard report: informe de hallazgos ESCRITO PARA UN AGENTE DE CÓDIGO
// (Claude Code, Gemini CLI, Codex...). Versionado, con instrucciones precisas
// y — lo importante — re-ejecutable: al volver a correrlo marca como resueltos
// los que ya no aparecen, y solo se declara COMPLETADO cuando no queda ninguno.

const reportFile = ".codeguard/HALLAZGOS.md"

// La huella de un hallazgo, tal y como la ESCRIBE este archivo. Son dos sitios
// y en los dos la marca CIERRA la línea:
//
//	escribirHallazgo → sola en su propia línea:  <!-- fp:… -->
//	sección de deuda → al final de un bullet:    - `regla` — `f.go:3` · msg <!-- fp:… -->
//
// De ahí el ancla. Sin ella, un `<!-- fp:… -->` metido en el texto de una regla
// contaba como huella del informe, y el texto de una regla es de FUERA: sale del
// YAML del rulepack, que puede venir vendoreado en el repo analizado.
//
// A fin de línea sólo no basta, que es la parte que no se ve a la primera:
// "**Qué detectó:** <mensaje>" también termina con el mensaje, así que una marca
// que CIERRE el texto de la regla queda pegada al final de una línea legítima.
// Por eso delante se exige o nada, o un bullet.
//
// Y el `.*` es voraz a propósito: en un bullet de deuda con una marca colada en
// el texto, hace que la coincidencia sea la ÚLTIMA de la línea, o sea la que
// puso el generador. Antes ganaba la colada —FindStringSubmatch devuelve la
// primera— y la deuda corregida dejaba de contar como resuelta.
var fpRe = regexp.MustCompile(`^(?:-\s.*)?<!--\s*fp:([0-9a-f]{64})\s*-->\s*$`)

func reportCmd() *cobra.Command {
	var incluirAvisos, incluirDeuda bool
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Genera .codeguard/HALLAZGOS.md para que un agente de código los resuelva",
		Long: "Escanea el repo completo y escribe un informe con instrucciones precisas.\n" +
			"Re-ejecutarlo marca como RESUELTOS los hallazgos que ya no existen.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return err
			}
			cfg, err := config.Load(repoRoot)
			if err != nil {
				return err
			}
			if cfg == nil {
				return fmt.Errorf("el repo no está enrolado: corre `codeguard init`")
			}

			// hallazgos previos (para saber cuáles se resolvieron) y las
			// discrepancias anotadas, que sobreviven a la regeneración
			previos, err := leerFingerprintsPrevios(filepath.Join(repoRoot, filepath.FromSlash(reportFile)))
			if err != nil {
				// El informe anterior no se pudo leer entero: sin sus
				// fingerprints no se puede decir qué se resolvió, así que esta
				// corrida no declara RESUELTO nada (fail-closed) y lo avisa.
				// No se aborta el comando: el informe se reescribe entero más
				// abajo, así que la próxima corrida ya parte de un archivo sano.
				fmt.Printf("  ⚠️  no se pudo leer el informe anterior (%v): esta corrida no marcará resueltos\n", err)
			}
			discrepancias := leerDiscrepanciasPrevias(filepath.Join(repoRoot, filepath.FromSlash(reportFile)))

			rutas, err := gitdiff.Rastreados(repoRoot)
			if err != nil {
				return err
			}
			var files []gitdiff.ChangedFile
			for _, r := range rutas {
				// El informe no se analiza a sí mismo: cada corrida lo
				// reescribe, y ese cambio perpetuo invalidaba su entrada de
				// caché — semgrep pagaba su arranque completo en cada informe
				// solo para mirar la salida del informe anterior.
				if r == reportFile {
					continue
				}
				files = append(files, gitdiff.ChangedFile{Path: r, Status: "M"})
			}
			files = conHuellas(repoRoot, files)
			fmt.Printf("escaneando %d archivos…\n", len(files))

			// El caché por archivo (§9) es lo que separa el primer informe
			// (todo se analiza) del segundo (solo lo que cambió desde entonces).
			cache, cerrarCache := abrirCache(repoRoot, cfg)
			defer cerrarCache()

			// La baseline NO se le pasa al pipeline: el informe la aplica él
			// mismo, porque necesita las dos mitades. Los hallazgos nuevos van
			// a "bloqueantes" (impiden commitear, el agente los corrige); los
			// baselineados son deuda aceptada — no bloquean, pero el agente los
			// ENCONTRÓ, y hasta ahora no existía ninguna superficie donde un
			// humano pudiera revisarlos: quedaban como fingerprints en
			// baseline.txt, hallados pero invisibles.
			// Una baseline ilegible NO se degrada aquí: el informe la aplica él
			// mismo para separar bloqueantes de deuda, y con una baseline
			// parcial presentaría deuda aceptada como bloqueante — el informe
			// mentiría en las dos direcciones a la vez. Se falla y se dice.
			supr, err := baseline.Load(repoRoot)
			if err != nil {
				return err
			}

			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:   cfg,
				Diff:     &gitdiff.Diff{Files: files},
				Secrets:  nil, // los secretos se atienden en el acto, no por informe
				Engines:  daemon.Engines(cfg, false, cache),
				Rulepack: daemon.RulepackDir(repoRoot, cfg.Rulepack),
				Timeout:  15 * time.Minute,
			})
			if err != nil {
				return err
			}

			// clasificar: nuevo-bloqueante / nuevo-aviso / deuda baselineada.
			// "actuales" incluye TAMBIÉN la deuda: un hallazgo baselineado que
			// desaparece del código cuenta como resuelto, no como fantasma.
			var bloq, avisos, deuda []finding.Finding
			actuales := map[string]bool{}
			for _, f := range res.Findings {
				actuales[f.Fingerprint] = true
				switch {
				case supr[f.Fingerprint]:
					deuda = append(deuda, f)
				case f.Blocking:
					bloq = append(bloq, f)
				case incluirAvisos:
					avisos = append(avisos, f)
				}
			}
			// «RESUELTO» SÓLO SE PUEDE DECIR SI ALGUIEN MIRÓ.
			//
			// Un hallazgo se declaraba resuelto por AUSENCIA: estaba en el
			// informe anterior y no está en éste. Pero una capa degradada
			// produce exactamente esa ausencia sin que nadie haya tocado el
			// código, así que el informe marcaba con casilla `[x]` bugs que
			// siguen ahí enteros.
			//
			// MEDIDO en un repo de juguete, tres corridas: con staticcheck
			// instalado salían U1000 y SA4006 como pendientes; renombrando su
			// binario, las DOS aparecían bajo «✅ Resueltos desde el informe
			// anterior», en el mismo documento que un párrafo más arriba admite
			// que esa capa no corrió. Y de regalo, el conteo de deuda
			// baselineada caía a 0 por el mismo camino.
			//
			// Lo lee un humano por la mañana, pero sobre todo lo lee un AGENTE
			// que decide si queda trabajo: darle por cerrado lo que nadie
			// revisó es la peor mentira que puede contar este archivo.
			//
			// El daño medido es acotado —al restaurar la capa vuelven a
			// aparecer, porque cada corrida reescanea de verdad y no arrastra
			// un registro acumulativo— pero dura todo el ciclo en que la capa
			// está rota, y es indefinido si nadie vuelve a correr el informe.
			//
			// Se calla ENTERA la sección en vez de filtrarla capa por capa, y
			// es deliberado: los fingerprints previos no dicen de qué motor
			// salieron, así que filtrar exigiría adivinarlo por el texto. Entre
			// adivinar y callar, se calla — y se dice por qué, que es lo que
			// convierte un hueco en información.
			resueltos, noSePuedeDecirResuelto := calcularResueltos(previos, actuales, res.Degraded)

			md := construirInforme(cfg, res, bloq, avisos, resueltos, noSePuedeDecirResuelto, deuda, incluirAvisos, incluirDeuda, discrepancias)
			dest := filepath.Join(repoRoot, filepath.FromSlash(reportFile))
			_ = os.MkdirAll(filepath.Dir(dest), 0o755) // best-effort: el WriteFile de abajo dará el error real
			if err := os.WriteFile(dest, []byte(md), 0o644); err != nil {
				return err
			}

			fmt.Printf("\ninforme: %s\n", reportFile)
			fmt.Printf("  bloqueantes pendientes: %d\n", len(bloq))
			if incluirAvisos {
				fmt.Printf("  avisos: %d\n", len(avisos))
			}
			if len(deuda) > 0 {
				if incluirDeuda {
					fmt.Printf("  deuda aceptada (baseline): %d — detallada en el informe\n", len(deuda))
				} else {
					fmt.Printf("  deuda aceptada (baseline): %d — revísala con `codeguard report --deuda`\n", len(deuda))
				}
			}
			if len(resueltos) > 0 {
				fmt.Printf("  RESUELTOS desde el informe anterior: %d\n", len(resueltos))
			}
			// Lo que no se revisó se dice ANTES del veredicto, no en una línea
			// suelta después: leído en ese orden, "no quedan bloqueantes" ya no
			// se puede confundir con "está limpio".
			capas := explicarCapas(res.Degraded)
			for _, c := range capas {
				fmt.Println("\n  ⚠️  " + textoPlano(c))
			}
			switch {
			case len(bloq) == 0 && len(capas) == 0:
				fmt.Println("\n  ✅ COMPLETADO: no quedan bloqueantes")
			case len(bloq) == 0:
				fmt.Println("\n  ⚠️  PARCIAL: sin bloqueantes en lo que sí se revisó, pero el")
				fmt.Println("      análisis está incompleto. Esto NO es un visto bueno.")
			default:
				fmt.Println("\n  entrégale el archivo a tu agente: \"resuelve .codeguard/HALLAZGOS.md\"")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&incluirAvisos, "avisos", false, "incluir también los hallazgos no bloqueantes")
	cmd.Flags().BoolVar(&incluirDeuda, "deuda", false, "detallar la deuda aceptada por la baseline (hallada pero suprimida)")
	return cmd
}

// leerDiscrepanciasPrevias rescata lo que el agente anotó en la sección
// "Discrepancias" del informe anterior.
//
// El informe INSTRUYE al agente a anotar ahí los falsos positivos "para que
// un humano decida después" — y acto seguido cada `codeguard report`
// reconstruía el archivo entero y borraba la anotación antes de que ningún
// humano la viera. Las dos mitades del contrato se contradecían.
func leerDiscrepanciasPrevias(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	texto := strings.ReplaceAll(string(raw), "\r\n", "\n")
	const marca = "\n## Discrepancias\n"
	inicio := strings.Index(texto, marca)
	if inicio < 0 {
		return ""
	}
	cuerpo := texto[inicio+len(marca):]
	if fin := strings.Index(cuerpo, "\n---"); fin >= 0 {
		cuerpo = cuerpo[:fin]
	}
	cuerpo = strings.TrimSpace(cuerpo)
	// El comentario-guía de la plantilla no es una anotación: se descarta para
	// no acumular copias de sí mismo en cada regeneración.
	if strings.HasPrefix(cuerpo, "<!--") {
		if cierre := strings.Index(cuerpo, "-->"); cierre >= 0 {
			cuerpo = strings.TrimSpace(cuerpo[cierre+3:])
		}
	}
	return cuerpo
}

func leerFingerprintsPrevios(path string) (map[string]string, error) {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out, nil // sin informe anterior no hay "previos": no es un error
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// Mismo motivo que en baseline.Load: el buffer de 64 KB convertía una
	// línea larga en un EOF falso y el mapa salía a medias sin ruido.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var ultimoTitulo string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "### ") {
			ultimoTitulo = strings.TrimSpace(strings.TrimPrefix(line, "###"))
			ultimoTitulo = strings.TrimPrefix(ultimoTitulo, "✅ RESUELTO — ")
		}
		if m := fpRe.FindStringSubmatch(line); m != nil {
			out[m[1]] = ultimoTitulo
		}
	}
	if err := sc.Err(); err != nil {
		// Un mapa leído a medias no se entrega como si estuviera completo:
		// el llamador decide (hoy: no declarar resueltos y avisar).
		return nil, fmt.Errorf("informe anterior truncado: %w", err)
	}
	return out, nil
}

// calcularResueltos decide qué se puede declarar resuelto y qué no.
//
// Está aparte del RunE a propósito: la DECISIÓN es lo que hay que poder probar
// y romper a propósito. Mientras vivió dentro del comando, los tests sólo
// llegaban a `construirInforme` —o sea al RENDERIZADO— y una mutación de la
// decisión pasaba en verde, que es la definición de test decorativo.
//
// Devuelve (resueltos, capasQueImpidenDecirlo). Las dos listas no se solapan
// nunca: o se puede afirmar, o no se puede.
func calcularResueltos(previos map[string]string, actuales map[string]bool, degraded []string) ([]string, []string) {
	if rotas := pipeline.SinGarantia(degraded); len(rotas) > 0 {
		return nil, rotas
	}
	var resueltos []string
	for fp, desc := range previos {
		if !actuales[fp] {
			resueltos = append(resueltos, desc)
		}
	}
	sort.Strings(resueltos)
	return resueltos, nil
}

func construirInforme(cfg *config.Config, res *pipeline.Result, bloq, avisos []finding.Finding,
	resueltos, noSePuedeDecirResuelto []string, deuda []finding.Finding, incluirAvisos, incluirDeuda bool, discrepancias string) string {

	var b strings.Builder
	fecha := time.Now().Format("2006-01-02 15:04")
	capas := explicarCapas(res.Degraded)
	// COMPLETADO exige las DOS cosas: que no queden bloqueantes y que se haya
	// revisado todo. Antes bastaba lo primero, y con el rulepack sin instalar
	// el informe encabezaba "✅ COMPLETADO" con las 119 reglas de la casa sin
	// ejecutar — y unas líneas más abajo le decía al agente de código que ese
	// encabezado "es el criterio de terminado, no tu impresión de haber
	// terminado". Una máquina leyendo eso da el trabajo por bueno con la
	// compuerta principal apagada.
	completado := len(bloq) == 0 && len(capas) == 0

	fmt.Fprintf(&b, "# Hallazgos de CodeGuard\n\n")
	switch {
	case completado:
		fmt.Fprintf(&b, "> ## ✅ COMPLETADO — no quedan hallazgos bloqueantes\n>\n")
		fmt.Fprintf(&b, "> Generado el %s · rulepack `%s`\n\n", fecha, cfg.Rulepack)
	case len(bloq) == 0:
		fmt.Fprintf(&b, "> ## ⚠️ PARCIAL — sin bloqueantes EN LO QUE SÍ SE REVISÓ\n>\n")
		fmt.Fprintf(&b, "> Este análisis no está completo, así que no vale como visto bueno:\n>\n")
		for _, c := range capas {
			fmt.Fprintf(&b, "> - %s\n", c)
		}
		fmt.Fprintf(&b, ">\n> Generado el %s · rulepack `%s`\n\n", fecha, cfg.Rulepack)
	default:
		fmt.Fprintf(&b, "> **Estado: %d bloqueante(s) pendiente(s)** · generado el %s · rulepack `%s`\n\n",
			len(bloq), fecha, cfg.Rulepack)
		if len(capas) > 0 {
			fmt.Fprintf(&b, "> ⚠️ Y el análisis está INCOMPLETO, así que puede haber más:\n>\n")
			for _, c := range capas {
				fmt.Fprintf(&b, "> - %s\n", c)
			}
			b.WriteString(">\n")
		}
	}

	b.WriteString(`## Instrucciones para el agente de código

Eres el agente encargado de resolver estos hallazgos. Reglas de trabajo:

1. **Atiende primero los BLOQUEANTES** — impiden hacer commit y el CI también los rechaza.
2. **Un hallazgo, un cambio, una verificación.** No agrupes correcciones no relacionadas.
3. **No suprimas la regla para callar el hallazgo** (nada de ` + "`// nolint`" + `, ` + "`# noqa`" + `,
   ` + "`@ts-ignore`" + ` ni añadir el fingerprint a la baseline). Corrige la causa.
4. **Verifica cada corrección** ejecutando lo que corresponda:
   - formato: ` + "`gofmt -w <archivo>`" + ` / ` + "`ruff format <archivo>`" + ` / ` + "`dotnet format`" + `
   - tipos: ` + "`npx tsc --noEmit`" + ` / ` + "`mypy <archivo>`" + `
   - lint: ` + "`go vet ./...`" + ` / ` + "`ruff check <archivo>`" + `
5. **Al terminar, ejecuta ` + "`codeguard report`" + ` otra vez.** El informe se regenera:
   lo resuelto pasa a la sección "✅ Resueltos" y, cuando no quede ningún
   bloqueante **y todas las capas hayan corrido**, el encabezado dirá
   **COMPLETADO**. Ese es el criterio de terminado — no tu impresión de haber
   terminado.
   Si el encabezado dice **PARCIAL**, el trabajo NO está terminado por mucho que
   no queden bloqueantes: significa que una capa del análisis no se ejecutó y
   nadie sabe qué habría encontrado. Arregla primero lo que el encabezado
   indique y vuelve a generar el informe.
6. Si un hallazgo te parece un falso positivo, **no lo silencies**: anótalo en la
   sección "Discrepancias" al final y sigue con los demás.

`)

	if len(bloq) > 0 {
		fmt.Fprintf(&b, "---\n\n## ⛔ Bloqueantes (%d)\n\n", len(bloq))
		for i, f := range bloq {
			escribirHallazgo(&b, i+1, f)
		}
	}

	if incluirAvisos && len(avisos) > 0 {
		fmt.Fprintf(&b, "---\n\n## ⚠️ Avisos (%d) — opcionales, no bloquean\n\n", len(avisos))
		for i, f := range avisos {
			escribirHallazgo(&b, i+1, f)
		}
	}

	if len(resueltos) > 0 {
		fmt.Fprintf(&b, "---\n\n## ✅ Resueltos desde el informe anterior (%d)\n\n", len(resueltos))
		for _, t := range resueltos {
			fmt.Fprintf(&b, "- [x] %s\n", t)
		}
		b.WriteString("\n")
	}
	// El hueco se nombra. Un apartado que simplemente no aparece se lee como
	// "no había nada que resolver", que es la misma ausencia que se acaba de
	// dejar de tomar por buena unas líneas más arriba.
	if len(noSePuedeDecirResuelto) > 0 {
		b.WriteString("---\n\n## ❔ No puedo decir qué se resolvió\n\n")
		fmt.Fprintf(&b, "Estas capas no llegaron a mirar en esta corrida: **%s**.\n\n",
			strings.Join(noSePuedeDecirResuelto, ", "))
		b.WriteString("Un hallazgo se da por resuelto cuando estaba en el informe anterior y ya no " +
			"aparece. Con una capa caída, esa ausencia no significa que se arreglara: significa que " +
			"nadie lo buscó. Arregla la capa y vuelve a correr `codeguard report`.\n\n")
	}

	// La deuda aceptada, cuando se pide: el agente la ENCONTRÓ y la baseline la
	// calla en el commit —correcto: sólo lo nuevo bloquea—, pero sin esta
	// sección no existía superficie donde un humano pudiera revisarla. Quedaba
	// como fingerprints en baseline.txt: hallada pero invisible.
	if incluirDeuda && len(deuda) > 0 {
		ordenada := make([]finding.Finding, len(deuda))
		copy(ordenada, deuda)
		sort.Slice(ordenada, func(i, j int) bool {
			if ordenada[i].File != ordenada[j].File {
				return ordenada[i].File < ordenada[j].File
			}
			return ordenada[i].Line < ordenada[j].Line
		})
		fmt.Fprintf(&b, "---\n\n## 📋 Deuda aceptada por la baseline (%d) — no bloquea\n\n", len(ordenada))
		b.WriteString("Hallazgos que ya existían al enrolar el repo. Se revisan al ritmo del equipo;\n" +
			"al corregir uno, quita su línea de `.codeguard/baseline.txt` (o regenera la\n" +
			"baseline) para que vuelva a vigilarse como nuevo.\n\n")
		for _, f := range ordenada {
			fmt.Fprintf(&b, "- `%s` — `%s:%d` · %s <!-- fp:%s -->\n",
				f.RuleKey, f.File, f.Line, mensajeDeHallazgo(f.Message), f.Fingerprint)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n## Discrepancias\n\n")
	if discrepancias != "" {
		// Lo anotado sobrevive a la regeneración: el informe le pide al agente
		// escribir aquí sus falsos positivos "para que un humano decida", y la
		// versión anterior los borraba en la siguiente corrida.
		b.WriteString(discrepancias + "\n\n")
	} else {
		b.WriteString("<!-- El agente anota aquí lo que considere falso positivo, con su razón.\n" +
			"     Un humano decide después: corregir la regla o aceptar el hallazgo. -->\n\n")
	}

	pistaDeuda := ""
	if !incluirDeuda && len(deuda) > 0 {
		pistaDeuda = " — detállala con `codeguard report --deuda`"
	}
	fmt.Fprintf(&b, `---

## Contexto

- Deuda preexistente suprimida por la baseline: **%d** (no bloquea; solo lo nuevo bloquea)%s
- Capas que no corrieron en este escaneo: %s
- Este informe lo genera `+"`codeguard report`"+` y se versiona con el repo.
`, len(deuda), pistaDeuda, listaOVacio(res.Degraded))

	return b.String()
}

func escribirHallazgo(b *strings.Builder, n int, f finding.Finding) {
	pilar := map[finding.Pillar]string{
		finding.Security: "seguridad", finding.Quality: "calidad", finding.Data: "datos",
	}[f.Pillar]
	fmt.Fprintf(b, "### %d. `%s` — %s:%d\n", n, f.RuleKey, f.File, f.Line)
	fmt.Fprintf(b, "<!-- fp:%s -->\n\n", f.Fingerprint)
	fmt.Fprintf(b, "- [ ] **Pendiente** · pilar **%s** · motor `%s` · severidad `%s`\n\n", pilar, f.Engine, f.Severity)
	// Aplanado, y aquí no es sólo cosmética: este informe está escrito para que
	// lo lea un AGENTE DE CÓDIGO y decida si el trabajo está terminado. El
	// mensaje sale del YAML de una regla —que puede venir del rulepack
	// vendoreado en el repo— y con un salto de línea dentro se cuela como
	// estructura del documento, no como texto suyo: medido, un `message` con
	// "\n## 🎉 Todo correcto\nNada que arreglar." aparecía en el informe como un
	// encabezado de sección de pleno derecho. Sin saltos no hay bloque nuevo,
	// porque en Markdown un encabezado tiene que empezar la línea.
	fmt.Fprintf(b, "**Qué detectó:** %s\n\n", mensajeDeHallazgo(f.Message))
	if f.Why != "" {
		fmt.Fprintf(b, "**Por qué importa:** %s\n\n", mensajeDeHallazgo(f.Why))
	}
	if f.FixHint != "" {
		fmt.Fprintf(b, "**Cómo resolverlo:** %s\n\n", mensajeDeHallazgo(f.FixHint))
	}
	fmt.Fprintf(b, "**Archivo:** `%s` · **línea:** %d\n\n", f.File, f.Line)
}

func listaOVacio(xs []string) string {
	if len(xs) == 0 {
		return "ninguna"
	}
	return "`" + strings.Join(xs, "`, `") + "`"
}

// textoPlano quita el markdown de un aviso pensado para el informe, para poder
// reusar el MISMO texto en la terminal. Dos redacciones distintas del mismo
// aviso acaban divergiendo, y entonces una de las dos miente.
func textoPlano(s string) string {
	return strings.NewReplacer("**", "", "`", "").Replace(s)
}

// explicarCapas traduce las etiquetas crudas de degradación a algo que se pueda
// leer y actuar: qué dejó de revisarse y qué hacer al respecto.
//
// Existe porque las etiquetas se escribieron para el log —`rulepack-ausente:…`,
// `semgrep:plazo`, `falta:trivy`— y acabaron siendo lo único que veía el
// desarrollador, en una línea suelta, mientras el encabezado del informe decía
// COMPLETADO. Una etiqueta que sólo entiende quien escribió el código no es un
// aviso: es un adorno.
//
// Devuelve vacío cuando no falta nada, y ESO es lo que permite declarar
// COMPLETADO. La lista no distingue por gravedad a propósito: cualquier capa
// que no corre deja un hueco que nadie ha mirado.
func explicarCapas(degraded []string) []string {
	var out []string
	for _, d := range degraded {
		switch {
		case strings.HasPrefix(d, "rulepack-ausente:"):
			v := strings.TrimPrefix(d, "rulepack-ausente:")
			out = append(out, fmt.Sprintf(
				"**Las reglas de la casa NO se aplicaron**: este repo apunta al rulepack `%s` "+
					"y no está instalado. El CI sí las aplica, así que puede rechazar lo que aquí pasó. "+
					"Arréglalo con `codeguard repair`.", v))
		case d == "daemon:offline":
			out = append(out, "El agente no estaba corriendo: la revisión fue en frío y sin caché, "+
				"y suele arrastrar otras capas. Arráncalo y repite.")
		case strings.HasSuffix(d, ":plazo"):
			m := strings.TrimSuffix(d, ":plazo")
			out = append(out, fmt.Sprintf(
				"`%s` no cupo en el plazo y no revisó nada. La primera corrida es la cara "+
					"(compilar, arrancar node); repite y con el caché tibio debería entrar.", m))
		case strings.HasPrefix(d, "falta:"):
			m := strings.TrimPrefix(d, "falta:")
			out = append(out, fmt.Sprintf(
				"`%s` no está instalado, así que su capa no se revisó. Instálalo con "+
					"`codeguard repair` para tener la misma cobertura que el CI.", m))
		case strings.HasSuffix(d, ":error"):
			m := strings.TrimSuffix(d, ":error")
			out = append(out, fmt.Sprintf(
				"`%s` falló y no revisó nada. El motivo está en el log del agente "+
					"(`%%LOCALAPPDATA%%\\CodeGuard\\daemon.log`).", m))
		default:
			out = append(out, fmt.Sprintf("`%s` no se revisó.", d))
		}
	}
	return out
}
