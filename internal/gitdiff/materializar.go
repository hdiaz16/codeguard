package gitdiff

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"codeguard/internal/engines/proc"
)

// InstantaneaIndice es un árbol temporal construido exclusivamente con los
// blobs del índice activo. No contiene .git ni copia bytes del worktree.
//
// Esa distinción es la garantía: durante `git add -p` el disco y el índice son
// dos programas distintos, y el que se debe revisar es el que Git va a guardar.
type InstantaneaIndice struct {
	Root       string
	Tree       string
	Submodulos []string
}

// Cerrar elimina la instantánea. Es idempotente en la práctica: RemoveAll no
// falla cuando el directorio ya no existe.
func (i *InstantaneaIndice) Cerrar() error {
	if i == nil || i.Root == "" {
		return nil
	}
	return os.RemoveAll(i.Root)
}

type entradaIndice struct {
	modo, objeto, ruta string
}

// MaterializarIndice congela el índice que Git anunció al proceso —incluido un
// GIT_INDEX_FILE temporal de `git commit -a`— en un directorio nuevo.
//
// No usa checkout-index: los filtros smudge se definen desde el repositorio y
// pueden ejecutar procesos. cat-file entrega el blob crudo, sin filtros, hooks
// ni lectura del worktree. Los enlaces simbólicos se escriben como archivos con
// su destino, igual que un checkout de Git para Windows con symlinks apagados;
// crear el enlace real permitiría que un analizador escapara de la instantánea.
func MaterializarIndice(repoRoot string) (_ *InstantaneaIndice, err error) {
	arbolAntes, err := ArbolIndice(repoRoot)
	if err != nil {
		return nil, err
	}
	entradas, err := entradasDelIndice(repoRoot)
	if err != nil {
		return nil, err
	}

	raiz, err := os.MkdirTemp("", "codeguard-index-")
	if err != nil {
		return nil, fmt.Errorf("crear instantánea del índice: %w", err)
	}
	inst := &InstantaneaIndice{Root: raiz}
	defer func() {
		if err != nil {
			_ = inst.Cerrar()
		}
	}()

	var blobs []entradaIndice
	for _, e := range entradas {
		if e.modo == "160000" { // gitlink: el commit guarda el SHA, no sus archivos.
			ruta, rutaErr := rutaSegura(raiz, e.ruta)
			if rutaErr != nil {
				return nil, rutaErr
			}
			if err = os.MkdirAll(ruta, 0o700); err != nil {
				return nil, fmt.Errorf("materializar submódulo %q: %w", e.ruta, err)
			}
			inst.Submodulos = append(inst.Submodulos, e.ruta)
			continue
		}
		if e.modo != "100644" && e.modo != "100755" && e.modo != "120000" {
			return nil, fmt.Errorf("entrada %q del índice con modo no soportado %s", e.ruta, e.modo)
		}
		blobs = append(blobs, e)
	}

	if err = escribirBlobs(repoRoot, raiz, blobs); err != nil {
		return nil, err
	}
	arbolDespues, err := ArbolIndice(repoRoot)
	if err != nil {
		return nil, err
	}
	if arbolAntes != arbolDespues {
		return nil, fmt.Errorf("el índice cambió mientras se construía la instantánea (%s → %s)", arbolAntes, arbolDespues)
	}
	inst.Tree = arbolAntes
	return inst, nil
}

// ArbolIndice devuelve la identidad byte-exacta del índice activo. write-tree
// honra GIT_INDEX_FILE y no modifica el índice; el objeto resultante permite
// demostrar que diff e instantánea describen el mismo commit candidato.
func ArbolIndice(repoRoot string) (string, error) {
	out, err := run(repoRoot, "write-tree")
	if err != nil {
		return "", fmt.Errorf("identificar índice: %w", err)
	}
	arbol := strings.TrimSpace(string(out))
	if arbol == "" {
		return "", errors.New("git write-tree no devolvió una identidad")
	}
	return arbol, nil
}

func entradasDelIndice(repoRoot string) ([]entradaIndice, error) {
	out, err := run(repoRoot, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, fmt.Errorf("enumerar índice: %w", err)
	}
	var entradas []entradaIndice
	for _, registro := range bytes.Split(out, []byte{0}) {
		if len(registro) == 0 {
			continue
		}
		tab := bytes.IndexByte(registro, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("entrada ilegible en el índice")
		}
		meta := strings.Fields(string(registro[:tab]))
		if len(meta) != 3 {
			return nil, fmt.Errorf("metadatos ilegibles en el índice para %q", registro[tab+1:])
		}
		if meta[2] != "0" {
			return nil, fmt.Errorf("el índice tiene un conflicto sin resolver en %q (stage %s)", registro[tab+1:], meta[2])
		}
		entradas = append(entradas, entradaIndice{
			modo: meta[0], objeto: meta[1], ruta: string(registro[tab+1:]),
		})
	}
	return entradas, nil
}

func escribirBlobs(repoRoot, raiz string, entradas []entradaIndice) (err error) {
	if len(entradas) == 0 {
		return nil
	}

	cmd := exec.Command("git", "-c", "core.quotePath=false", "cat-file", "--batch")
	proc.SinVentana(cmd)
	cmd.Dir = repoRoot
	cmd.Env = proc.EntornoGit()
	entrada, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("abrir entrada de git cat-file: %w", err)
	}
	salida, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("abrir salida de git cat-file: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("iniciar git cat-file: %w", err)
	}
	terminado := false
	defer func() {
		_ = entrada.Close()
		if !terminado && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	lector := bufio.NewReader(salida)
	for _, e := range entradas {
		if _, err = io.WriteString(entrada, e.objeto+"\n"); err != nil {
			return fmt.Errorf("pedir blob %s a git: %w", e.objeto, err)
		}
		cabecera, readErr := lector.ReadString('\n')
		if readErr != nil {
			return fmt.Errorf("leer blob de %q: %w (%s)", e.ruta, readErr, strings.TrimSpace(stderr.String()))
		}
		campos := strings.Fields(cabecera)
		if len(campos) != 3 || campos[1] != "blob" {
			return fmt.Errorf("git devolvió una cabecera inválida para %q: %q", e.ruta, strings.TrimSpace(cabecera))
		}
		tamano, parseErr := strconv.ParseInt(campos[2], 10, 64)
		if parseErr != nil || tamano < 0 {
			return fmt.Errorf("git devolvió un tamaño inválido para %q: %q", e.ruta, campos[2])
		}

		destino, rutaErr := rutaSegura(raiz, e.ruta)
		if rutaErr != nil {
			return rutaErr
		}
		if err = os.MkdirAll(filepath.Dir(destino), 0o700); err != nil {
			return fmt.Errorf("crear carpeta para %q: %w", e.ruta, err)
		}
		archivo, openErr := os.OpenFile(destino, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if openErr != nil {
			return fmt.Errorf("crear %q en la instantánea: %w", e.ruta, openErr)
		}
		_, copyErr := io.CopyN(archivo, lector, tamano)
		closeErr := archivo.Close()
		if copyErr != nil {
			return fmt.Errorf("escribir %q en la instantánea: %w", e.ruta, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("cerrar %q en la instantánea: %w", e.ruta, closeErr)
		}
		separador, readErr := lector.ReadByte()
		if readErr != nil || separador != '\n' {
			return fmt.Errorf("respuesta incompleta de git para %q", e.ruta)
		}
		if e.modo == "100755" {
			if err = os.Chmod(destino, 0o700); err != nil {
				return fmt.Errorf("aplicar modo ejecutable a %q: %w", e.ruta, err)
			}
		}
	}

	if err = entrada.Close(); err != nil {
		return fmt.Errorf("cerrar entrada de git cat-file: %w", err)
	}
	if err = cmd.Wait(); err != nil {
		return fmt.Errorf("git cat-file: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	terminado = true
	return nil
}

func rutaSegura(raiz, rel string) (string, error) {
	local := filepath.FromSlash(rel)
	if rel == "" || !filepath.IsLocal(local) {
		return "", fmt.Errorf("ruta no local en el índice: %q", rel)
	}
	for _, parte := range strings.FieldsFunc(local, func(r rune) bool { return r == '/' || r == '\\' }) {
		if strings.EqualFold(parte, ".git") {
			return "", fmt.Errorf("ruta reservada en el índice: %q", rel)
		}
	}
	destino := filepath.Join(raiz, local)
	relativo, err := filepath.Rel(raiz, destino)
	if err != nil || relativo == ".." || strings.HasPrefix(relativo, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("ruta fuera de la instantánea: %q", rel)
	}
	return destino, nil
}
