package store

import "testing"

// UN REPO SIN REMOTE GUARDABA BAJO UN IDENTIFICADOR Y BUSCABA BAJO OTRO.
//
// El identificador de un repositorio se calculaba en CINCO sitios, y sólo dos
// tenían el respaldo para cuando no hay remote: `local/<carpeta>`. Los otros
// tres —`codeguard stats`, el caché por archivo, y el RepoID que el gancho le
// manda al daemon— llamaban a CanonicalRepoID("") y se quedaban con la cadena
// vacía.
//
// Medido en demo-checkout, un repo recién creado sin `origin`: la base tenía 21
// hallazgos registrados y `codeguard stats` respondía "sin hallazgos
// registrados todavía". La única forma de verlos era `--all`.
//
// Y muerde donde más duele: un repositorio sin remote es el de quien acaba de
// crear algo para probar el producto. Su primera impresión es un agente que
// dice no haber visto nada mientras la base está llena.
//
// Lo destapó un agente comprobando A MANO una afirmación de la documentación
// que otro había dado por buena leyendo el código. Los dos caminos existían y
// eran razonables por separado; sólo se ve al ejecutarlos.
//
// El arreglo es una función y no cinco: dos criterios para la misma pregunta
// acaban discrepando, y aquí ya habían discrepado.
func TestUnRepoSinRemoteTieneIdentificadorYEsSiempreElMismo(t *testing.T) {
	const raiz = `C:\Users\dev\Desktop\demo-checkout`

	sinRemote := RepoIDDe(raiz, "")
	if sinRemote == "" {
		t.Fatal("un repo sin remote se quedaba SIN identificador, así que guardaba bajo " +
			"uno y leía bajo otro: la base se llenaba y stats decía que no había nada")
	}

	// Estable: la misma pregunta, la misma respuesta. Si esto bailara, cada
	// corrida escribiría en un cajón distinto.
	if otra := RepoIDDe(raiz, ""); otra != sinRemote {
		t.Errorf("dos llamadas iguales dieron %q y %q", sinRemote, otra)
	}

	// Y no se confunde con otro repo que se llame distinto.
	if otro := RepoIDDe(`C:\Users\dev\Desktop\demo-tienda`, ""); otro == sinRemote {
		t.Error("dos repos distintos sin remote comparten identificador: sus hallazgos " +
			"se mezclarían en la misma base")
	}
}

// Con remote manda el remote, que es lo que permite que dos clones del MISMO
// repositorio —en dos máquinas, o en dos carpetas— compartan historial. Si el
// respaldo pisara al remote, esa propiedad se perdería.
func TestConRemoteMandaElRemoteYNoLaCarpeta(t *testing.T) {
	const remote = "https://github.com/acme/inventario.git"

	enUnaCarpeta := RepoIDDe(`C:\dev\inventario`, remote)
	enOtra := RepoIDDe(`D:\clones\inventario-copia`, remote)

	if enUnaCarpeta != enOtra {
		t.Errorf("dos clones del mismo repositorio tienen que compartir identificador, "+
			"salieron %q y %q", enUnaCarpeta, enOtra)
	}
	if enUnaCarpeta != CanonicalRepoID(remote) {
		t.Errorf("con remote el identificador es el del remote, salió %q", enUnaCarpeta)
	}
	// Y el respaldo NO se parece al del mismo repo sin remote: son dos cosas
	// distintas y mezclarlas uniría historiales que no son el mismo.
	if enUnaCarpeta == RepoIDDe(`C:\dev\inventario`, "") {
		t.Error("el identificador con remote y sin remote no puede coincidir")
	}
}

// Rutas de Windows con barra invertida y con barra normal son la misma carpeta.
// El daemon las entrega normalizadas y la CLI no, así que si esto no coincidiera
// el panel y la terminal hablarían de repositorios distintos.
func TestLaBarraDeLaRutaNoCambiaElIdentificador(t *testing.T) {
	conBarraInvertida := RepoIDDe(`C:\Users\dev\Desktop\demo-checkout`, "")
	conBarraNormal := RepoIDDe("C:/Users/dev/Desktop/demo-checkout", "")
	if conBarraInvertida != conBarraNormal {
		t.Errorf("la misma carpeta dio dos identificadores: %q y %q",
			conBarraInvertida, conBarraNormal)
	}
}
