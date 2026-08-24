package main



// cualquier otra cae en su ○ por defecto y se quedaría sin rótulo correcto.
func marcaProyecto(p *panelPayload) string {
	switch {
	case p == nil:
		return "○"
	case p.Verdict == "block":
		return "⛔"
	// Omitido: el embudo se paró en la etapa 0. No hay revisión que enseñar,
	// igual que un proyecto que todavía no se ha analizado nunca.
	case p.Verdict == "skipped":
		return "○"
	case p.Verdict == "pass":
		return "✓"
	}
	return "○" // "—" y cualquier otro: sin análisis todavía
}

// paraPublicar saca del estado compartido la copia que se entrega a otra
// goroutine —el bus de eventos, el explorador—. Exige e.mu tomado.
//
// La copia es superficial y basta: los campos de slice (OtrosRepos, Degraded,
// Findings) se sustituyen enteros, nunca se editan elemento a elemento, así
// que quien se quedó con el slice viejo se queda con un array que ya nadie
// escribe. Si algún día se muta un slice en su sitio, esto deja de bastar.
func paraPublicar(p *panelPayload) *panelPayload {
	if p == nil {
		return nil
	}
	copia := *p
	return &copia
}

// publicarLocked es LA operación sobre el contexto: recalcula la lista de
// proyectos, se la deja al contexto de raiz, lo vuelve el activo y devuelve la
// copia que viaja al panel. Todo en una sola sección crítica — exige e.mu.
//
// Devuelve nil si raiz no tiene contexto (p.ej. su carpeta ya no existe y la
// lista acaba de darlo de baja).
func (e *escritorio) publicarLocked(raiz string) *panelPayload {
	// La lista primero: da de alta los enrolados y da de baja los borrados,
	// así que decide si raiz sigue siendo un proyecto.
	lista := e.listaProyectosLocked(raiz)
	p := e.porProyecto[raiz]
	if p == nil {
		return nil
	}
	p.OtrosRepos = lista
	e.activo = p
	return paraPublicar(p)
}

// activoActual entrega una copia del contexto activo, o nil si no hay ninguno.
// Es la ÚNICA forma de leer e.activo desde fuera de una sección crítica.
func (e *escritorio) activoActual() *panelPayload {
	e.mu.Lock()
	defer e.mu.Unlock()
	return paraPublicar(e.activo)
}

// sembrarDesdeRegistro llena el contexto activo cuando no hay ninguno y
// devuelve la copia que el panel tiene que pintar (nil si no hay nada).
//
// Daemon recién reiniciado: sin análisis en memoria, pero los proyectos
// enrolados EXISTEN. Un panel vacío aquí se lee como "se perdieron mis repos"
// — pasó tras actualizar a 1.2.0. Se muestra el primero del registro con su
// estado placeholder; el primer commit lo llena de verdad.
//
// Comprobar el activo y sembrarlo son el mismo paso: partidos en dos, un
// análisis que entraba por el IPC en medio se perdía entero, y el usuario veía
