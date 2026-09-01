package linters

import (
	"fmt"
	"strings"
)

type guiaSeguridad struct {
	porQue  string
	arreglo string
}

var guiasPorCWE = map[string]guiaSeguridad{
	"22": {
		porQue:  "Una ruta controlable puede escapar del directorio previsto y permitir lectura o escritura de archivos con los privilegios del proceso.",
		arreglo: "Normaliza y resuelve la ruta final, comprueba que permanezca dentro del directorio base y rechaza rutas absolutas, enlaces o segmentos de traversal.",
	},
	"78": {
		porQue:  "Una entrada controlable que alcanza un intérprete de comandos permite ejecutar operaciones adicionales con los privilegios de la aplicación.",
		arreglo: "Evita el shell, fija el ejecutable y pasa cada argumento mediante la API estructurada; valida cualquier valor variable con una lista permitida.",
	},
	"79": {
		porQue:  "Renderizar entrada no confiable como HTML permite ejecutar scripts en el origen de la aplicación y comprometer sesiones o datos.",
		arreglo: "Renderiza como texto por defecto; si necesitas HTML, sanitízalo con una biblioteca mantenida y agrega una prueba con una carga XSS.",
	},
	"89": {
		porQue:  "Construir SQL con datos variables permite alterar la consulta, leer o modificar información y eludir controles de autorización.",
		arreglo: "Usa parámetros enlazados para todos los valores; para nombres de tabla o columna aplica una lista cerrada de identificadores permitidos.",
	},
	"94": {
		porQue:  "Evaluar datos como código convierte una entrada controlable en ejecución con los privilegios de la aplicación.",
		arreglo: "Sustituye la evaluación por un parser o una tabla cerrada de operaciones y evita que datos externos alcancen una primitiva de ejecución.",
	},
	"95": {
		porQue:  "Evaluar datos como código convierte una entrada controlable en ejecución con los privilegios de la aplicación.",
		arreglo: "Sustituye la evaluación por un parser o una tabla cerrada de operaciones y evita que datos externos alcancen una primitiva de ejecución.",
	},
	"259": {
		porQue:  "Una credencial incluida en código se replica a clones, historial y artefactos, y deja de poder considerarse secreta.",
		arreglo: "Revoca y rota el valor, elimínalo del código y cárgalo desde un gestor de secretos con permisos mínimos y auditoría.",
	},
	"295": {
		porQue:  "Omitir la validación TLS permite que un intermediario suplante el servidor y lea o modifique el tráfico.",
		arreglo: "Valida cadena y hostname; para certificados privados instala la CA confiable o aplica pinning con un procedimiento de rotación.",
	},
	"327": {
		porQue:  "Una primitiva criptográfica obsoleta o mal configurada puede permitir colisiones, recuperación o modificación silenciosa de los datos.",
		arreglo: "Usa una API criptográfica de alto nivel y mantenida, con algoritmos actuales, cifrado autenticado, nonces únicos y gestión segura de claves.",
	},
	"330": {
		porQue:  "Los valores sensibles generados con entropía insuficiente pueden predecirse y permiten adivinar tokens, claves o nonces.",
		arreglo: "Obtén el valor de la fuente criptográfica del sistema, usa suficiente entropía y no reutilices semillas, claves ni nonces.",
	},
	"338": {
		porQue:  "Los generadores no criptográficos son predecibles y permiten adivinar tokens, códigos, claves o nonces.",
		arreglo: "Usa el generador criptográfico del sistema para cada valor sensible y no reutilices semillas ni nonces.",
	},
	"502": {
		porQue:  "Reconstruir objetos desde contenido no confiable puede activar tipos o gadgets que ejecutan código durante la deserialización.",
		arreglo: "Usa un formato sin ejecución como JSON o Protobuf, valida su esquema y limita tamaño y profundidad antes de procesarlo.",
	},
	"601": {
		porQue:  "Una redirección controlable permite enviar al usuario a un sitio malicioso conservando la confianza del dominio original.",
		arreglo: "Acepta sólo rutas relativas o destinos de una lista exacta de orígenes y rechaza esquemas, hosts y variantes codificadas no permitidas.",
	},
	"611": {
		porQue:  "Procesar entidades XML externas permite leer archivos locales, acceder a servicios internos o agotar recursos.",
		arreglo: "Deshabilita DTD y resolución externa en el parser o usa una implementación segura; prueba que una entidad externa sea rechazada.",
	},
	"703": {
		porQue:  "Ignorar un error puede continuar con estado incompleto o datos no validados y ocultar la causa real del fallo.",
		arreglo: "Comprueba y propaga el error en el mismo límite donde ocurre; agrega contexto sin perder la causa y prueba el camino de fallo.",
	},
	"798": {
		porQue:  "Una credencial incluida en código se replica a clones, historial y artefactos, y deja de poder considerarse secreta.",
		arreglo: "Revoca y rota el valor, elimínalo del código y cárgalo desde un gestor de secretos con permisos mínimos y auditoría.",
	},
}

func retroalimentacionSeguridad(motor, regla, cwe, detalle string) (string, string) {
	clave := strings.TrimPrefix(strings.TrimSpace(cwe), "CWE-")
	if guia, ok := guiasPorCWE[clave]; ok {
		return guia.porQue, guia.arreglo
	}
	identidad := strings.TrimSpace(motor + " " + regla)
	porQue := fmt.Sprintf("%s clasificó este patrón como un riesgo de seguridad determinista; dejarlo sin resolver conserva la condición descrita en el hallazgo.", identidad)
	arreglo := "Elimina la condición señalada en el mensaje, evita silenciar la regla como sustituto de la corrección y agrega una prueba que demuestre que entrada no confiable ya no alcanza la operación riesgosa."
	if strings.TrimSpace(detalle) == "" {
		porQue = fmt.Sprintf("%s detectó un patrón de seguridad que requiere revisión antes de integrar el cambio.", identidad)
	}
	return porQue, arreglo
}
