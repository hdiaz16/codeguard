// Package secreto guarda la clave del modelo fuera del entorno del usuario.
//
// Antes vivía en HKCU\Environment, en texto plano, que es donde la dejaría
// `setx`. Eso tiene dos problemas de distinto tamaño:
//
//   - El grande: cualquier proceso del usuario la lee sin pedirle permiso a
//     nadie. Un .exe abierto desde un correo la tiene con un `Get-ChildItem
//     Env:`. El entorno acotado de los motores (42 variables retenidas) impide
//     que la clave BAJE a gitleaks o a semgrep; no impide que otro programa
//     suyo la lea de lado.
//   - El pequeño pero constante: una variable de entorno la hereda cada
//     proceso hijo por defecto, y basta olvidarse de filtrarla una vez.
//
// Honestidad sobre lo que esto arregla y lo que no: el Credential Manager
// **no es una frontera de seguridad** frente a código que corre como el mismo
// usuario. Un programa suyo puede llamar a CredRead igual que llamamos
// nosotros. Lo que se gana es concreto y vale la pena de todos modos: la clave
// deja de estar en texto plano en el registro, deja de heredarse sola a los
// procesos hijos, y queda cifrada en reposo por DPAPI con las credenciales del
// usuario. Es subir el listón de "cualquiera que liste variables" a "alguien
// que sepa qué está buscando y lo pida a propósito".
package secreto

// Nombre compone el identificador con el que la credencial aparece en el
// Administrador de credenciales de Windows.
//
// Lleva prefijo para que se vea de quién es: alguien revisando su bóveda tiene
// que poder saber qué guardó esto y borrarlo sin adivinar.
func Nombre(variable string) string { return "CodeGuard:" + variable }
