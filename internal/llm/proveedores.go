package llm

import "strings"

// CodeGuard no se casa con un proveedor. La capa de consejo habla dos
// dialectos —el de OpenAI, que casi todo el mundo copió, y el de Anthropic,
// que es distinto— y con eso alcanza para los servicios que un equipo usa de
// verdad, incluido un modelo corriendo en la propia máquina.
//
// La API key NUNCA se guarda en un archivo de CodeGuard: la config sólo dice
// el NOMBRE de la variable de entorno que la contiene.

type Dialecto string

const (
	// DialectoOpenAI: /chat/completions con "Authorization: Bearer".
	// Lo hablan OpenAI, Azure AI Foundry, Groq, DeepSeek, OpenRouter,
	// Together, Ollama, LM Studio, vLLM y prácticamente cualquier servidor
	// local moderno.
	DialectoOpenAI Dialecto = "openai"
	// DialectoAnthropic: /v1/messages con "x-api-key" y el system fuera de
	// los mensajes.
	DialectoAnthropic Dialecto = "anthropic"
)

// Proveedor es un preajuste: lo que hay que saber para hablar con un servicio
// sin que el desarrollador tenga que averiguarlo.
type Proveedor struct {
	ID          string
	Nombre      string
	Dialecto    Dialecto
	Endpoint    string // vacío = lo pone el usuario (servicios propios)
	VarEntorno  string // nombre sugerido para la variable con la key
	Modelos     []string
	Comentario  string
	NecesitaKey bool
}

// Proveedores está ordenado como se muestra en la pantalla de configuración:
// primero el de la casa, después los servicios comunes, al final lo local.
var Proveedores = []Proveedor{
	{
		ID: "azure-foundry", Nombre: "Azure AI Foundry", Dialecto: DialectoOpenAI,
		Endpoint:   "https://TU-RECURSO.services.ai.azure.com/openai/v1",
		VarEntorno: "FOUNDRY_API_KEY", NecesitaKey: true,
		Modelos:    []string{"FW-Kimi-K3", "gpt-5.6-sol"},
		Comentario: "El proveedor de la casa. Sustituye TU-RECURSO por el nombre de tu recurso.",
	},
	{
		ID: "openai", Nombre: "OpenAI", Dialecto: DialectoOpenAI,
		Endpoint: "https://api.openai.com/v1", VarEntorno: "OPENAI_API_KEY", NecesitaKey: true,
		Modelos: []string{"gpt-5.6", "gpt-5.6-mini"},
	},
	{
		ID: "anthropic", Nombre: "Anthropic", Dialecto: DialectoAnthropic,
		Endpoint: "https://api.anthropic.com/v1", VarEntorno: "ANTHROPIC_API_KEY", NecesitaKey: true,
		Modelos: []string{"claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"},
	},
	{
		ID: "openrouter", Nombre: "OpenRouter", Dialecto: DialectoOpenAI,
		Endpoint: "https://openrouter.ai/api/v1", VarEntorno: "OPENROUTER_API_KEY", NecesitaKey: true,
		Comentario: "Pasarela a muchos modelos con una sola cuenta.",
	},
	{
		ID: "groq", Nombre: "Groq", Dialecto: DialectoOpenAI,
		Endpoint: "https://api.groq.com/openai/v1", VarEntorno: "GROQ_API_KEY", NecesitaKey: true,
	},
	{
		ID: "deepseek", Nombre: "DeepSeek", Dialecto: DialectoOpenAI,
		Endpoint: "https://api.deepseek.com/v1", VarEntorno: "DEEPSEEK_API_KEY", NecesitaKey: true,
	},
	{
		ID: "ollama", Nombre: "Ollama (local)", Dialecto: DialectoOpenAI,
		Endpoint: "http://localhost:11434/v1", VarEntorno: "", NecesitaKey: false,
		Comentario: "Corre en tu máquina: el código no sale de aquí y no cuesta nada.",
	},
	{
		ID: "lmstudio", Nombre: "LM Studio (local)", Dialecto: DialectoOpenAI,
		Endpoint: "http://localhost:1234/v1", VarEntorno: "", NecesitaKey: false,
		Comentario: "Igual que Ollama: modelo local, sin red.",
	},
	{
		ID: "openai-compatible", Nombre: "Otro compatible con OpenAI", Dialecto: DialectoOpenAI,
		Endpoint: "", VarEntorno: "LLM_API_KEY", NecesitaKey: true,
		Comentario: "vLLM, TGI, LiteLLM o cualquier servidor que exponga /chat/completions.",
	},
}

// BuscarProveedor devuelve el preajuste por id. El segundo valor dice si se
// encontró: un id desconocido cae al dialecto de OpenAI, que es lo que habla
// casi todo, en vez de dejar la capa apagada sin explicación.
func BuscarProveedor(id string) (Proveedor, bool) {
	for _, p := range Proveedores {
		if strings.EqualFold(p.ID, id) {
			return p, true
		}
	}
	return Proveedor{ID: id, Nombre: id, Dialecto: DialectoOpenAI}, false
}

// dialectoDe decide cómo hablarle a un endpoint. El proveedor configurado
// manda; si no hay ninguno, se deduce de la URL para que una config vieja
// —que no tenía este campo— siga funcionando igual.
func dialectoDe(proveedor, endpoint string) Dialecto {
	if proveedor != "" {
		p, _ := BuscarProveedor(proveedor)
		return p.Dialecto
	}
	if strings.Contains(strings.ToLower(endpoint), "api.anthropic.com") {
		return DialectoAnthropic
	}
	return DialectoOpenAI
}
