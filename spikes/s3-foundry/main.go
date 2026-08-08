// Spike S3 — latencia de Microsoft Foundry desde la red corporativa.
// Criterio: p95 < 8 s en 50 llamadas con un diff realista.
// Uso:
//   set FOUNDRY_ENDPOINT=https://...   (endpoint compatible con la API de OpenAI, con /chat/completions)
//   set FOUNDRY_API_KEY=...
//   set FOUNDRY_MODEL=...              (nombre del deployment/modelo)
//   go run .
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const sampleDiff = `diff --git a/src/Api/UserController.cs b/src/Api/UserController.cs
--- a/src/Api/UserController.cs
+++ b/src/Api/UserController.cs
@@ -10,6 +10,14 @@ public class UserController : ControllerBase
 {
+    [HttpGet("orders/{userId}")]
+    public async Task<IActionResult> GetOrders(string userId)
+    {
+        var user = await _db.Users.FindAsync(userId);
+        var orders = new List<Order>();
+        foreach (var oid in user.OrderIds)
+            orders.Add(await _db.Orders.FindAsync(oid));
+        return Ok(orders);
+    }
 }`

const systemPrompt = `Eres un analizador de código. Responde SOLO JSON con el esquema
{"findings":[{"file":"...","line":0,"severity":"info|warning","confidence":0.0,"message":"...","why":"...","fix_hint":"..."}]}.
Devolver cero hallazgos es válido y frecuente. Cita archivo y línea exactos del diff.`

func main() {
	endpoint := os.Getenv("FOUNDRY_ENDPOINT")
	apiKey := os.Getenv("FOUNDRY_API_KEY")
	model := os.Getenv("FOUNDRY_MODEL")
	if endpoint == "" || apiKey == "" || model == "" {
		fmt.Println("FALTAN VARIABLES: FOUNDRY_ENDPOINT, FOUNDRY_API_KEY, FOUNDRY_MODEL")
		os.Exit(2)
	}
	if !strings.Contains(endpoint, "/chat/completions") {
		endpoint = strings.TrimRight(endpoint, "/") + "/chat/completions"
	}

	const calls = 50
	client := &http.Client{Timeout: 30 * time.Second}
	body, _ := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": "Analiza este diff (pilar: datos):\n\n" + sampleDiff},
		},
		"max_tokens":  800,
		"temperature": 0,
	})

	latencies := make([]time.Duration, 0, calls)
	errors := 0
	for i := 0; i < calls; i++ {
		req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("api-key", apiKey) // Azure-style, por si el gateway lo pide

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			errors++
			fmt.Printf("llamada %02d: ERROR %v\n", i+1, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			errors++
			fmt.Printf("llamada %02d: HTTP %d (%.2f s)\n", i+1, resp.StatusCode, elapsed.Seconds())
			continue
		}
		latencies = append(latencies, elapsed)
		fmt.Printf("llamada %02d: %.2f s\n", i+1, elapsed.Seconds())
	}

	if len(latencies) == 0 {
		fmt.Println("RESULTADO: FAIL — ninguna llamada exitosa")
		os.Exit(1)
	}
	sort.Slice(latencies, func(a, b int) bool { return latencies[a] < latencies[b] })
	p := func(q float64) time.Duration { return latencies[int(q*float64(len(latencies)-1))] }
	fmt.Printf("\nexitosas: %d/%d  errores: %d\n", len(latencies), calls, errors)
	fmt.Printf("p50: %.2f s   p95: %.2f s   max: %.2f s\n",
		p(0.50).Seconds(), p(0.95).Seconds(), latencies[len(latencies)-1].Seconds())
	if p(0.95) < 8*time.Second {
		fmt.Println("RESULTADO: PASS (p95 < 8 s)")
	} else {
		fmt.Println("RESULTADO: FAIL (p95 >= 8 s)")
		os.Exit(1)
	}
}
