// Fixture de semgrep --test — no es código del producto.
// Casos positivos (ruleid) y negativos (ok) de seguridad-paridad.yaml (csharp).
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;

public class Paridad
{
    public IHtmlContent XssMalo(dynamic Html, string delUsuario)
    {
        // ruleid: csharp-xss
        var a = Html.Raw(delUsuario);
        // ruleid: csharp-xss
        var b = new HtmlString(delUsuario);
        return b;
    }

    public IHtmlContent XssBueno(dynamic Html)
    {
        // ok: csharp-xss
        var a = Html.Raw("<b>texto fijo del programador</b>");
        // ok: csharp-xss
        var b = new HtmlString("<i>tambien fijo</i>");
        return b;
    }

    public string RutaMala(HttpRequest Request, string raiz)
    {
        // ruleid: csharp-path-traversal
        var ruta = Path.Combine(raiz, Request.Query["archivo"]);
        return File.ReadAllText(ruta);
    }

    public string RutaBuena(string raiz, string nombreValidado)
    {
        // ok: csharp-path-traversal
        var ruta = Path.Combine(raiz, nombreValidado);
        return File.ReadAllText(ruta);
    }

    public async Task<string> SsrfMalo(HttpRequest Request, HttpClient cliente)
    {
        var destino = Request.Query["url"];
        // ruleid: csharp-ssrf
        return await cliente.GetStringAsync(destino);
    }

    public async Task<string> SsrfBueno(HttpClient cliente)
    {
        // ok: csharp-ssrf
        return await cliente.GetStringAsync("https://interno.bodesa.local/salud");
    }

    public void DebugMalo(WebApplication app)
    {
        // ruleid: csharp-debug-en-prod
        app.UseDeveloperExceptionPage();
    }

    public void DebugBueno(WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            // ok: csharp-debug-en-prod
            app.UseDeveloperExceptionPage();
        }
    }
}
