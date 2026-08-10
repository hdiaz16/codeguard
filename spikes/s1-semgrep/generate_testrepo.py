"""Genera el repo de prueba del spike S1: ~20 archivos en 5 lenguajes,
con defectos sembrados que las house-rules deben detectar."""

import os

BASE = os.path.join(os.path.dirname(__file__), "testrepo")

TS_CLEAN = """export function sum(values: number[]): number {
  return values.reduce((a, b) => a + b, 0);
}
export function formatUser(name: string, age: number): string {
  return `${name} (${age})`;
}
"""

TS_BAD = """export function process(data: any) {
  return JSON.stringify(data);
}
export async function loadAll(db: { query: (s: string) => Promise<unknown> }, ids: string[]) {
  const out = [];
  for (const id of ids) {
    out.push(await db.query(`SELECT * FROM users WHERE id = '${id}'`));
  }
  return out;
}
"""

GO_CLEAN = """package util

import "strings"

func Normalize(s string) string {
\treturn strings.ToLower(strings.TrimSpace(s))
}
"""

GO_BAD = """package util

import "os"

func WriteLog(msg string) {
\tf, err := os.Create("app.log")
\tif err != nil {
\t\treturn
\t}
\t_ = f.Close()
}
"""

PY_CLEAN = """def average(values):
    if not values:
        return 0.0
    return sum(values) / len(values)
"""

PY_BAD = """def run_expr(user_input):
    return eval(user_input)
"""

CS_CLEAN = """namespace Demo;

public static class MathUtil
{
    public static int Sum(int[] values)
    {
        var total = 0;
        foreach (var v in values) total += v;
        return total;
    }
}
"""

CS_BAD = """namespace Demo;

public class Repo
{
    private const string Conn = "Server=prod-db;Database=app;User Id=sa;Password=SuperSecret123";

    public void Save(string data)
    {
        try { System.IO.File.WriteAllText("out.txt", data); }
        catch (System.Exception e) { }
    }
}
"""

JAVA_CLEAN = """package demo;

public final class Text {
    private Text() {}
    public static String clean(String s) {
        return s == null ? "" : s.trim();
    }
}
"""

JAVA_BAD = """package demo;

public class Loader {
    public void load(String path) {
        try {
            java.nio.file.Files.readAllBytes(java.nio.file.Path.of(path));
        } catch (Exception e) { }
    }
}
"""

files = {}
for i in range(4):
    files[f"src/ts/module{i}.ts"] = TS_CLEAN
files["src/ts/bad.ts"] = TS_BAD
for i in range(3):
    files[f"src/go/util{i}.go"] = GO_CLEAN
files["src/go/bad.go"] = GO_BAD
for i in range(3):
    files[f"src/py/mod{i}.py"] = PY_CLEAN
files["src/py/bad.py"] = PY_BAD
for i in range(3):
    files[f"src/cs/Util{i}.cs"] = CS_CLEAN
files["src/cs/Bad.cs"] = CS_BAD
for i in range(2):
    files[f"src/java/Text{i}.java"] = JAVA_CLEAN
files["src/java/Bad.java"] = JAVA_BAD

for rel, content in files.items():
    path = os.path.join(BASE, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

print(f"{len(files)} archivos generados en {BASE}")
