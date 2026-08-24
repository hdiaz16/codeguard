"""Genera un proyecto TS mediano (~300 archivos, con imports cruzados)
para medir tsc --noEmit frio vs incremental caliente."""

import json
import os

BASE = os.path.join(os.path.dirname(__file__), "tsproject")
SRC = os.path.join(BASE, "src")
N_MODULES = 1500

os.makedirs(SRC, exist_ok=True)

for i in range(N_MODULES):
    dep = (
        f"import {{ value{(i + 1) % N_MODULES} }} from './mod{(i + 1) % N_MODULES}';\n"
        if i != N_MODULES - 1
        else ""
    )
    ref = f"value{(i + 1) % N_MODULES} +" if i != N_MODULES - 1 else ""
    content = f"""{dep}
export interface Record{i} {{
  id: string;
  index: number;
  tags: string[];
}}

export function build{i}(id: string): Record{i} {{
  return {{ id, index: {i}, tags: ['gen'] }};
}}

export const value{i}: number = {ref} {i};

export function describe{i}(r: Record{i}): string {{
  return `${{r.id}}#${{r.index}}`;
}}
"""
    with open(
        os.path.join(SRC, f"mod{i}.ts"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(content)

with open(os.path.join(SRC, "index.ts"), "w", encoding="utf-8", newline="\n") as f:
    f.write("".join(f"export * from './mod{i}';\n" for i in range(N_MODULES)))

tsconfig = {
    "compilerOptions": {
        "target": "ES2022",
        "module": "ESNext",
        "moduleResolution": "bundler",
        "strict": True,
        "noEmit": True,
        "incremental": True,
        "tsBuildInfoFile": ".tscache/buildinfo.json",
    },
    "include": ["src/**/*"],
}
with open(os.path.join(BASE, "tsconfig.json"), "w", encoding="utf-8") as f:
    json.dump(tsconfig, f, indent=2)

print(f"{N_MODULES + 1} archivos TS generados en {BASE}")
