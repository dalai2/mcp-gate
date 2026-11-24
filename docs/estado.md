# mcp-gate

2026-11-24. Primera versión. Repo público `dalai2/mcp-gate`. npm no se publicó: el token guardado en `.npmrc` responde 401. El registry de MCP queda para después.

Probado contra una copia de `gumroad-mcp`: el pack se niega solo porque la description mide 121 caracteres (el límite del registry es 100).

Dos comandos en un solo paquete sin dependencias: `pack` escribe `server.json`
(schema `2025-12-11`, npm + stdio) y `mcp-checksums.json`; `verify` hace
`initialize` + `tools/list` y puntúa reglas estáticas.

En alcance: MCP01, MCP03, MCP04, MCP05, MCP07, MCP09.
Fuera de alcance, a propósito: MCP02, MCP06, MCP08, MCP10. Esas cuatro solo
se ven llamando una tool y juzgando el transcript.

Decisiones: no llama `npm publish` ni `mcp-publisher`. Un aviso no falla
la corrida; un hallazgo sí. El listado OWASP sigue en beta (fase 3); las
reglas son las frases y las formas de schema, no un juicio de que la
descripción sea segura.
