# 🧠 Mindset y Reglas de Inferencia (Elite Flow - GEMINI Edition)
- **Circuit Breaker (CRÍTICO):** Máximo 3 intentos de corrección. Al tercer fallo, detente. PROHIBIDO entrar en bucles ciegos.
- **Cambios Quirúrgicos:** Toca solo lo estrictamente necesario.
- **Pipeline Ágil:** Usa herramientas de búsqueda OBLIGATORIAMENTE. Prohibido usar `read_file` en archivos >200 líneas sin permiso o acotación previa. **PROHIBIDO también orientarte con `cat`/`wc`/`sed`/`head`/`tail`/`awk` sobre ficheros FUENTE** (eso es teatro de cumplimiento, no Tier 1): para LOCALIZAR usa `blast-search`; para LEER un fichero ya identificado usa la herramienta `read_file`. (Esos comandos sobre JSON/MD/logs o como filtro tras un pipe siguen permitidos.) **Excepción: `wc -l` PURO sobre fuente SÍ está permitido** — contar líneas no vuelca contenido, y esta misma regla exige conocer el tamaño antes de un `read_file` >200 líneas. `wc -c`, `wc` a secas o `wc` encadenado con un lector siguen bloqueados.
- **Compresión:** Salidas de terminal > 50 líneas DEBEN pasar por `rtk pipe -f <filtro>` (p. ej. `| rtk pipe -f git-log`). La forma importa: `| rtk` a secas sale **rc=2** e imprime el help (pierdes la salida); `| rtk pipe` sin `-f` es passthrough y **no ahorra un token**; un `-f` que no exista sale **rc=1** y también pierde la salida. **`git status` NO está en la allowlist y su filtro `-f git-status` está PROHIBIDO:** descarta la 1.ª línea de stdin, así que un estado de un solo fichero se reporta como `clean — nothing to commit` con rc=0 — falso negativo silencioso. `git status --short` ya cabe en pantalla: va sin pipe. Los filtros válidos por comando están declarados en `.claude/hooks/blast-rtk-lists.json` — PROHIBIDO inventar nombres de filtro. Si no hay filtro para ese comando (p. ej. `blast-search`), no lo pipees: comprimir de mentira solo añade riesgo. El gate `blast-require-rtk.sh` bloquea antes de ejecutar el `| rtk` a secas, el `| rtk pipe` sin `-f` y cualquier `blast-search | rtk`.
- **Atomicidad de `run_command` (AUTONOMÍA):** una tool-call `run_command` = **un comando que el allowlist pueda casar**. El harness solo auto-aprueba si prueba que el comando ENTERO cae bajo una regla permitida; **NO sabe descomponer** `for`/`while`, `$(...)`/backticks, `if`/`case`/heredocs ni redirecciones a fichero (`> ruta`) → cada envoltura de esas fuerza una aprobación humana y rompe la autonomía. Sácalas a pasos propios. Los pipes a `rtk`/`jq`/`grep`-filtro (`|`) y las cadenas de hojas ya permitidas (`&&`/`;`) sí se descomponen. **Regla:** si un one-liner mezcla control de flujo (bucle/subshell/condicional) con mutación, pártelo; el que ata exploración+mutación en un solo string es el que garantiza el prompt.
- **Registro del trío:** Tras el éxito, **commitea**: el hook `prepare-commit-msg` sella los trailers `Blast-Query`/`Blast-Case`/`Blast-Manifest` (qué pedí / qué se recuperó) y `Blast-Plan-Closed` (planes cerrados en el commit); el diff es qué modifiqué. **El trío es por MANIFIESTO, no por commit:** el 2.º commit que se apoya en la misma búsqueda lleva `Blast-Retrieval: reused manifest@<sig>` en vez del trío; un commit sin búsqueda lleva `Blast-Retrieval: none`. `git log` + trailers son la única fuente de continuidad — no existe ningún digest aparte.

- **🛑 REGLA DE INTERCEPCIÓN (ANTI-IMPULSOS):** Si el usuario te da una orden cruda o vaga (ej. "arregla este bug", "revisa el precio"), TIENES ESTRICTAMENTE PROHIBIDO saltar a leer o editar archivos a ciegas.
- **Auto-Aplicación del Pipeline:** Ante una orden directa, DEBES pausar y ejecutar internamente los Tiers:
  1. Primero, avisa al usuario: "Iniciando Tier 1 (Búsqueda Quirúrgica)".
  2. **Toda búsqueda pasa por `blast-search` (rpgrep/rg/sg). `grep` está PROHIBIDO.**
     **PROHIBIDO reformular/inventar la query con el agente antes de buscar:** corre
     `blast-search` con la intención cruda tal cual. Una query vaga es un fork abierto,
     no una tarea del LLM.
     **El carril `semantic` NO es semántico: es BM25 léxico** (rpgrep = Xor + BM25 +
     MinHash + QUBO, sin embeddings y sin stemming). Solo puntúa documentos que
     contienen los tokens **literales** de la query, así que prosa castellana contra
     código en inglés puntúa ~0: es inalcanzable aritméticamente, no mal ordenado.
     No esperes que "entienda" la intención difusa — y **elegir CARRIL no es
     reformular la intención**: pasar al identificador real (`BiometricAuthService`),
     a `lit:<cadena>`, o acotar con `--lang`/`--root` es la respuesta correcta a un
     desajuste de vocabulario. Inventar sinónimos de la prosa NO lo es.
  3. **Si el manifiesto vuelve disperso / baja confianza / 0 hits, es un DIAGNÓSTICO, no un fallo a parchear improvisando:**
     - ambigüedad de **hecho/vocabulario** → drill-down en el MISMO hilo (`--thread <id>`), acotado al scope.
     - ambigüedad de **preferencia** → UNA pregunta al HUMANO. PROHIBIDO que el agente adivine la intención.
     - desajuste de **vocabulario/idioma** (la query es prosa, el código está en otro idioma o usa otros nombres) → **cambiar de CARRIL, no de sinónimo**: identificador exacto, `lit:`, `--lang`, `--root`.
  4. Ejecuta el Tier 2 (`edit_file`/`write_file`) y Tier 3 (`run_command` con linters/tests) respetando la regla de "Cambios Quirúrgicos". NUNCA improvises.
     **PROHIBIDO ejecutar Read/read_file/view_file sobre un fichero inmediatamente después de editarlo:** el output de la herramienta de edición ya confirma el estado. Releerlo genera prefijo rancio (`[3i]`). Si necesitas re-inspeccionar tras editar, commitea antes y limpia el contexto (`/compact` o reinicio).
  **Excepción — paso de un plan activo:** un fichero listado LITERALMENTE en la «Superficie de cambio» del plan activo se abre con `read_file` directo, sin `blast-search` previo.

- **📐 Ciclo de Planes (PLAN-SCHEMA.md):** Ante cualquier tarea no trivial o de múltiples pasos, el punto de entrada es autorizar/crear un plan en `.claude/plans/<id>.md` (o en `.claude/plans/queued/NN-<id>.md`) siguiendo `PLAN-SCHEMA.md`: hechos anclados a `blast-search --thread <id>`, forks de preferencia resueltos con su PORQUE, `Superficie de cambio` explícita y `Criterio de HECHO` con comandos ejecutables. PROHIBIDO operar en bucles ad-hoc de búsquedas y ediciones dispersas sin plan formal.

- **🧵 JERARQUÍA DE BÚSQUEDA (ANTI-BUCLE):** Una tarea = **un hilo de búsqueda**. La 1ª `blast-search` abre el hilo con un id (`--thread <id>`) y fija el *scope* (los ficheros de su manifiesto). **TODO refinamiento posterior de la misma tarea DEBE ir DENTRO de ese hilo**: `blast-search "<consulta más fina>" --thread <mismo id>`. **PROHIBIDO** abrir una `blast-search` tree-wide nueva (sin `--thread`, o con id distinto) para "ampliar" dentro de la misma tarea — eso reinicia el contexto y es el bucle que el audit detecta.

### ⚙️ Telemetría y Pipeline (BLAST Engine)
- **Higiene de Memoria:** Si el contexto se infla con trabajo acumulado, commitea y compacta/limpia sesión (`/compact` o reinicio). La continuidad no se guarda en resúmenes de handoff; vive en `git log` + trailers `Blast-*`, y los planes en disco sobreviven.
- **Invariante Pre-Compact:** ANTES de compactar o sugerir `/compact`, es OBLIGATORIO asegurar que todo cambio pendiente esté commiteado (`git status --short`). Si hay modificaciones o archivos sin registrar, se DEBEN commitear antes del compact para que `prepare-commit-msg` selle los trailers `Blast-*` (el hook `.claude/hooks/blast-pre-compact.sh` actúa además como salvaguarda determinista).
- **Pipeline Enforcement:** Triaje Estricto: Obligatorio aislar el contexto antes de actuar.
- **Distribución (CLI global):** el toolchain vive en el PATH global (`blast <sub>` / `blast-search`).

### 🛡️ Reglas Anti-Racionalización (No Excusas)
- **Excusa de la IA:** "Refactorizaré este código espagueti en un PR posterior".
- **Contra-argumento:** PROHIBIDO. Si tocas un archivo y ves deuda técnica en el nodo que estás editando, la aislas en ese momento.
- **Excusa de la IA:** "El cambio parece correcto, no necesito ejecutar el linter".
- **Contra-argumento:** FALSO. "Seems right" nunca es suficiente. La verificación (Tier 3) con herramientas nativas es innegociable.

