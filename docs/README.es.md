# PrivScout

**Documentación:** [English](../README.md) | Español

PrivScout es una herramienta de línea de comandos para priorizar resultados de
enumeración de escalada de privilegios en Linux. Lee archivos de texto con
rutas SUID, reglas de `sudo -l` y file capabilities, elimina ruido habitual y
muestra primero lo que merece revisión manual.

Su fuente principal de técnicas es **GTFOBins**. PrivScout añade análisis de
contexto, puntuación explicable, líneas base de paquetes comunes y correlaciones
offline con software de terceros, Exploit-DB y CVE.

PrivScout no explota el sistema, no ejecuta los binarios encontrados y no se
conecta al objetivo. Úsalo únicamente en sistemas propios o con autorización.

## Cómo funciona

1. Lee cualquier archivo `.txt` o la entrada estándar.
2. Detecta automáticamente entradas SUID, sudo y capabilities.
3. Normaliza nombres y agrupa observaciones repetidas.
4. Reduce el ruido de binarios y combinaciones esperadas del sistema.
5. Consulta la base offline de GTFOBins para el contexto detectado.
6. Añade señales como rutas inusuales, argumentos sudo, capabilities de alto
   impacto y posibles productos de terceros.
7. Asigna una puntuación de 0 a 100 y presenta acciones para validación manual.

Una coincidencia con GTFOBins indica que existe una técnica documentada para
ese contexto. No demuestra por sí sola que el objetivo sea vulnerable.

## Requisitos

- Python 3.11 o posterior.
- Internet para instalar dependencias y ejecutar `privscout update`.
- Los análisis normales funcionan offline.

## Instalación

### Linux: comando disponible desde cualquier directorio

Para una aplicación de línea de comandos, la opción recomendada es
[pipx](https://pipx.pypa.io/stable/). Mantiene PrivScout aislado del Python del
sistema y expone `privscout` en el `PATH` del usuario:

```bash
# Debian, Ubuntu, Kali y derivados
sudo apt install pipx
pipx ensurepath

# Ejecuta esto dentro del repositorio clonado de PrivScout
pipx install .
```

Abre una terminal nueva después de `pipx ensurepath`. Desde ese momento podrás
ejecutar `privscout` en cualquier directorio sin activar un entorno.

### Windows PowerShell

```powershell
py -m pip install --user pipx
py -m pipx ensurepath

# Ejecuta esto dentro del repositorio clonado de PrivScout
pipx install .
```

Abre una ventana nueva de PowerShell antes de utilizar el comando.

Comprueba la instalación:

```console
privscout version
privscout --help
```

### Actualizar la base de datos offline

Después de instalar, se recomienda descargar los datos más recientes de
GTFOBins, Exploit-DB y los CVE relevantes:

```console
privscout update
```

Este comando necesita conexión a Internet. PrivScout incluye una base de datos
inicial, así que la actualización es recomendable, pero no obligatoria para el
primer análisis. Una vez finalizada, los análisis normales siguen funcionando
offline. Usa `privscout update --json` para obtener un informe de actualización
procesable por otras herramientas.

## Uso

PrivScout no requiere una carpeta especial. Puede analizar cualquier archivo de
texto indicando su ruta:

```console
privscout analyze enumeracion.txt --lang es
privscout analyze C:\ruta\al\resultado.txt --lang es
```

`analyze` detecta automáticamente el tipo de cada entrada. También puedes
indicar una fuente concreta:

```console
privscout suid suids.txt --lang es
privscout sudo sudo.txt --lang es
privscout caps capabilities.txt --lang es
```

Para leer desde la entrada estándar utiliza `-`:

```bash
cat enumeracion.txt | privscout analyze - --lang es
```

```powershell
Get-Content .\enumeracion.txt | privscout analyze - --lang es
```

## Recopilar la información

En el sistema Linux autorizado:

```bash
find / -perm -4000 -type f 2>/dev/null
sudo -l
getcap -r / 2>/dev/null
```

Puedes guardar cada salida por separado o combinarlas con encabezados:

```text
=== SUID ===
/usr/bin/passwd
/usr/local/bin/custom-helper

=== SUDO ===
(root) NOPASSWD: /usr/bin/systemctl restart demo.service

=== CAPABILITIES ===
/usr/bin/ping cap_net_raw=ep
/usr/bin/python3.11 cap_setuid=ep
```

## Opciones útiles

- `--lang es`: salida en español.
- `--explain`: explica la puntuación.
- `--show-all`: incluye entradas comunes y de prioridad baja.
- `--min-score N`: establece el umbral mínimo.
- `--json`: genera una salida estructurada.
- `--no-color`: elimina códigos de color ANSI.
- `--verbose`: muestra diagnósticos del análisis.

```console
privscout analyze enumeracion.txt --lang es --explain
privscout analyze enumeracion.txt --min-score 70 --no-color
privscout sudo sudo.txt --json > informe.json
```

## Interpretar los resultados

| Puntuación | Prioridad |
| ---: | --- |
| 90–100 | Crítica |
| 70–89 | Alta |
| 40–69 | Media |
| 20–39 | Baja |
| 0–19 | Informativa |

De forma predeterminada se muestran resultados con puntuación 40 o mayor. Los
hallazgos se separan entre correlaciones con GTFOBins, pistas offline de
software de terceros y elementos que requieren revisión manual.

Las acciones y comandos son sugerencias para validación. PrivScout nunca los
ejecuta.

## Licencia

PrivScout se distribuye bajo la licencia MIT. Consulta [LICENSE](../LICENSE).
