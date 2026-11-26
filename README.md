<p align="center">
  <a href="https://ag.tavardt.com/mx/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Auditor de Seguridad para Servidores y Herramientas MCP

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Auditor de seguridad de configuración y motor automatizado de blindaje para servidores Model Context Protocol (MCP) y agentes de IA desarrollado por **TAVARDT**. Inspecciona archivos de configuración frente a intérpretes de shell directos, montajes de discos peligrosos, credenciales en texto plano, dependencias no fijadas y vectores SSRF hacia metadatos de nube.

***

## Capacidades Principales y Arquitectura Defensiva

* **Verificación de Privilegio Mínimo**: Evalúa las definiciones de servidores en clientes de IA frente a límites estrictos de seguridad de confianza cero.
* **Blindaje Automatizado de Configuraciones**: Produce manifiestos corregidos que encapsulan shells en contenedores seguros y trasladan credenciales a variables de entorno.
* **Integración Flexible en Canales CI/CD**: Funciona como auditor local de terminal, control de calidad automatizado con códigos de salida estrictos o generador de informes JSON.

***

## Vectores de Riesgo e Impacto Operacional

Las configuraciones permisivas de servidores MCP exponen el sistema anfitrión y la información local a movimientos laterales, sustracción de datos y ejecución remota no autorizada. El escáner intercepta seis vectores de riesgo para salvaguardar entornos de agentes de inteligencia artificial:

* **Invocación Directa de Intérpretes de Shell (`Ejecución de Comandos`)**: Identifica intérpretes como bash, powershell o cmd ejecutándose sin aislamiento de contenedores (-35 puntos de penalización, CRÍTICO).
* **Parámetros de Ejecución Dinámica de Código (`Ejecución de Comandos`)**: Detecta modificadores de evaluación arbitraria como -c, /c, invoke-expression o funciones eval (-25 puntos de penalización, CRÍTICO).
* **Montajes de Raíz y Rutas Críticas (`Acceso al Sistema de Archivos`)**: Bloquea montajes completos del almacenamiento local (-35 puntos) y accesos a claves SSH, credenciales AWS y archivos del sistema operativo (-30 puntos de penalización, CRÍTICO).
* **Credenciales de Base de Datos y Claves de API (`Secretos Expuestos`)**: Detecta contraseñas y claves privadas almacenadas en texto plano sin variables de entorno (-20 puntos de penalización, ALTO).
* **Accesos SSRF hacia Servicios de Metadatos (`Seguridad de Red`)**: Neutraliza argumentos dirigidos a puntos de enlace internos y metadatos de infraestructura cloud (-20 puntos de penalización, ALTO).
* **Ejecución de Paquetes Remotos sin Versión Bloqueada (`Seguridad de Cadena de Suministro`)**: Detecta invocaciones npx, uvx o pipx sin etiquetas inmutables de versión (-10 puntos de penalización, MEDIO).

La puntuación inicial parte de 100 puntos y se reduce en función de cada anomalía confirmada. Cero hallazgos certifica la conformidad con las directrices de mínimo privilegio, mientras que desviaciones críticas detienen los procesos de integración.

***

## Instalación y Ejecución CLI

Audite configuraciones localmente o configure barreras de validación en flujos automatizados con Python:

```bash
# Clonar el repositorio oficial
git clone https://github.com/TAVARDT-Mexico/mcp-security-auditor-mx.git

# Acceder al directorio del proyecto
cd mcp-security-auditor-mx

# Auditar un archivo de configuración MCP
python mcp_security_scanner.py -f mcp.json

# Validar en modo estricto
python mcp_security_scanner.py -f mcp.json -s

# Generar configuración blindada y exportar reporte JSON
python mcp_security_scanner.py -f mcp.json -o hardened_mcp.json -j
```

***

## Preguntas Frecuentes Técnicas

### ¿Qué vectores de vulnerabilidad evalúa el auditor en configuraciones de servidores MCP?

La herramienta inspecciona manifiestos frente a invocación directa de intérpretes shell, parámetros de comando dinámicos, montaje de sistemas de archivos raíz, credenciales expuestas, dependencias sin versión fija e intentos de SSRF hacia metadatos de nube. Cada desviación detectada aplica deducciones ponderadas sobre una puntuación inicial de 100 puntos.

### ¿Cómo mitiga el escáner los riesgos de elevación de privilegios en el acceso a discos?

El auditor cataloga como críticas las vinculaciones a la raíz del sistema de archivos y el acceso a rutas sensibles como claves SSH, credenciales AWS y directorios del sistema operativo. La corrección ejecutada con la opción -o restringe automáticamente los directorios hacia volúmenes aislados según el principio de privilegio mínimo.

### ¿Por qué las opciones dinámicas como -c o expresiones de evaluación se consideran críticas?

La presencia de argumentos dinámicos permite que modelos de lenguaje o entradas adversarias evalúen comandos arbitrarios directamente sobre el entorno anfitrión. Bloquear estos parámetros asegura que las herramientas funcionen exclusivamente con binarios predeterminados y esquemas de entrada validados.

### ¿De qué manera la función de blindaje automatizado protege secretos y credenciales en texto plano?

La rutina de auto-harden mediante el parámetro -o sustituye cadenas de conexión a bases de datos y tokens privados por referencias parametrizadas a variables de entorno del sistema. Esta sustitución evita la exposición involuntaria de contraseñas confidenciales en repositorios de control de versiones o registros de agentes.

### ¿Puede implementarse el auditor para control de calidad en flujos de integración continua CI/CD?

La interfaz CLI procesa archivos locales mediante el parámetro -f y dispone de un modo estricto activable con la opción -s para detener la ejecución con código de error 1 ante cualquier fallo. Junto con la salida estructurada -j, permite bloquear de forma automatizada cualquier compilación que vulnere los umbrales de seguridad.

***

## Enlaces Útiles

* **Portal Corporativo:** https://ag.tavardt.com/mx/
* **Suite de Diagnósticos:** https://tools.tavardt.com/mx/
* **Contacto Técnico:** https://ag.tavardt.com/mx/contacto/

***

### Licencia
Distribuido bajo la Licencia MIT. Consulte [LICENSE](LICENSE) para más detalles.

***

© 2026 TAVARDT. Todos los derechos reservados.
