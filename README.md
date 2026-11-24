# Auditor de Seguridad para Servidores y Herramientas MCP

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
[![Standard](https://img.shields.io/badge/Standard-OWASP%20LLM-3b82f6?style=for-the-badge)](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client-Side-10b981?style=for-the-badge)](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Auditor de seguridad para servidores y herramientas MCP en plataformas con inteligencia artificial. Aplicación web y CLI.

Desarrollado para organizaciones e ingenieros en **México**, este repositorio provee una suite práctica para inspeccionar y blindar configuraciones del **Model Context Protocol (MCP)** en sistemas impulsados por inteligencia artificial.

***

## Modos de Operación

### 1. Aplicación Web en Navegador (GitHub Pages)
Acceda a la versión gráfica interactiva desde cualquier navegador web:
- **Enlace Oficial**: [https://tavardt-mexico.github.io/mcp-security-auditor-mx/](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
- **Privacidad Total**: Procesamiento en el motor JavaScript local. Ningún archivo o credencial se remite a servidores externos.

### 2. Herramienta de Línea de Comandos (CLI)
Para validaciones automáticas en pipelines de CI/CD o revisiones locales:

```bash
# Análisis de archivo de configuración
python mcp_security_scanner.py -file mcp.json

# Modo estricto para pipelines (falla con código 1 si hay riesgos)
python mcp_security_scanner.py -file mcp.json -strict

# Creación de archivo con configuración blindada
python mcp_security_scanner.py -file mcp.json -harden mcp-hardened.json

# Generación de reporte en JSON
python mcp_security_scanner.py -file mcp.json -json
```

***

## Vectores de Seguridad Evaluados

1. **Alcance en Sistema de Archivos**: Detección de accesos a directorios raíz (`/`, `C:\`) o carpetas sensibles del sistema.
2. **Ejecución Arbitraria de Comandos**: Restricción de shells directos (`bash`, `sh`, `powershell`, `cmd`) y comandos dinámicos.
3. **Exposición de Secretos**: Protección de llaves de API, tokens privados y credenciales de bases de datos.
4. **Cadena de Suministro**: Fijación estricta de versiones en paquetes descargados dinámicamente (`npx`, `uvx`).
5. **Bloqueo de SSRF**: Prevención de consultas hacia interfaces locales y servicios internos no autorizados.

***

## Integración en GitHub Actions

```yaml
name: MCP Security Gate
on: [push, pull_request]

jobs:
  audit-mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Instalar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Ejecutar Auditoría MCP
        run: |
          python mcp_security_scanner.py -file config/mcp.json -strict
```

***

## Referenciales y Conformidad

- **Marco Técnico**: Estándares de Ciberseguridad para Sistemas Inteligentes y OWASP

## Enlaces TAVARDT

- **Portal Institucional**: [Portal Institucional](https://ag.tavardt.com/mx/)
- **Centro de Herramientas**: [Central de Herramientas](https://tools.tavardt.com/mx/)
- **Contacto Técnico**: [https://ag.tavardt.com/mx/contacto/](https://ag.tavardt.com/mx/contacto/)

***

## Enlaces Útiles

* **Portal Corporativo:** https://ag.tavardt.com/mx/
* **Suite de Diagnósticos:** https://tools.tavardt.com/mx/
* **Contacto Técnico:** https://ag.tavardt.com/mx/contacto/

***

### Licencia
Distribuido bajo términos de la licencia MIT. Revise el archivo [LICENSE](LICENSE) para más información.

***

© 2026 TAVARDT. Todos los derechos reservados.
