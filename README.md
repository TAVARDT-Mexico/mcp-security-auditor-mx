# Auditor de Seguridad para Servidores y Herramientas MCP

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
[![Standard](https://img.shields.io/badge/Standard-OWASP%20LLM-3b82f6?style=for-the-badge)](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981?style=for-the-badge)](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Auditor de seguridad para servidores y herramientas MCP en plataformas con inteligencia artificial. Aplicacion web y CLI.

Desarrollado para organizaciones e ingenieros en **Mexico**, este repositorio provee una suite practica para inspeccionar y blindar configuraciones del **Model Context Protocol (MCP)** en sistemas impulsados por inteligencia artificial.

---

## Modos de Operacion

### 1. Aplicacion Web en Navegador (GitHub Pages)
Acceda a la version grafica interactiva desde cualquier navegador web:
- **Enlace Oficial**: [https://tavardt-mexico.github.io/mcp-security-auditor-mx/](https://tavardt-mexico.github.io/mcp-security-auditor-mx/)
- **Privacidad Total**: Procesamiento en el motor JavaScript local. Ningun archivo o credencial se remite a servidores externos.

### 2. Herramienta de Linea de Comandos (CLI)
Para validaciones automaticas en pipelines de CI/CD o revisiones locales:

```bash
# Analisis de archivo de configuracion
python mcp_security_scanner.py --file mcp.json

# Modo estricto para pipelines (falla con codigo 1 si hay riesgos)
python mcp_security_scanner.py --file mcp.json --strict

# Creacion de archivo con configuracion blindada
python mcp_security_scanner.py --file mcp.json --harden mcp-hardened.json

# Generacion de reporte en JSON
python mcp_security_scanner.py --file mcp.json --json
```

---

## Vectores de Seguridad Evaluados

1. **Alcance en Sistema de Archivos**: Deteccion de accesos a directorios raiz (`/`, `C:\`) o carpetas sensibles del sistema.
2. **Ejecucion Arbitraria de Comandos**: Restriccion de shells directos (`bash`, `sh`, `powershell`, `cmd`) y comandos dinamicos.
3. **Exposicion de Secretos**: Proteccion de llaves de API, tokens privados y credenciales de bases de datos.
4. **Cadena de Suministro**: Fijacion estricta de versiones en paquetes descargados dinamicamente (`npx`, `uvx`).
5. **Bloqueo de SSRF**: Prevencion de consultas hacia interfaces locales y metadatos de instancias cloud (`169.254.169.254`).

---

## Integracion en GitHub Actions

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
      - name: Ejecutar Auditoria MCP
        run: |
          python mcp_security_scanner.py --file config/mcp.json --strict
```

---

## Referenciales y Conformidad

- **Jurisdiccion**: Mexico
- **Marco Tecnico**: Estandares de Ciberseguridad para Sistemas Inteligentes y OWASP
- **Organizacion**: [TAVARDT-Mexico](https://github.com/TAVARDT-Mexico)

## Enlaces TAVARDT

- **Portal Institucional**: [https://ag.tavardt.com/mx/](https://ag.tavardt.com/mx/)
- **Herramientas de Ciberseguridad**: [https://tools.tavardt.com/mx/](https://tools.tavardt.com/mx/)
- **Contacto Tecnico**: [https://ag.tavardt.com/mx/contacto/](https://ag.tavardt.com/mx/contacto/)

---

### Licencia
Distribuido bajo terminos de la licencia MIT. Revise el archivo [LICENSE](LICENSE) para mas informacion.
