#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT México
Auditor de Seguridad para Servidores y Herramientas MCP
Auditor de seguridad para servidores y herramientas MCP en plataformas con inteligencia artificial. Aplicación web y CLI.

Standard: Estándares de Ciberseguridad para Sistemas Inteligentes y OWASP
Repository: https://github.com/TAVARDT-Mexico/mcp-security-auditor-mx
Online Web App: https://tavardt-mexico.github.io/mcp-security-auditor-mx/
"""

import os
import sys
import json
import re
import argparse

DANGEROUS_SHELLS = ["bash", "sh", "zsh", "powershell", "powershell.exe", "cmd", "cmd.exe"]
ROOT_PATHS = ["/", "\\", "c:\\", "c:/", "d:\\", "d:/", "~", "$home", "%userprofile%"]
SENSITIVE_PATHS = ["/etc", "/var", "/root", ".ssh", ".aws", ".gnupg", "system32", "appdata"]
METADATA_HOSTS = ["metadata.cloud-provider.internal", "metadata.internal", "instance-data.internal", "cloud-metadata.service"]

def analyze_mcp_config(config_data):
    servers = {}
    if "mcpServers" in config_data and isinstance(config_data["mcpServers"], dict):
        servers = config_data["mcpServers"]
    elif isinstance(config_data, dict):
        servers = config_data

    findings = []
    penalty = 0

    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue

        cmd = (srv.get("command") or "").strip().lower()
        args = srv.get("args") or []
        env = srv.get("env") or {}

        # 1. Shell execution
        if cmd in DANGEROUS_SHELLS:
            findings.append({
                "server": s_name,
                "severity": "CRITICAL",
                "category": "Ejecución de Comandos",
                "title": "Ejecución Directa de Intérprete de Shell Detectada",
                "detail": "El servidor ejecuta el intérprete '{cmd}' directamente sin aislamiento en contenedor.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Elimine la ejecución directa de shells. Utilice contenedores Docker aislados con privilegios mínimos."
            })
            penalty += 35

        # 2. Dynamic command flags
        for arg in args:
            a_str = str(arg).lower()
            if a_str in ["-c", "/c", "-command"] or "invoke-expression" in a_str or "eval(" in a_str:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Ejecución de Comandos",
                    "title": "Argumentos con Parámetros de Ejecución Arbitraria",
                    "detail": "Se detectó el parámetro '{arg}', permitiendo ejecución dinámica de instrucciones.".replace("{arg}", str(arg)),
                    "remediation": "Elimine parámetros como -c o llamadas dinámicas. Parametrice herramientas de modo estricto."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acceso al Sistema de Archivos",
                    "title": "Montaje de Directorio Raíz del Sistema de Archivos",
                    "detail": "La ruta '{path}' concede permisos totales a todo el disco del sistema anfitrión.".replace("{path}", str(arg)),
                    "remediation": "Limite las rutas permitidas a carpetas de trabajo específicas y aisladas."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acceso al Sistema de Archivos",
                    "title": "Acceso Permitido a Directorios Sensibles del Sistema",
                    "detail": "El servidor tiene permiso para leer archivos en directorios protegidos ('{path}').".replace("{path}", str(arg)),
                    "remediation": "Bloquee el acceso a llaves SSH y carpetas protegidas del sistema operativo."
                })
                penalty += 30

        # 4. Plaintext secrets
        for env_k, env_v in env.items():
            k_lower = env_k.lower()
            v_str = str(env_v or "")
            if any(s_k in k_lower for s_k in ["db_url", "database_url", "conn_str", "postgres", "mysql"]):
                if "password" in v_str.lower() or "://" in v_str:
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Credenciales Expuestas",
                        "title": "Cadena de Conexión de Base de Datos con Contraseña en Texto Plano",
                        "detail": "La variable de entorno '{key}' contiene credenciales de acceso expuestas.".replace("{key}", env_k),
                        "remediation": "Sustituya por referencia de variable de entorno: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20
            elif any(s_k in k_lower for s_k in ["api_key", "secret", "token", "auth", "private_key"]):
                if not (v_str.startswith("${") and v_str.endswith("}")):
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Credenciales Expuestas",
                        "title": "Clave de API o Token Privado Expuesto en Texto Plano",
                        "detail": "La variable '{key}' contiene un token privado codificado directamente.".replace("{key}", env_k),
                        "remediation": "Utilice variables de entorno del sistema anfitrión: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20

        # 5. Supply chain unpinned packages
        if cmd in ["npx", "uvx", "pipx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for a in args:
                a_str = str(a)
                if not a_str.startswith("-"):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str[1:] or "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Cadena de Suministro",
                    "title": "Paquete Remoto sin Fijación de Versión (Riesgo de Cadena de Suministro)",
                    "detail": "El paquete '{pkg}' se descarga dinámicamente sin especificación de versión inmutable.".replace("{pkg}", pkg_name),
                    "remediation": "Fije la versión exacta del paquete (ejemplo: {pkg}@1.0.0 o ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_HOSTS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Red y Bloqueo de SSRF",
                    "title": "Riesgo de SSRF o Conexión a Metadatos en la Nube",
                    "detail": "El parámetro '{target}' apunta a servicios de metadatos internos o endpoints protegidos.".replace("{target}", a_str),
                    "remediation": "Configure listas de permitidos estrictas de dominios corporativos y bloquee servicios de metadados internos."
                })
                penalty += 20

    score = max(0, 100 - penalty)
    return {
        "server_count": len(servers),
        "score": score,
        "findings": findings,
        "servers": servers
    }

def harden_config(servers):
    hardened = {"mcpServers": {}}
    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue
        h_cmd = srv.get("command", "")
        h_args = list(srv.get("args") or [])

        # Wrap shells
        if h_cmd.lower() in DANGEROUS_SHELLS:
            h_cmd = "docker"
            h_args = ["run", "--rm", "-i", "--read-only", "--cap-drop=ALL", "sandbox-runner:latest"]

        # Restrict root or critical paths
        cleaned_args = []
        for a in h_args:
            a_str = str(a).strip().lower()
            if a_str in ROOT_PATHS:
                cleaned_args.append("/workspace/sandbox/app-data")
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                cleaned_args.append("/workspace/sandbox/isolated-storage")
            elif any(mh in a_str for mh in METADATA_HOSTS):
                cleaned_args.append("metadata-blocked.internal")
            elif h_cmd in ["npx", "uvx"] and a_str.startswith("@modelcontextprotocol/server-") and "@" not in a_str[1:]:
                cleaned_args.append(str(a) + "@0.6.2")
            else:
                cleaned_args.append(a)

        h_srv = {
            "command": h_cmd,
            "args": cleaned_args
        }

        # Abstract secrets into env vars
        if "env" in srv and isinstance(srv["env"], dict):
            h_env = {}
            for e_k, e_v in srv["env"].items():
                v_str = str(e_v or "")
                if v_str.startswith("${") and v_str.endswith("}"):
                    h_env[e_k] = v_str
                else:
                    h_env[e_k] = "${" + e_k.upper() + "}"
            h_srv["env"] = h_env

        hardened["mcpServers"][s_name] = h_srv
    return hardened

def main():
    parser = argparse.ArgumentParser(
        description="Auditor de Seguridad para Archivos de Configuración MCP (Model Context Protocol)."
    )
    parser.add_argument("--file", "-f", required=True, help="Ruta al archivo mcp.json o configuración del cliente de inteligencia artificial")
    parser.add_argument("--strict", action="store_true", help="Modo estricto: salir con código 1 si se detecta cualquier vulnerabilidad")
    parser.add_argument("--harden", "-o", help="Exportar archivo JSON con configuración corregida y asegurada")
    parser.add_argument("--json", action="store_true", help="Imprimir salida en formato JSON estructurado")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"Error reading JSON from {args.file}: {e}", file=sys.stderr)
        sys.exit(2)

    report = analyze_mcp_config(cfg)

    if args.harden:
        hardened_json = harden_config(report["servers"])
        with open(args.harden, "w", encoding="utf-8") as out_f:
            json.dump(hardened_json, out_f, indent=2)
        print(f"Configuración blindada guardada exitosamente en: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"AUDITORÍA DE SEGURIDAD MCP: TAVARDT México")
        print(f"Standard: Estándares de Ciberseguridad para Sistemas Inteligentes y OWASP")
        print(f"Servidores Analizados: {report['server_count']}")
        print(f"Índice de Seguridad: {report['score']} / 100")
        print(f"Vulnerabilidades Detectadas: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Ninguna vulnerabilidad detectada. Configuración en conformidad con el principio de mínimo privilegio.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
