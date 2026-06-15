# atomic-lockfile-supply-chain-attack

[English](README.md) | [Español](README.es.md)

Detector de indicadores asociados al ataque de cadena de suministro de AUR
`atomic-lockfile`.

- Autor: [l0rdmalware](https://l0rdmalware.cc)
- Repositorio: <https://github.com/l0rdmalware/atomic-lockfile-supply-chain-attack>
- Proyecto de referencia: <https://github.com/lenucksi/aur-malware-check>

## Instalación y uso

Clona el repositorio y entra en su directorio:

```bash
git clone https://github.com/l0rdmalware/atomic-lockfile-supply-chain-attack.git
cd atomic-lockfile-supply-chain-attack
```

Ejecuta el análisis predeterminado con Bash:

```bash
./check_supply-chain-attack.sh
```

El análisis predeterminado revisa los paquetes externos instalados y el
historial de pacman. Para actualizar primero la lista de paquetes afectados y
activar todas las comprobaciones opcionales:

```bash
./check_supply-chain-attack.sh --update
./check_supply-chain-attack.sh --full
```

También puedes usar cualquiera de las otras implementaciones:

```bash
./check_supply-chain-attack.zsh --full
./check_supply-chain-attack.fish --full
./check_supply-chain-attack.py --full
```

Revisa el resultado final y el código de salida. No ejecutes los scripts con
`sudo` salvo que necesites acceder a un log protegido específico. Inspecciona
el código fuente antes de conceder privilegios elevados.

## Versiones

Todas las versiones aceptan las mismas opciones y usan la lista
`aur_infected_packages.md`.

```bash
# Bash
./check_supply-chain-attack.sh --full

# zsh
./check_supply-chain-attack.zsh --full

# fish
./check_supply-chain-attack.fish --full

# Python 3.9+
./check_supply-chain-attack.py --full
```

Los lanzadores de zsh y fish usan la implementación Python para mantener el
mismo comportamiento. La versión Bash es independiente.

## Opciones principales

```text
--update             Actualiza la lista de paquetes afectados
--list FILE          Usa otra lista Markdown
--skip-logs          Omite el historial de pacman
--check-systemd      Busca persistencia en unidades systemd
--check-ebpf         Busca nombres conocidos de mapas eBPF
--check-npm-cache    Revisa artefactos de npm
--check-bun-cache    Revisa artefactos de bun
--full               Activa todas las comprobaciones opcionales
--all-time           Revisa todo el historial de pacman
-v, --verbose        Muestra los archivos inspeccionados
```

## Requisitos

- Arch Linux o un sistema con `pacman`.
- Bash para la versión `.sh`.
- Python 3.9 o superior para `.py`, `.zsh` y `.fish`.
- zsh o fish para su lanzador correspondiente.
- `zstdcat` para revisar logs de pacman comprimidos con Zstandard.

## Códigos de salida

- `0`: no se encontraron indicadores.
- `1`: el análisis quedó incompleto o ocurrió un error.
- `2`: se encontraron uno o más indicadores.

Una coincidencia es un indicador para investigación, no una confirmación
automática de compromiso.

## Cobertura del incidente

- [Aviatrix Threat Research: Arch Linux AUR Compromise 2026](https://aviatrix.ai/threat-research-center/arch-linux-aur-compromise-2026/)
- [The Hacker News: Over 400 Arch Linux AUR Packages](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html)
- [Discusión de la comunidad en Hacker News](https://news.ycombinator.com/item?id=48500447)

Estos enlaces proporcionan análisis técnico, cobertura periodística y discusión
comunitaria sobre el incidente. Verifica las medidas de mitigación con los
avisos oficiales vigentes de Arch Linux.
