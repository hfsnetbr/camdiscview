#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${ROOT_DIR}/venv/bin/python"

if [[ ! -x "${VENV_PYTHON}" ]]; then
  echo "Python do venv nao encontrado em ${VENV_PYTHON}" >&2
  exit 1
fi

"${VENV_PYTHON}" -m pip install -r "${ROOT_DIR}/requirements-gui.txt"

"${VENV_PYTHON}" -m PyInstaller \
  --noconfirm \
  --clean \
  --name camera-discovery \
  --windowed \
  --collect-all PySide6 \
  "${ROOT_DIR}/camera_discovery_gui.py"

echo
echo "Build concluido em: ${ROOT_DIR}/dist/camera-discovery"
