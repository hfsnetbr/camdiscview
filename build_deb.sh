#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_NAME="camera-discovery"
PKG_VERSION="${1:-0.1.0}"
ARCH="all"
BUILD_ROOT="${ROOT_DIR}/dist/deb-build"
PKG_ROOT="${BUILD_ROOT}/${PKG_NAME}_${PKG_VERSION}_${ARCH}"
APP_DIST_DIR="${ROOT_DIR}/dist/${PKG_NAME}"

if [[ ! -x "${APP_DIST_DIR}/${PKG_NAME}" ]]; then
  echo "Build do app nao encontrado em ${APP_DIST_DIR}/${PKG_NAME}" >&2
  echo "Execute ./build_app.sh antes de gerar o .deb" >&2
  exit 1
fi

rm -rf "${PKG_ROOT}"
mkdir -p "${PKG_ROOT}/DEBIAN"
mkdir -p "${PKG_ROOT}/etc/xdg/autostart"
mkdir -p "${PKG_ROOT}/opt/${PKG_NAME}"
mkdir -p "${PKG_ROOT}/usr/bin"
mkdir -p "${PKG_ROOT}/usr/share/applications"
mkdir -p "${PKG_ROOT}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${ROOT_DIR}/dist"

sed "s/^Version: .*/Version: ${PKG_VERSION}/" "${ROOT_DIR}/packaging/DEBIAN_control" > "${PKG_ROOT}/DEBIAN/control"
cp "${ROOT_DIR}/packaging/DEBIAN_postinst" "${PKG_ROOT}/DEBIAN/postinst"
cp "${ROOT_DIR}/packaging/DEBIAN_postrm" "${PKG_ROOT}/DEBIAN/postrm"
chmod 0755 "${PKG_ROOT}/DEBIAN/postinst" "${PKG_ROOT}/DEBIAN/postrm"

install -m 0755 "${ROOT_DIR}/packaging/usr_bin_camera-discovery" "${PKG_ROOT}/usr/bin/camera-discovery"
install -m 0644 "${ROOT_DIR}/camera-discovery.desktop" "${PKG_ROOT}/usr/share/applications/camera-discovery.desktop"
install -m 0644 "${ROOT_DIR}/packaging/etc_xdg_autostart_camera-discovery.desktop" "${PKG_ROOT}/etc/xdg/autostart/camera-discovery.desktop"
install -m 0644 "${ROOT_DIR}/assets/camera-discovery.svg" "${PKG_ROOT}/usr/share/icons/hicolor/scalable/apps/camera-discovery.svg"

cp -a "${APP_DIST_DIR}/." "${PKG_ROOT}/opt/${PKG_NAME}/"
install -m 0644 "${ROOT_DIR}/README.md" "${PKG_ROOT}/opt/${PKG_NAME}/README.md"

dpkg-deb --build "${PKG_ROOT}" "${ROOT_DIR}/dist/${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"

echo
echo "Pacote criado em: ${ROOT_DIR}/dist/${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"
