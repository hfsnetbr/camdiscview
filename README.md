# Camera Discovery & Viewer

[Português](#português) | [English](#english)

---

## English

A Linux application written in Python/PySide6 to discover ONVIF and RTSP cameras, view streams using `ffplay`, and save scan results locally.

### Key Features

- Scan specific IP addresses (space/comma separated) or CIDR networks (default: `192.168.1.0/24`).
- Optional `nmap` pre-scan for faster CIDR discovery.
- Persistence: Saves settings and last scan results in `~/.config/camera-discovery/`.
- Smart Discovery: Attempts ONVIF first with a conservative RTSP fallback.
- Interactive: Allows manual URL editing before launching the viewer.
- System Tray: Runs in the tray using PySide6's `QSystemTrayIcon`.

### Installation & Development

1. **Setup Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements-gui.txt
   ```

2. **Run**:
   ```bash
   python camera_discovery_gui.py
   ```

3. **Build Binary**:
   ```bash
   ./build_app.sh
   ```

4. **Create Debian Package**:
   ```bash
   ./build_deb.sh
   ```

### Requirements

- `ffplay` (ffmpeg) must be installed for viewing.
- `nmap` (optional, for faster scans).

### License

This project is licensed under the MIT License.

### Author

**Henrique Fernandes Silveira** - [henriquefsilveira@gmail.com](mailto:henriquefsilveira@gmail.com)

---

## Português

Aplicação Linux em Python/PySide6 para descobrir câmeras ONVIF/RTSP, abrir no `ffplay` e manter resultados/configurações salvos localmente.

### Recursos

- Aceita IPs separados por espaço/vírgula.
- Aceita redes CIDR, por padrão `192.168.1.0/24`.
- Pode usar `nmap` como pre-scan para acelerar redes CIDR.
- Salva configurações em `~/.config/camera-discovery/settings.conf`.
- Salva o último resultado em `~/.config/camera-discovery/last_results.json`.
- Tenta ONVIF primeiro e faz fallback RTSP conservador.
- Permite editar URL manualmente antes de abrir.
- Usa `QSystemTrayIcon` via PySide6 para tray.

### Executar em desenvolvimento

```bash
./venv/bin/python camera_discovery_gui.py
```

### Empacotar

Instale as dependências e gere o binário:

```bash
chmod +x build_app.sh
./build_app.sh
```

### Gerar pacote Debian

```bash
chmod +x build_deb.sh
./build_app.sh
./build_deb.sh
```

O pacote instala:
- Launcher em `/usr/bin/camera-discovery`
- Desktop entry em `/usr/share/applications/camera-discovery.desktop`
- Autostart global em `/etc/xdg/autostart/camera-discovery.desktop`
- Ícone em `/usr/share/icons/hicolor/scalable/apps/camera-discovery.svg`
- Aplicação em `/opt/camera-discovery`

### Instalação do Pacote

```bash
sudo dpkg -i dist/camera-discovery_0.1.0_all.deb
sudo apt -f install
```

### Observações

- `ffplay` precisa estar instalado no sistema.
- Câmeras sensíveis podem travar com sondas muito rápidas; a GUI já usa atraso configurável entre tentativas RTSP.

### Licença

Este projeto está licenciado sob a Licença MIT.

### Autor

**Henrique Fernandes Silveira** - [henriquefsilveira@gmail.com](mailto:henriquefsilveira@gmail.com)
