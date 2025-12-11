# ACS Server with Auto SN Configuration

A CWMP/TR-069 ACS (Auto Configuration Server) with automatic device configuration based on Serial Number (SN).

## Features

- **Auto SetParam by Serial Number**: Automatically configure devices based on their SN
- **SN Config JSON Structure**: Flexible JSON-based configuration system
- **Device Registry**: Track and manage connected devices
- **Configuration Templates**: Reusable configuration templates
- **Auto Unlock Sequence**: Automatic unlock sequences including SuperAdmin user
- **Web Dashboard**: Real-time web dashboard for monitoring and control
- **WebSocket Updates**: Real-time device status updates

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start server
./start_server.sh

# Or manually
python3 acs_server_auto_sn.py --port 10302
```

## Configuration Structure

```
config/
├── sn_registry.json          # Main SN registry
├── templates/                 # Configuration templates
│   ├── standard_unlock.json
│   ├── huawei_hg8145.json
│   └── full_unlock_superadmin.json
└── devices/                   # Device-specific configs (optional)

data/
└── device_registry.json      # Runtime device data
```

## Usage

### Command Line Options

```bash
python3 acs_server_auto_sn.py [options]

Options:
  --host HOST              Bind address (default: 0.0.0.0)
  --port PORT              CWMP port (default: 10302)
  --web-port PORT          Web dashboard port (default: 8080)
  -v, --verbose            Enable verbose logging
  --disable-auto-unlock    Disable automatic unlock
  --disable-auto-superadmin  Disable SuperAdmin configuration
  --all-at-once           Send all params at once (vs staged)
  --use-https             Enable HTTPS
  --certfile FILE         SSL certificate file
  --keyfile FILE          SSL key file
```

### Web Dashboard

Access the web dashboard at `http://localhost:10302/`

Features:
- Real-time device status
- Device list with unlock progress
- Manual unlock trigger
- Event log
- Statistics

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/acs` | POST | CWMP TR-069 endpoint |
| `/healthz` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/api/devices` | GET | List all devices |
| `/api/devices/{sn}` | GET | Get device details |
| `/api/devices/{sn}` | DELETE | Delete device |
| `/api/templates` | GET | List templates |
| `/api/config/{sn}` | GET | Get config for SN |
| `/api/config/{sn}/unlock` | POST | Trigger unlock |
| `/api/reload` | POST | Reload configurations |
| `/api/stats` | GET | Server statistics |
| `/ws` | WS | WebSocket for real-time updates |

## Configuration Templates

### Creating a Template

Create a JSON file in `config/templates/`:

```json
{
  "name": "My Template",
  "description": "Template description",
  "version": "1.0",
  "sequences": [
    {
      "name": "step1",
      "description": "First step",
      "params": [
        {
          "Name": "InternetGatewayDevice.Some.Parameter",
          "Value": "value",
          "Type": "xsd:string"
        }
      ]
    }
  ],
  "superadmin": {
    "enabled": true,
    "params": [
      {
        "Name": "InternetGatewayDevice.UserInterface.X_AIS_WebUserInfo.SuperAdminName",
        "Value": "superadmin",
        "Type": "xsd:string"
      },
      {
        "Name": "InternetGatewayDevice.UserInterface.X_AIS_WebUserInfo.SuperAdminPassword",
        "Value": "password",
        "Type": "xsd:string"
      }
    ]
  }
}
```

### SN Registry

Configure `config/sn_registry.json`:

```json
{
  "default_template": "standard_unlock",
  "devices": {
    "SPECIFIC_SN_123": {
      "template": "huawei_hg8145",
      "enabled": true,
      "name": "Office Device"
    }
  },
  "sn_patterns": [
    {
      "pattern": "^48575.*",
      "template": "huawei_hg8145",
      "description": "Huawei devices"
    }
  ]
}
```

## Utilities

```bash
# Add device to registry
python3 utils/add_device.py SN123456 --template huawei_hg8145

# List devices
python3 utils/list_devices.py --all

# Test configuration
python3 utils/test_config.py SN123456 -v
```

## Unlock Sequence

The default unlock sequence:

1. **Disable Captcha**: `X_AIS_WebUserInfo.Captcha_enable = 0`
2. **Disable SuperAdmin Security**: `X_AIS_WebUserInfo.SuperAdminSecurity = 0`
3. **Enable Remote Access**: `X_AIS_WebUserInfo.RemoteAccess = 1`
4. **Disable Carrier Lock**: `CarrierLocking.X_AIS_LockingEnable = 0`
5. **Configure SuperAdmin** (if enabled):
   - `SuperAdminName = superadmin`
   - `SuperAdminPassword = Ais@SuperAdmin`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ACS Server Auto-SN                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ SN Config    │  │ Device       │  │ Template     │       │
│  │ Loader       │  │ Registry     │  │ System       │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│          │                │                 │                │
│          └────────────────┴─────────────────┘                │
│                           │                                  │
│  ┌────────────────────────┴────────────────────────┐        │
│  │                 CWMP Handler                     │        │
│  │  - Inform processing                            │        │
│  │  - Auto unlock by SN                            │        │
│  │  - Session management                           │        │
│  └────────────────────────┬────────────────────────┘        │
│                           │                                  │
│  ┌────────────────────────┴────────────────────────┐        │
│  │               Web Dashboard                      │        │
│  │  - Real-time status                             │        │
│  │  - Device management                            │        │
│  │  - WebSocket updates                            │        │
│  └─────────────────────────────────────────────────┘        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## License

MIT License
