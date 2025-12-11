# ACS Server Enhanced

ACS Server พร้อม Auto SetParam by Serial Number และ features เพิ่มเติม

## Features

### 1. Auto SetParam by Serial Number (SN)
เมื่อ device connect (Inform) เข้ามา server จะ:
- ตรวจสอบ Serial Number
- หา config ที่ match กับ SN (exact match, pattern, หรือ default)
- ส่ง SetParameterValues อัตโนมัติ

### 2. SN Config JSON File
กำหนด config สำหรับแต่ละ SN หรือ pattern:
```json
{
  "templates": [...],
  "configs": [
    {
      "sn": "48575443D89A1234",
      "params": [...],
      "one_time": true
    }
  ]
}
```

### 3. Device Registry (SQLite)
เก็บข้อมูล device ทั้งหมด:
- Serial Number, OUI, Product Class
- Software/Hardware Version
- IP Address, MAC Address
- First/Last seen timestamp
- Config applied status
- Unlock status

### 4. REST API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all devices |
| `/api/devices/{sn}` | GET | Get device by SN |
| `/api/devices/{sn}/params` | GET | Get device parameters |
| `/api/devices/{sn}/setparam` | POST | Queue SetParam |
| `/api/devices/{sn}/reboot` | POST | Queue Reboot |
| `/api/stats` | GET | Get statistics |
| `/api/config` | GET/POST | Manage SN config |
| `/api/templates` | GET | Get unlock templates |

### 5. Config Templates
Reusable parameter templates:
- `huawei_ais_unlock` - Unlock UI, Captcha, Carrier
- `wifi_basic` - Basic WiFi config
- `remote_access` - Enable remote management

### 6. Auto Unlock Sequence
อัตโนมัติ unlock device Huawei AIS:
- Disable Captcha
- Disable SuperAdminSecurity
- Enable RemoteAccess
- Disable CarrierLocking

### 7. Web Dashboard
Simple dashboard ที่ `/` หรือ `/dashboard`:
- Device list และ status
- Statistics (total, online, config applied, unlocked)
- Real-time monitoring

## Usage

### Basic Usage
```bash
# Start server with auto apply by SN
python acs_server_enhanced.py --auto-apply --sn-config sn_config_example.json

# With auto unlock
python acs_server_enhanced.py --auto-apply --auto-unlock --sn-config sn_config_example.json

# Verbose mode
python acs_server_enhanced.py -v --auto-apply --sn-config sn_config_example.json
```

### CLI Options (New)
| Option | Description |
|--------|-------------|
| `--sn-config FILE` | JSON file with SN -> parameters mapping |
| `--auto-apply` | Enable auto SetParam by SN |
| `--device-db FILE` | SQLite database file (default: devices.db) |
| `--templates FILE` | JSON file with config templates |
| `--auto-unlock` | Enable auto unlock for Huawei AIS |
| `--no-dashboard` | Disable web dashboard |
| `--no-api` | Disable REST API |

### Example: Auto Config by SN
```bash
# 1. Create sn_config.json
cat > sn_config.json << 'EOF'
{
  "configs": [
    {
      "sn": "48575443D89A1234",
      "params": [
        {"Name": "InternetGatewayDevice.UserInterface.X_AIS_WebUserInfo.Captcha_enable", "Value": "0"}
      ],
      "one_time": true
    }
  ]
}
EOF

# 2. Start server
python acs_server_enhanced.py --auto-apply --sn-config sn_config.json -v
```

### Example: REST API Usage
```bash
# Get all devices
curl http://localhost:10302/api/devices

# Get device by SN
curl http://localhost:10302/api/devices/48575443D89A1234

# Queue SetParam for device
curl -X POST http://localhost:10302/api/devices/48575443D89A1234/setparam \
  -H "Content-Type: application/json" \
  -d '{
    "params": [
      {"Name": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID", "Value": "NewSSID"}
    ]
  }'

# Queue Reboot
curl -X POST http://localhost:10302/api/devices/48575443D89A1234/reboot

# Get stats
curl http://localhost:10302/api/stats

# Add new SN config via API
curl -X POST http://localhost:10302/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "sn": "NEW_SERIAL_123",
    "params": [{"Name": "...", "Value": "..."}],
    "one_time": true
  }'
```

## SN Config File Format

```json
{
  "templates": [
    {
      "name": "template_name",
      "description": "Template description",
      "params": [
        {"Name": "param.path", "Value": "value", "Type": "xsd:string"}
      ]
    }
  ],
  "configs": [
    {
      "sn": "EXACT_SERIAL_NUMBER",
      "description": "Description",
      "template": "template_name",
      "params": [...],
      "one_time": true,
      "enabled": true
    },
    {
      "sn_pattern": "PREFIX*",
      "description": "Pattern match",
      "params": [...],
      "one_time": true,
      "enabled": true
    },
    {
      "sn": "*",
      "description": "Default for all",
      "params": [...],
      "one_time": false,
      "enabled": false
    }
  ]
}
```

### Pattern Matching
- `*` - matches any characters
- `?` - matches single character
- Exact SN match takes priority over patterns
- Default (`*`) is used as fallback

### one_time Option
- `true` - Apply config only once per device
- `false` - Apply every time device connects

## Database Schema

### devices table
| Column | Type | Description |
|--------|------|-------------|
| serial_number | TEXT | Primary key |
| oui | TEXT | OUI |
| product_class | TEXT | Product class |
| vendor | TEXT | Vendor name |
| software_version | TEXT | SW version |
| hardware_version | TEXT | HW version |
| ip_address | TEXT | Last IP |
| mac_address | TEXT | MAC address |
| first_seen | TEXT | First connection |
| last_seen | TEXT | Last connection |
| config_applied | INTEGER | 0/1 |
| config_applied_at | TEXT | Timestamp |
| unlock_applied | INTEGER | 0/1 |
| status | TEXT | online/offline |

### device_params table
| Column | Type | Description |
|--------|------|-------------|
| serial_number | TEXT | FK to devices |
| param_name | TEXT | Parameter path |
| param_value | TEXT | Value |
| param_type | TEXT | XSD type |
| updated_at | TEXT | Timestamp |

## Requirements

```
fastapi
uvicorn
defusedxml
pydantic
```

## License

MIT
