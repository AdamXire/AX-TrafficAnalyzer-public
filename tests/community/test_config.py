"""
@fileoverview Configuration Tests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Configuration tests.
"""

import sys
import json
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from community.core import load_config, ConfigurationError


def test_config_load_valid():
    """Test loading valid config."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({
            "hotspot": {"interface": "wlan0", "ssid": "Test", "password": "12345678"},
            "capture": {}, "storage": {}, "api": {}
        }, f)
        f.flush()
        
        config = load_config(f.name)
        assert config["hotspot"]["ssid"] == "Test"
        Path(f.name).unlink()


def test_config_invalid_password():
    """Test password validation."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({
            "hotspot": {"interface": "wlan0", "ssid": "Test", "password": "123"},
            "capture": {}, "storage": {}, "api": {}
        }, f)
        f.flush()
        
        try:
            load_config(f.name)
            assert False, "Should have raised ConfigurationError"
        except ConfigurationError:
            pass
        finally:
            Path(f.name).unlink()


if __name__ == "__main__":
    print("\n🔍 Starting configuration tests...\n")
    
    try:
        test_config_load_valid()
        print("✅ test_config_load_valid: PASS")
    except Exception as e:
        print(f"❌ test_config_load_valid: FAIL - {e}")
        sys.exit(1)
    
    try:
        test_config_invalid_password()
        print("✅ test_config_invalid_password: PASS")
    except Exception as e:
        print(f"❌ test_config_invalid_password: FAIL - {e}")
        sys.exit(1)
    
    print("\n✅ All configuration tests passed!\n")

