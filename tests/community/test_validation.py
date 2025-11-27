"""
@fileoverview Validation Tests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Tests for platform detection and dependency validation.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from community.core import get_platform_info, DependencyValidator, setup_logging


def test_platform_detection():
    """Test platform detection."""
    print("\n" + "="*60)
    print("TEST: Platform Detection")
    print("="*60)
    try:
        platform = get_platform_info()
        assert platform.python_version_tuple >= (3, 11, 0)
        print(f"✅ Platform: {platform.distribution} {platform.distribution_version}")
        print(f"✅ Python: {platform.python_version}")
        print(f"✅ Kernel: {platform.kernel_version}")
        print(f"✅ Architecture: {platform.architecture}")
        return True
    except Exception as e:
        print(f"❌ Platform detection failed: {e}")
        return False


def test_dependency_validation():
    """Test dependency validation."""
    print("\n" + "="*60)
    print("TEST: Dependency Validation")
    print("="*60)
    try:
        platform = get_platform_info()
        validator = DependencyValidator(platform)
        validator.validate_all(mode="dev")  # Use dev mode for testing
        print("✅ All dependencies validated")
        return True
    except Exception as e:
        print(f"❌ Dependency validation failed: {e}")
        return False


if __name__ == "__main__":
    setup_logging(mode="dev")  # Initialize logging
    print("\n🔍 Starting validation tests...\n")
    
    success = True
    success &= test_platform_detection()
    success &= test_dependency_validation()
    
    print("\n" + "="*60)
    if success:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed")
        sys.exit(1)
    print("="*60 + "\n")

