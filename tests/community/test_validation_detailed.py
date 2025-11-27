"""
@fileoverview Detailed Validation Tests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Detailed tests for individual validation components.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from community.core.platform.detector import PlatformDetector, PlatformDetectionError
from community.core.dependencies import DependencyValidator, DependencyValidationError


def test_platform_detection_fail_fast():
    """Test that platform detection fails-fast on Python version."""
    print("\n" + "="*60)
    print("TEST 1: Platform Detection - Fail-Fast Behavior")
    print("="*60)
    try:
        detector = PlatformDetector()
        platform = detector.detect()
        print(f"❌ Should have failed - Python version: {platform.python_version}")
        return False
    except PlatformDetectionError as e:
        print("✅ Fail-fast working correctly!")
        print(f"   Error message format: {'✓' if 'CRITICAL ERROR' in str(e) else '✗'}")
        print(f"   Actionable solution: {'✓' if 'SOLUTION:' in str(e) else '✗'}")
        return True
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def test_dependency_validator_initialization():
    """Test dependency validator can be initialized."""
    print("\n" + "="*60)
    print("TEST 2: Dependency Validator Initialization")
    print("="*60)
    try:
        # Create a mock platform info to bypass Python version check
        from community.core.platform.detector import PlatformInfo
        mock_platform = PlatformInfo(
            os="Linux",
            is_wsl2=False,
            is_native_linux=True,
            is_native_windows=False,
            wsl_distro=None,
            kernel_version="5.15.0",
            architecture="x86_64",
            distribution="Ubuntu",
            distribution_version="22.04",
            python_version="3.11.0",
            python_version_tuple=(3, 11, 0)
        )
        
        validator = DependencyValidator(mock_platform)
        print("✅ DependencyValidator initialized successfully")
        print(f"   Platform: {validator.platform_info.distribution} {validator.platform_info.distribution_version}")
        return True
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_system_tools_check():
    """Test system tools checking logic."""
    print("\n" + "="*60)
    print("TEST 3: System Tools Check Logic")
    print("="*60)
    try:
        from community.core.platform.detector import PlatformInfo
        mock_platform = PlatformInfo(
            os="Linux",
            is_wsl2=False,
            is_native_linux=True,
            is_native_windows=False,
            wsl_distro=None,
            kernel_version="5.15.0",
            architecture="x86_64",
            distribution="Ubuntu",
            distribution_version="22.04",
            python_version="3.11.0",
            python_version_tuple=(3, 11, 0)
        )
        
        validator = DependencyValidator(mock_platform)
        
        # Test tool checking (won't run full validation due to root check)
        import shutil
        tools_checked = 0
        for tool in ["ip", "systemctl"]:  # Tools that might be available
            if shutil.which(tool):
                check = validator._check_system_tool(tool, None)
                if check.found:
                    tools_checked += 1
                    print(f"   ✓ {tool}: found at {check.path}")
        
        print(f"✅ Checked {tools_checked} system tools")
        return True
    except Exception as e:
        print(f"❌ System tools check failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_error_message_format():
    """Test error message formatting."""
    print("\n" + "="*60)
    print("TEST 4: Error Message Format")
    print("="*60)
    try:
        from community.core.platform.detector import PlatformInfo
        mock_platform = PlatformInfo(
            os="Linux",
            is_wsl2=False,
            is_native_linux=True,
            is_native_windows=False,
            wsl_distro=None,
            kernel_version="5.15.0",
            architecture="x86_64",
            distribution="Ubuntu",
            distribution_version="22.04",
            python_version="3.11.0",
            python_version_tuple=(3, 11, 0)
        )
        
        validator = DependencyValidator(mock_platform)
        
        # Test error message format
        from community.core.dependencies import DependencyCheck
        check = DependencyCheck(
            name="test_tool",
            required=True,
            found=False,
            error="Not found"
        )
        
        try:
            validator._fail_fast_tool("test_tool", "1.0", check)
        except DependencyValidationError as e:
            error_str = str(e)
            checks = [
                "CRITICAL ERROR" in error_str,
                "COMPONENT:" in error_str,
                "SOLUTION:" in error_str,
                "DOCUMENTATION:" in error_str
            ]
            if all(checks):
                print("✅ Error message format correct")
                print("   Contains: CRITICAL ERROR, COMPONENT, SOLUTION, DOCUMENTATION")
                return True
            else:
                print(f"❌ Error message missing components: {checks}")
                return False
        
    except Exception as e:
        print(f"❌ Error message test failed: {e}")
        return False


def test_version_parsing():
    """Test version parsing logic."""
    print("\n" + "="*60)
    print("TEST 5: Version Parsing Logic")
    print("="*60)
    try:
        from community.core.platform.detector import PlatformInfo
        mock_platform = PlatformInfo(
            os="Linux",
            is_wsl2=False,
            is_native_linux=True,
            is_native_windows=False,
            wsl_distro=None,
            kernel_version="5.15.0",
            architecture="x86_64",
            distribution="Ubuntu",
            distribution_version="22.04",
            python_version="3.11.0",
            python_version_tuple=(3, 11, 0)
        )
        
        validator = DependencyValidator(mock_platform)
        
        # Test version comparison
        test_cases = [
            ("2.9.0", "2.9", True),   # Meets requirement
            ("2.8.0", "2.9", False),   # Below requirement
            ("3.0.0", "2.9", True),    # Above requirement
        ]
        
        passed = 0
        for version, min_version, expected in test_cases:
            result = validator._version_meets_requirement(version, min_version)
            if result == expected:
                passed += 1
                print(f"   ✓ {version} >= {min_version}: {result} (expected {expected})")
            else:
                print(f"   ✗ {version} >= {min_version}: {result} (expected {expected})")
        
        if passed == len(test_cases):
            print(f"✅ All {len(test_cases)} version parsing tests passed")
            return True
        else:
            print(f"❌ {passed}/{len(test_cases)} tests passed")
            return False
        
    except Exception as e:
        print(f"❌ Version parsing test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\n" + "="*70)
    print("PHASE 0 TESTING - Detailed Component Tests")
    print("="*70)
    
    results = []
    results.append(("Fail-Fast Behavior", test_platform_detection_fail_fast()))
    results.append(("Validator Initialization", test_dependency_validator_initialization()))
    results.append(("System Tools Check", test_system_tools_check()))
    results.append(("Error Message Format", test_error_message_format()))
    results.append(("Version Parsing", test_version_parsing()))
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print("="*70)
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All Phase 0 tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed")
        sys.exit(1)

