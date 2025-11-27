#!/usr/bin/env python3
"""
AX-TrafficAnalyzer - Backend Bundler
Copyright © 2025 MMeTech (Macau) Ltd.

Bundle Python backend with PyInstaller for desktop distribution.
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path

# Paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
SRC_DIR = PROJECT_ROOT / "src"
DESKTOP_DIR = PROJECT_ROOT / "desktop"
OUTPUT_DIR = DESKTOP_DIR / "backend-bundle"

print(f"[BUNDLER] Project root: {PROJECT_ROOT}")
print(f"[BUNDLER] Source dir: {SRC_DIR}")
print(f"[BUNDLER] Output dir: {OUTPUT_DIR}")


def check_pyinstaller():
    """Fail-fast if PyInstaller not installed."""
    try:
        import PyInstaller
        print(f"[BUNDLER] PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[BUNDLER] ERROR: PyInstaller not installed!")
        print("[BUNDLER] Install with: pip install pyinstaller")
        sys.exit(1)


def clean_output():
    """Clean previous build artifacts."""
    if OUTPUT_DIR.exists():
        print(f"[BUNDLER] Cleaning {OUTPUT_DIR}")
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)


def bundle_backend():
    """Bundle the backend with PyInstaller."""
    print("[BUNDLER] Starting PyInstaller build...")
    
    spec_content = f'''
# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for AX-TrafficAnalyzer

block_cipher = None

a = Analysis(
    ['{SRC_DIR / "community" / "main.py"}'],
    pathex=['{SRC_DIR}'],
    binaries=[],
    datas=[
        ('{PROJECT_ROOT / "config"}', 'config'),
        ('{SRC_DIR / "community" / "ui" / "dist"}', 'ui'),
    ],
    hiddenimports=[
        'uvicorn.logging',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'sqlalchemy.dialects.sqlite',
        'mitmproxy',
        'structlog',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ax-traffic-analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
'''
    
    spec_file = DESKTOP_DIR / "ax-traffic-analyzer.spec"
    spec_file.write_text(spec_content)
    print(f"[BUNDLER] Spec file written: {spec_file}")
    
    # Run PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--distpath", str(OUTPUT_DIR),
        "--workpath", str(DESKTOP_DIR / "build"),
        str(spec_file)
    ]
    
    print(f"[BUNDLER] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    
    if result.returncode != 0:
        print("[BUNDLER] ERROR: PyInstaller failed!")
        sys.exit(1)
    
    print(f"[BUNDLER] SUCCESS: Backend bundled to {OUTPUT_DIR}")


def main():
    print("[BUNDLER] AX-TrafficAnalyzer Backend Bundler")
    print("=" * 50)
    
    check_pyinstaller()
    clean_output()
    bundle_backend()
    
    print("=" * 50)
    print("[BUNDLER] Done!")


if __name__ == "__main__":
    main()

