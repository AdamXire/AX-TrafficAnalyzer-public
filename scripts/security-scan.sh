#!/bin/bash
# AX-TrafficAnalyzer Security Scanner
# Copyright © 2025 MMeTech (Macau) Ltd.
#
# FAIL-FAST: Exits with error on critical vulnerabilities
#
# Usage:
#   ./scripts/security-scan.sh         # Run all scans
#   ./scripts/security-scan.sh --deps  # Dependency scan only
#   ./scripts/security-scan.sh --sast  # SAST scan only

set -euo pipefail

echo "=============================================="
echo "  AX-TrafficAnalyzer Security Scanner"
echo "=============================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Results tracking
DEPS_RESULT=0
BANDIT_RESULT=0
SECRETS_RESULT=0

# Create output directory
mkdir -p security/reports

# =============================================================================
# Dependency Vulnerability Scan
# =============================================================================
run_dependency_scan() {
    echo ""
    echo "[SECURITY] Running dependency vulnerability scan..."
    
    # Try pip-audit first (preferred)
    if command -v pip-audit &> /dev/null; then
        echo "[SECURITY] Using pip-audit..."
        if pip-audit --desc on --fix --dry-run 2>&1 | tee security/reports/pip-audit.txt; then
            echo -e "${GREEN}[SECURITY] ✅ pip-audit passed${NC}"
        else
            echo -e "${YELLOW}[SECURITY] ⚠ pip-audit found vulnerabilities${NC}"
            DEPS_RESULT=1
        fi
    # Fallback to safety
    elif command -v safety &> /dev/null; then
        echo "[SECURITY] Using safety..."
        if safety check --full-report 2>&1 | tee security/reports/safety.txt; then
            echo -e "${GREEN}[SECURITY] ✅ safety passed${NC}"
        else
            echo -e "${YELLOW}[SECURITY] ⚠ safety found vulnerabilities${NC}"
            DEPS_RESULT=1
        fi
    else
        echo -e "${YELLOW}[SECURITY] ⚠ No dependency scanner found${NC}"
        echo "[SECURITY] Install with: pip install pip-audit"
        DEPS_RESULT=2
    fi
}

# =============================================================================
# Static Application Security Testing (SAST)
# =============================================================================
run_sast_scan() {
    echo ""
    echo "[SECURITY] Running SAST scan with Bandit..."
    
    if command -v bandit &> /dev/null; then
        # Run bandit with medium+ severity
        if bandit -r src/ -ll -f json -o security/reports/bandit.json 2>/dev/null; then
            echo -e "${GREEN}[SECURITY] ✅ Bandit passed (no high/critical issues)${NC}"
        else
            echo -e "${RED}[SECURITY] ❌ Bandit found security issues${NC}"
            # Show summary
            bandit -r src/ -ll -f txt 2>/dev/null | tail -20
            BANDIT_RESULT=1
        fi
        
        # Also generate HTML report
        bandit -r src/ -f html -o security/reports/bandit.html 2>/dev/null || true
    else
        echo -e "${YELLOW}[SECURITY] ⚠ Bandit not installed${NC}"
        echo "[SECURITY] Install with: pip install bandit"
        BANDIT_RESULT=2
    fi
}

# =============================================================================
# Secrets Detection
# =============================================================================
run_secrets_scan() {
    echo ""
    echo "[SECURITY] Scanning for hardcoded secrets..."
    
    # Simple grep-based secret detection
    SECRETS_FOUND=0
    
    # Check for common secret patterns
    echo "[SECURITY] Checking for API keys..."
    if grep -rn "api[_-]?key\s*=\s*['\"][^'\"]*['\"]" src/ --include="*.py" 2>/dev/null | grep -v "example\|test\|mock" | head -5; then
        SECRETS_FOUND=1
    fi
    
    echo "[SECURITY] Checking for passwords..."
    if grep -rn "password\s*=\s*['\"][^'\"]*['\"]" src/ --include="*.py" 2>/dev/null | grep -v "example\|test\|mock\|hash\|verify" | head -5; then
        SECRETS_FOUND=1
    fi
    
    echo "[SECURITY] Checking for private keys..."
    if grep -rn "PRIVATE KEY" src/ --include="*.py" 2>/dev/null | head -5; then
        SECRETS_FOUND=1
    fi
    
    if [ $SECRETS_FOUND -eq 0 ]; then
        echo -e "${GREEN}[SECURITY] ✅ No obvious secrets found${NC}"
    else
        echo -e "${YELLOW}[SECURITY] ⚠ Potential secrets detected (review above)${NC}"
        SECRETS_RESULT=1
    fi
}

# =============================================================================
# Main
# =============================================================================

# Parse arguments
SCAN_DEPS=true
SCAN_SAST=true
SCAN_SECRETS=true

for arg in "$@"; do
    case $arg in
        --deps)
            SCAN_SAST=false
            SCAN_SECRETS=false
            ;;
        --sast)
            SCAN_DEPS=false
            SCAN_SECRETS=false
            ;;
        --secrets)
            SCAN_DEPS=false
            SCAN_SAST=false
            ;;
    esac
done

# Run scans
if [ "$SCAN_DEPS" = true ]; then
    run_dependency_scan
fi

if [ "$SCAN_SAST" = true ]; then
    run_sast_scan
fi

if [ "$SCAN_SECRETS" = true ]; then
    run_secrets_scan
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
echo "  Security Scan Summary"
echo "=============================================="

TOTAL_ISSUES=0

if [ $DEPS_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Dependencies: PASS${NC}"
elif [ $DEPS_RESULT -eq 2 ]; then
    echo -e "${YELLOW}⚠ Dependencies: SKIPPED (tool not installed)${NC}"
else
    echo -e "${RED}❌ Dependencies: FAIL${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
fi

if [ $BANDIT_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ SAST (Bandit): PASS${NC}"
elif [ $BANDIT_RESULT -eq 2 ]; then
    echo -e "${YELLOW}⚠ SAST (Bandit): SKIPPED (tool not installed)${NC}"
else
    echo -e "${RED}❌ SAST (Bandit): FAIL${NC}"
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
fi

if [ $SECRETS_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Secrets: PASS${NC}"
else
    echo -e "${YELLOW}⚠ Secrets: REVIEW NEEDED${NC}"
fi

echo ""
echo "[SECURITY] Reports saved to: security/reports/"

if [ $TOTAL_ISSUES -gt 0 ]; then
    echo ""
    echo -e "${RED}[SECURITY] ❌ $TOTAL_ISSUES critical issue(s) found${NC}"
    echo "[SECURITY] Fix issues before deploying to production"
    exit 1
else
    echo ""
    echo -e "${GREEN}[SECURITY] ✅ All security checks passed${NC}"
    exit 0
fi

