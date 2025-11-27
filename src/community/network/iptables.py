"""
@fileoverview iptables management with automatic cleanup
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

iptables rule management with atomic operations.
Note: IPv6 (ip6tables) support deferred to Phase 2.
"""

import subprocess
from typing import List
from ..core.errors import NetworkError
from ..core.logging import get_logger

log = get_logger(__name__)

CHAIN_NAME = "AX_TRAFFIC_ANALYZER"
TABLE_NAME = "nat"


class IPTablesManager:
    """
    Manage iptables rules with atomic operations.
    
    NO signal handler registration - orchestrator handles signals.
    Register cleanup with orchestrator, not atexit directly.
    """
    
    def __init__(self, interface: str = "wlan0"):
        """
        Initialize iptables manager.
        
        Args:
            interface: Network interface to manage rules for
        """
        self.interface = interface
        self.rules_applied = False
        log.debug("iptables_manager_initialized", interface=interface)
    
    def _run_iptables(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run iptables command."""
        cmd = ["iptables", "-t", TABLE_NAME] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        if check and result.returncode != 0:
            raise NetworkError(
                f"iptables command failed: {' '.join(cmd)}\nError: {result.stderr}",
                None
            )
        return result
    
    def _check_chain_exists(self) -> bool:
        """Check if custom chain exists."""
        result = self._run_iptables(["-L", CHAIN_NAME], check=False)
        return result.returncode == 0
    
    def create_chain(self) -> None:
        """Create custom iptables chain if it doesn't exist."""
        if self._check_chain_exists():
            log.debug("iptables_chain_exists", chain=CHAIN_NAME)
            return
        
        # Create chain
        self._run_iptables(["-N", CHAIN_NAME])
        log.info("iptables_chain_created", chain=CHAIN_NAME)
    
    def add_rules(self) -> None:
        """
        Add iptables rules for traffic redirection.
        
        Rules are applied atomically - if any rule fails, previous rules remain
        but method raises exception (caller should handle cleanup).
        """
        if self.rules_applied:
            log.warning("iptables_rules_already_applied")
            return
        
        log.info("adding_iptables_rules", interface=self.interface)
        
        # Create chain first
        self.create_chain()
        
        # Define PREROUTING rules (redirect to custom chain)
        prerouting_rules = [
            # Redirect HTTP traffic to custom chain
            ["-A", "PREROUTING", "-i", self.interface, "-p", "tcp", "--dport", "80", 
             "-j", CHAIN_NAME],
            # Redirect HTTPS traffic to custom chain
            ["-A", "PREROUTING", "-i", self.interface, "-p", "tcp", "--dport", "443",
             "-j", CHAIN_NAME],
            # Redirect DNS traffic to custom chain
            ["-A", "PREROUTING", "-i", self.interface, "-p", "udp", "--dport", "53",
             "-j", CHAIN_NAME],
        ]
        
        # Apply PREROUTING rules
        for rule in prerouting_rules:
            try:
                self._run_iptables(rule)
                log.debug("iptables_rule_added", rule=" ".join(rule))
            except NetworkError as e:
                # Log and re-raise - don't leave partial state
                log.error("iptables_rule_failed", rule=" ".join(rule), error=str(e))
                raise
        
        # Use add_redirect_rule() for actual REDIRECT rules (eliminates duplication)
        # HTTP redirect to mitmproxy
        self.add_redirect_rule(80, 8080, "tcp")
        # HTTPS redirect to mitmproxy
        self.add_redirect_rule(443, 8080, "tcp")
        
        self.rules_applied = True
        log.info("iptables_rules_added", interface=self.interface, 
                prerouting_rules=len(prerouting_rules), redirect_rules=2)
    
    def remove_rules(self) -> None:
        """
        Remove iptables rules.
        
        Does not raise exceptions - cleanup should be best-effort.
        """
        if not self.rules_applied:
            log.debug("iptables_rules_not_applied")
            return
        
        log.info("removing_iptables_rules")
        
        # Remove from PREROUTING (best-effort, ignore errors)
        prerouting_rules = [
            ["-D", "PREROUTING", "-i", self.interface, "-p", "tcp", "--dport", "80", "-j", CHAIN_NAME],
            ["-D", "PREROUTING", "-i", self.interface, "-p", "tcp", "--dport", "443", "-j", CHAIN_NAME],
            ["-D", "PREROUTING", "-i", self.interface, "-p", "udp", "--dport", "53", "-j", CHAIN_NAME],
        ]
        
        for rule in prerouting_rules:
            try:
                self._run_iptables(rule, check=False)
            except Exception as e:
                log.debug("iptables_rule_remove_failed", rule=" ".join(rule), error=str(e))
        
        # Flush chain (best-effort)
        try:
            self._run_iptables(["-F", CHAIN_NAME], check=False)
        except Exception as e:
            log.debug("iptables_chain_flush_failed", error=str(e))
        
        # Delete chain (best-effort)
        try:
            self._run_iptables(["-X", CHAIN_NAME], check=False)
        except Exception as e:
            log.debug("iptables_chain_delete_failed", error=str(e))
        
        self.rules_applied = False
        log.info("iptables_rules_removed")
    
    def cleanup(self) -> None:
        """Cleanup all iptables rules (alias for remove_rules)."""
        self.remove_rules()
    
    def enable_ip_forwarding(self) -> None:
        """Enable IP forwarding."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            log.info("ip_forwarding_enabled")
        except Exception as e:
            raise NetworkError(
                f"Failed to enable IP forwarding: {e}",
                None
            ) from e
    
    def disable_ip_forwarding(self) -> None:
        """Disable IP forwarding."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            log.info("ip_forwarding_disabled")
        except Exception as e:
            # Log but don't raise - cleanup should not fail
            log.warning("ip_forwarding_disable_failed", error=str(e))
    
    def add_redirect_rule(self, port: int, redirect_to: int, protocol: str = "tcp") -> None:
        """
        Add REDIRECT rule for transparent proxy.
        
        Args:
            port: Source port (e.g., 80 for HTTP, 443 for HTTPS)
            redirect_to: Destination port (e.g., 8080 for mitmproxy)
            protocol: Protocol (tcp or udp, default: tcp)
            
        Raises:
            NetworkError: If rule addition fails
        """
        # Ensure chain exists
        self.create_chain()
        
        # Build REDIRECT rule
        rule = [
            "-A", CHAIN_NAME,
            "-i", self.interface,
            "-p", protocol,
            "--dport", str(port),
            "-j", "REDIRECT",
            "--to-port", str(redirect_to)
        ]
        
        try:
            self._run_iptables(rule)
            self.rules_applied = True
            log.info("redirect_rule_added", port=port, redirect_to=redirect_to, protocol=protocol)
        except NetworkError as e:
            log.error("redirect_rule_failed", port=port, redirect_to=redirect_to, error=str(e))
            raise

