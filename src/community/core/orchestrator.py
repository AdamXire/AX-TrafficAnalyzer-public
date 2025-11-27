"""
@fileoverview Startup Orchestrator - Atomic startup/shutdown coordinator
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Coordinates atomic startup and shutdown of all components.
Handles signal registration (SIGINT, SIGTERM) and ensures cleanup.
"""

import signal
import sys
from typing import List, Callable, Optional, Any
from dataclasses import dataclass
from .logging import get_logger
from .errors import NetworkError

log = get_logger(__name__)


@dataclass
class Component:
    """Component with cleanup callback."""
    name: str
    start: Callable[[], None]
    stop: Callable[[], None]
    object: Optional[Any] = None


class StartupOrchestrator:
    """
    Orchestrates atomic startup and shutdown of all components.
    
    Ensures all-or-nothing startup: if any component fails after step 10,
    rollback all previous components in reverse order.
    
    Single signal handler registration - components do not register their own.
    """
    
    def __init__(self):
        """Initialize orchestrator."""
        self.components: List[Component] = []
        self.started_components: List[Component] = []  # Track what started successfully
        self._shutdown_requested = False
        self._original_signal_handlers = {}
        self._register_signal_handlers()
    
    def _register_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        # Save original handlers
        self._original_signal_handlers[signal.SIGINT] = signal.signal(signal.SIGINT, self._signal_handler)
        self._original_signal_handlers[signal.SIGTERM] = signal.signal(signal.SIGTERM, self._signal_handler)
        log.debug("signal_handlers_registered")
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle termination signals (SIGINT, SIGTERM)."""
        signal_name = signal.Signals(signum).name
        log.info("shutdown_signal_received", signal=signal_name)
        self._shutdown_requested = True
        self.stop()
        # Restore original handler and re-raise
        signal.signal(signum, self._original_signal_handlers.get(signum, signal.SIG_DFL))
        sys.exit(0)
    
    def register_component(
        self,
        name: str,
        start_func: Callable[[], None],
        stop_func: Callable[[], None],
        component_obj: Optional[Any] = None
    ) -> None:
        """
        Register a component with start/stop functions.
        
        Args:
            name: Component name (for logging)
            start_func: Function to start component (raises exception on failure)
            stop_func: Function to stop component (must not raise)
            component_obj: Optional component object reference
        """
        component = Component(
            name=name,
            start=start_func,
            stop=stop_func,
            object=component_obj
        )
        self.components.append(component)
        log.debug("component_registered", name=name)
    
    def start(self) -> None:
        """
        Start all components atomically.
        
        If any component fails, rollback all previously started components
        in reverse order, then raise the exception.
        """
        log.info("orchestrator_start_begin", component_count=len(self.components))
        
        try:
            for component in self.components:
                log.info("starting_component", name=component.name)
                try:
                    component.start()
                    self.started_components.append(component)
                    log.info("component_started", name=component.name)
                except Exception as e:
                    log.error(
                        "component_start_failed",
                        name=component.name,
                        error=str(e),
                        error_type=type(e).__name__
                    )
                    # Rollback all started components
                    self._rollback()
                    raise NetworkError(
                        f"Failed to start component '{component.name}': {e}",
                        None
                    ) from e
            
            log.info("orchestrator_start_complete", started_count=len(self.started_components))
        
        except Exception as e:
            log.error("orchestrator_start_failed", error=str(e))
            self._rollback()
            raise
    
    def _rollback(self) -> None:
        """Rollback all started components in reverse order."""
        log.warning("orchestrator_rollback_begin", components_to_rollback=len(self.started_components))
        
        # Stop in reverse order
        for component in reversed(self.started_components):
            try:
                log.info("rolling_back_component", name=component.name)
                component.stop()
                log.debug("component_rollback_complete", name=component.name)
            except Exception as e:
                # Log but continue rollback
                log.error(
                    "component_rollback_failed",
                    name=component.name,
                    error=str(e)
                )
        
        self.started_components.clear()
        log.warning("orchestrator_rollback_complete")
    
    def stop(self) -> None:
        """
        Gracefully stop all components in reverse order.
        
        Called by signal handler or manually for graceful shutdown.
        """
        if not self.started_components:
            log.debug("orchestrator_stop_no_components")
            return
        
        log.info("orchestrator_stop_begin", component_count=len(self.started_components))
        
        # Stop in reverse order
        for component in reversed(self.started_components):
            try:
                log.info("stopping_component", name=component.name)
                component.stop()
                log.debug("component_stopped", name=component.name)
            except Exception as e:
                # Log but continue shutdown
                log.error(
                    "component_stop_failed",
                    name=component.name,
                    error=str(e)
                )
        
        self.started_components.clear()
        log.info("orchestrator_stop_complete")
    
    def cleanup(self) -> None:
        """
        Emergency cleanup - called by signal handler.
        
        Same as stop(), but may be called during exception handling.
        """
        self.stop()

