"""
@fileoverview Main application entry point
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Main application that orchestrates all Phase 1 components.
"""

import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from uvicorn import run as uvicorn_run
from .core import (
    get_platform_info,
    DependencyValidator,
    load_config,
    setup_logging,
    StartupOrchestrator,
    EXIT_SUCCESS,
    EXIT_DEPENDENCY_ERROR,
    NetworkError,
)
from .hotspot import LinuxHotspot
from .network import IPTablesManager
from .storage import DiskSpaceManager
from .api.health import router as health_router, ComponentReferences
from .core.logging import get_logger
from .core.security import KeyringManager
from .core.platform import get_platform_info as _get_platform_info
# Phase 2b: Traffic Capture
from .capture.mitm import MitmproxyManager, CertificateManager
from .capture.raw import TCPDumpManager
from .capture.session import SessionTracker
from .capture.pcap import StreamingPCAPExporter
# Phase 3: Storage & API
from .storage import DatabaseManager
from .storage.migrations import MigrationManager
from .core.security import JWTManager
from .api.auth import router as auth_router
from .api.sessions import router as sessions_router
from .api.flows import router as flows_router
from .api.devices import router as devices_router
from .api.settings import router as settings_router
from .api.analysis import router as analysis_router  # Phase 5
from .api.websocket import websocket_endpoint, ws_manager

# Initialize logging first
setup_logging(mode="production")
log = get_logger(__name__)

# Create FastAPI app
app = FastAPI(title="AX-TrafficAnalyzer", version="0.1.0")

# CORS configuration for frontend development
# In dev mode: allow localhost origins for Vite/React dev server
# In production: restrict to configured origins only
cors_origins = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,  # TODO: Load from config in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
log.debug("cors_middleware_configured", origins=cors_origins)

app.include_router(health_router)


def main():
    """Main entry point."""
    orchestrator = None
    
    try:
        log.info("application_starting")
        
        # 1. Platform detection (Phase 0)
        log.info("detecting_platform")
        platform = get_platform_info()
        log.info("platform_detected", distribution=platform.distribution, version=platform.distribution_version)
        
        # 2. Dependency validation (Phase 0)
        log.info("validating_dependencies")
        validator = DependencyValidator(platform)
        
        # 3. Load configuration (Phase 0) - needed for conditional validation
        log.info("loading_configuration")
        config = load_config()
        log.info("configuration_loaded")
        
        # Validate dependencies (with config for conditional validation)
        validator.validate_all(mode="production", config=config)
        log.info("dependencies_validated")
        
        # 3a. Validate directories (Phase 2a)
        log.info("validating_directories")
        validator.validate_directories(config)
        log.info("directories_validated")
        
        # 4. Create orchestrator
        log.info("creating_orchestrator")
        orchestrator = StartupOrchestrator()
        
        # 5. Initialize Phase 3 components (before Phase 2b)
        log.info("initializing_phase3_components")
        
        # Phase 3: Database manager
        db_manager = None
        if config.get("database", {}).get("enabled", True):
            db_config = config.get("database", {})
            db_path = db_config.get("path", "./data/ax-traffic.db")
            pool_size = db_config.get("pool_size", 5)
            max_overflow = db_config.get("max_overflow", 10)
            db_manager = DatabaseManager(db_path=db_path, pool_size=pool_size, max_overflow=max_overflow)
            log.info("database_manager_initialized", db_path=db_path)
            
            # Run migrations
            mode = config.get("mode", "production")
            migration_mgr = MigrationManager(db_path=db_path)
            migration_mgr.run_migrations(mode=mode)
            log.info("migrations_checked", mode=mode)
            
            # Create default admin user if configured
            auth_config = config.get("auth", {})
            admin_username = auth_config.get("admin_username")
            admin_password = auth_config.get("admin_password")
            
            if admin_username and admin_password:
                import asyncio
                try:
                    created = asyncio.run(db_manager.create_default_admin(admin_username, admin_password))
                    if created:
                        log.info("admin_user_auto_created_from_config", username=admin_username)
                    else:
                        log.debug("admin_user_already_exists", username=admin_username)
                except Exception as e:
                    log.error("admin_user_auto_create_failed", username=admin_username, error=str(e))
                    # Don't fail startup - admin can be created via CLI
        
        # Phase 6 Prerequisite: Redis Queue (for event processing and replay)
        redis_queue = None
        rate_config = config.get("rate_limiting", {})
        redis_url = rate_config.get("redis_url", "redis://localhost:6379")
        
        # Only initialize Redis if not in dev mode with skip_system_tools
        if not config.get("skip_system_tools", False):
            try:
                from .core.concurrency.redis_queue import RedisQueue
                redis_queue = RedisQueue(redis_url=redis_url, queue_name="ax-traffic-events")
                # Note: Connection is async, will connect on first use
                # For fail-fast in production, we could add: await redis_queue.connect()
                log.info("redis_queue_initialized", redis_url=redis_url)
            except Exception as e:
                # In production mode, Redis is required for event processing
                if config.get("mode") == "production":
                    log.error("redis_queue_init_failed", error=str(e), 
                             message="Redis required in production mode")
                    raise
                else:
                    log.warning("redis_queue_init_failed", error=str(e),
                               message="Redis unavailable, event queue disabled")
        else:
            log.info("redis_queue_skipped", reason="dev_mode_skip_system_tools")
        
        # Phase 5: Analysis Orchestrator (after database, before capture)
        analysis_orchestrator = None
        if config.get("analysis", {}).get("enabled", False) and db_manager:
            from .analysis import AnalysisOrchestrator
            analysis_orchestrator = AnalysisOrchestrator(db_manager=db_manager, config=config)
            log.info("analysis_orchestrator_initialized", 
                    enabled_analyzers=analysis_orchestrator.get_enabled_analyzers())
        else:
            if config.get("analysis", {}).get("enabled", False) and not db_manager:
                log.warning("analysis_enabled_but_no_database", 
                           message="Analysis requires database to be enabled")
            log.debug("analysis_orchestrator_skipped", 
                     analysis_enabled=config.get("analysis", {}).get("enabled", False),
                     db_available=db_manager is not None)
            
            # First-run detection and setup
            from ..core.setup import FirstRunDetector
            first_run = FirstRunDetector(db_path=db_path)
            if first_run.is_first_run():
                log.info("first_run_detected")
                print("\n" + "="*60)
                print("  AX-TrafficAnalyzer - First Run Setup")
                print("="*60)
                print("\nWelcome! This appears to be your first run.")
                print("\nTo create an admin user, run:")
                print("  python -m src.community.cli.admin create-admin")
                print("\nOr add to config.json:")
                print('  "auth": {')
                print('    "admin_username": "admin",')
                print('    "admin_password": "your-secure-password"')
                print('  }')
                print("\n" + "="*60 + "\n")
            else:
                first_run.mark_initialized()  # Ensure flag exists
        
        # Phase 3: JWT manager (only if database enabled)
        jwt_manager = None
        if db_manager:
            # Skip keyring in dev mode with skip_system_tools
            if config.get("skip_system_tools", False):
                log.info("keyring_skipped", reason="dev_mode_skip_system_tools")
                keyring_mgr = None
            else:
                keyring_mgr = KeyringManager(platform)
            jwt_manager = JWTManager(
                keyring_manager=keyring_mgr,
                token_expiry_hours=config.get("auth", {}).get("token_expiry_hours", 24)
            )
            log.info("jwt_manager_initialized")
        else:
            log.info("jwt_manager_skipped", reason="database_disabled")
        
        # Phase 3: WebSocket manager (already initialized as singleton)
        log.info("websocket_manager_ready")
        
        # 6. Initialize Phase 2b components
        log.info("initializing_phase2b_components")
        
        # Phase 2b: Certificate manager (validate OR generate) - MUST be before mitmproxy
        cert_manager = None
        if config.get("capture", {}).get("enabled", False):
            if config.get("skip_system_tools", False):
                log.info("certificate_manager_skipped", reason="dev_mode_skip_system_tools")
            else:
                log.info("initializing_certificate_manager")
                cert_manager = CertificateManager(cert_dir="./certs", keyring_manager=keyring_mgr)
                cert_manager.validate_or_generate()
                log.info("certificate_manager_ready")
        
        # IPTables (needed for both hotspot and capture)
        iptables = IPTablesManager(config["hotspot"]["interface"])
        
        # Phase 2b: Session tracker (needed before mitmproxy) - with database persistence (Phase 3)
        session_tracker = None
        if config.get("capture", {}).get("enabled", False):
            timeout = config.get("capture", {}).get("session", {}).get("timeout_seconds", 3600)
            session_tracker = SessionTracker(timeout_seconds=timeout, database=db_manager)
            log.info("session_tracker_initialized", timeout_seconds=timeout, has_database=db_manager is not None)
            
            # Register session tracker with orchestrator
            orchestrator.register_component(
                name="session_tracker",
                start_func=lambda: log.info("session_tracker_started"),
                stop_func=lambda: log.info("session_tracker_stopped"),
                component_obj=session_tracker
            )
        
        # Phase 2b: mitmproxy (needs certificate and session tracker)
        mitmproxy = None
        if config.get("capture", {}).get("enabled", False):
            mitmproxy_port = config.get("capture", {}).get("mitmproxy", {}).get("port", 8080)
            mitmproxy = MitmproxyManager(port=mitmproxy_port, cert_dir="./certs")
            log.info("mitmproxy_manager_initialized", port=mitmproxy_port)
        
        # Phase 2b: tcpdump (will be initialized after pcap_monitor if DNS analyzer enabled)
        tcpdump = None
        
        # Phase 2b: PCAP exporter
        pcap_exporter = None
        if config.get("capture", {}).get("enabled", False):
            pcap_config = config.get("capture", {}).get("pcap", {})
            buffer_size = pcap_config.get("buffer_size_mb", 10)
            output_dir = pcap_config.get("output_dir", "./captures/pcap")
            pcap_exporter = StreamingPCAPExporter(output_dir=output_dir, buffer_size_mb=buffer_size)
            log.info("pcap_exporter_initialized", buffer_size_mb=buffer_size)
        
        # Phase 5: DNS Handler and PCAP Monitor (for DNS query processing)
        dns_handler = None
        pcap_monitor = None
        if config.get("analysis", {}).get("dns_analyzer", False) and analysis_orchestrator:
            from .capture.dns import DNSHandler
            from .capture.pcap import PCAPFileMonitor
            
            dns_handler = DNSHandler(
                analysis_orchestrator=analysis_orchestrator,
                db_manager=db_manager,
                enabled=True
            )
            log.info("dns_handler_initialized")
            
            # Get PCAP directories to monitor
            # Note: tcpdump directory will be added after tcpdump is initialized
            pcap_dirs = []
            if pcap_exporter:
                pcap_dirs.append(str(pcap_exporter.output_dir))
            # tcpdump.output_dir will be added later after tcpdump initialization
            
            if pcap_dirs:
                pcap_monitor = PCAPFileMonitor(
                    pcap_directories=pcap_dirs,
                    dns_handler=dns_handler,
                    poll_interval_seconds=config.get("analysis", {}).get("pcap_poll_interval", 30)
                )
                log.info("pcap_monitor_initialized", directories=pcap_dirs)
        
        # Phase 2b: tcpdump (initialize after pcap_monitor so monitor can be passed)
        if config.get("capture", {}).get("enabled", False) and config.get("capture", {}).get("tcpdump", {}).get("enabled", False):
            interface = config["hotspot"]["interface"]
            output_dir = config.get("storage", {}).get("pcap_dir", "./captures/")
            filter_expr = config.get("capture", {}).get("tcpdump", {}).get("filter", "udp or dns")
            tcpdump = TCPDumpManager(
                interface=interface, 
                output_dir=output_dir, 
                filter_expr=filter_expr,
                pcap_monitor=pcap_monitor
            )
            log.info("tcpdump_manager_initialized", interface=interface, filter=filter_expr)
            
            # Add tcpdump output directory to pcap_monitor if it exists
            if pcap_monitor and str(tcpdump.output_dir) not in [str(d) for d in pcap_monitor.pcap_directories]:
                pcap_monitor.pcap_directories.append(tcpdump.output_dir)
                log.info("tcpdump_directory_added_to_monitor", directory=str(tcpdump.output_dir))
        
        # Hotspot (skip in dev mode with skip_system_tools)
        hotspot = None
        if not config.get("skip_system_tools", False):
            hotspot = LinuxHotspot(config)
        else:
            log.info("hotspot_skipped", reason="dev_mode_skip_system_tools")
        
        # Disk monitor
        disk_monitor = DiskSpaceManager(monitor_path="/")
        
        # 7. Register components with orchestrator (correct order)
        log.info("registering_components")
        
        # Phase 3: Database (BEFORE all capture components)
        if db_manager:
            orchestrator.register_component(
                name="database",
                start_func=lambda: db_manager.start(),
                stop_func=lambda: db_manager.stop(),
                component_obj=db_manager
            )
        
        # Certificate manager (if enabled)
        if cert_manager:
            orchestrator.register_component(
                name="certificate_manager",
                start_func=lambda: None,  # Already validated/generated in init
                stop_func=lambda: None,
                component_obj=cert_manager
            )
        
        # IPTables (must be before mitmproxy for REDIRECT rules) - skip in dev mode
        if not config.get("skip_system_tools", False):
            orchestrator.register_component(
                name="iptables",
                start_func=lambda: _start_iptables(iptables),
                stop_func=lambda: _stop_iptables(iptables),
                component_obj=iptables
            )
        else:
            log.info("iptables_skipped", reason="dev_mode_skip_system_tools")
        
        # Session tracker (before mitmproxy)
        if session_tracker:
            orchestrator.register_component(
                name="session_tracker",
                start_func=lambda: None,  # No-op, already initialized
                stop_func=lambda: None,
                component_obj=session_tracker
            )
        
        # mitmproxy (after iptables REDIRECT rules) - skip in dev mode
        if mitmproxy and not config.get("skip_system_tools", False):
            orchestrator.register_component(
                name="mitmproxy",
                start_func=lambda: _start_mitmproxy(mitmproxy),
                stop_func=lambda: _stop_mitmproxy(mitmproxy),
                component_obj=mitmproxy
            )
        elif config.get("skip_system_tools", False):
            log.info("mitmproxy_skipped", reason="dev_mode_skip_system_tools")
        
        # tcpdump - skip in dev mode
        if tcpdump and not config.get("skip_system_tools", False):
            orchestrator.register_component(
                name="tcpdump",
                start_func=lambda: _start_tcpdump(tcpdump),
                stop_func=lambda: _stop_tcpdump(tcpdump),
                component_obj=tcpdump
            )
        elif config.get("skip_system_tools", False):
            log.info("tcpdump_skipped", reason="dev_mode_skip_system_tools")
        
        # PCAP exporter - skip in dev mode
        if pcap_exporter and not config.get("skip_system_tools", False):
            orchestrator.register_component(
                name="pcap_exporter",
                start_func=lambda: _start_pcap_exporter(pcap_exporter),
                stop_func=lambda: _stop_pcap_exporter(pcap_exporter, pcap_monitor),
                component_obj=pcap_exporter
            )
        elif config.get("skip_system_tools", False):
            log.info("pcap_exporter_skipped", reason="dev_mode_skip_system_tools")
        
        # PCAP Monitor (for DNS processing)
        if pcap_monitor:
            orchestrator.register_component(
                name="pcap_monitor",
                start_func=lambda: asyncio.run(pcap_monitor.start()),
                stop_func=lambda: asyncio.run(pcap_monitor.stop()),
                component_obj=pcap_monitor
            )
        
        # Hotspot (only if not skipped)
        if hotspot:
            orchestrator.register_component(
                name="hotspot",
                start_func=lambda: _start_hotspot(hotspot),
                stop_func=lambda: _stop_hotspot(hotspot),
                component_obj=hotspot
            )
        
        # Disk monitor
        orchestrator.register_component(
            name="disk_monitor",
            start_func=lambda: _start_disk_monitor(disk_monitor),
            stop_func=lambda: _stop_disk_monitor(disk_monitor),
            component_obj=disk_monitor
        )
        
        # 8. Start orchestrator (atomic startup)
        log.info("starting_orchestrator")
        orchestrator.start()
        log.info("orchestrator_started")
        
        # 9. Store component references in app.state for health API and dependencies
        log.info("storing_components_in_app_state")
        app.state.components = ComponentReferences(
            hotspot=hotspot,
            iptables=iptables,
            disk_monitor=disk_monitor,
            cert_manager=cert_manager,
            mitmproxy=mitmproxy,
            tcpdump=tcpdump,
            session_tracker=session_tracker,
            pcap_exporter=pcap_exporter,
            # Phase 3
            database=db_manager,
            jwt_manager=jwt_manager,
            websocket_manager=ws_manager
        )
        
        # Store Phase 3 managers in app.state for API dependencies
        app.state.database = db_manager
        app.state.jwt_manager = jwt_manager
        app.state.redis_queue = redis_queue  # Phase 6: For replay queue
        
        # Initialize rate limiter
        from .api.rate_limit import init_rate_limiter
        init_rate_limiter(config)
        log.debug("rate_limiter_initialized")
        
        # 10. Include Phase 3 API routers
        log.info("registering_api_routers")
        app.include_router(auth_router)
        app.include_router(sessions_router)
        app.include_router(flows_router)
        app.include_router(devices_router)
        app.include_router(settings_router)
        app.include_router(analysis_router)  # Phase 5
        app.add_websocket_route("/ws/traffic", websocket_endpoint)
        log.info("api_routers_registered", devices_router_included=True, settings_router_included=True, analysis_router_included=True)
        
        # 10b. Serve React UI (production mode only)
        ui_dist_dir = Path("src/community/ui/dist")
        if config.get("mode") == "production" and ui_dist_dir.exists():
            log.info("serving_static_ui", path=str(ui_dist_dir))
            app.mount("/", StaticFiles(directory=str(ui_dist_dir), html=True), name="ui")
            log.info("static_ui_mounted")
        elif config.get("mode") == "production" and not ui_dist_dir.exists():
            log.warning("ui_dist_not_found", path=str(ui_dist_dir), message="Run 'npm run build' in src/community/ui/")
        else:
            log.debug("static_ui_skipped", mode=config.get("mode"), reason="dev_mode_or_disabled")
        
        # 11. Run uvicorn
        api_host = config["api"]["host"]
        api_port = config["api"]["port"]
        log.info("starting_api_server", host=api_host, port=api_port)
        
        # Register shutdown handler
        @app.on_event("shutdown")
        async def shutdown_handler():
            log.info("api_shutdown_handler_called")
            if orchestrator:
                orchestrator.stop()
        
        # Start uvicorn (blocking)
        uvicorn_kwargs = {
            "app": app,
            "host": api_host,
            "port": api_port,
            "log_config": None  # Use our structured logging
        }
        
        # Add SSL in production mode if configured
        if config.get("api", {}).get("use_ssl", False):
            ssl_keyfile = config["api"].get("ssl_keyfile", "./certs/server.key")
            ssl_certfile = config["api"].get("ssl_certfile", "./certs/server.crt")
            
            if Path(ssl_keyfile).exists() and Path(ssl_certfile).exists():
                uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile
                uvicorn_kwargs["ssl_certfile"] = ssl_certfile
                log.info("ssl_enabled", keyfile=ssl_keyfile, certfile=ssl_certfile)
            else:
                log.warning("ssl_certificates_not_found", keyfile=ssl_keyfile, certfile=ssl_certfile)
        else:
            log.debug("ssl_disabled", mode=config.get("mode"))
        
        uvicorn_run(**uvicorn_kwargs)
        
    except KeyboardInterrupt:
        log.info("keyboard_interrupt_received")
    except NetworkError as e:
        log.error("network_error", error=str(e))
        sys.exit(EXIT_DEPENDENCY_ERROR)
    except Exception as e:
        log.error("startup_failed", error=str(e), error_type=type(e).__name__)
        sys.exit(EXIT_DEPENDENCY_ERROR)
    finally:
        # Cleanup handled by orchestrator's signal handler or shutdown event
        if orchestrator:
            try:
                orchestrator.stop()
            except Exception as e:
                log.error("cleanup_failed", error=str(e))
        log.info("application_shutdown_complete")


def _start_iptables(iptables: IPTablesManager) -> None:
    """Start iptables manager."""
    log.info("starting_iptables")
    iptables.enable_ip_forwarding()
    iptables.add_rules()
    log.info("iptables_started")


def _stop_iptables(iptables: IPTablesManager) -> None:
    """Stop iptables manager."""
    log.info("stopping_iptables")
    iptables.disable_ip_forwarding()
    iptables.cleanup()
    log.info("iptables_stopped")


def _start_hotspot(hotspot: LinuxHotspot) -> None:
    """Start hotspot."""
    log.info("starting_hotspot")
    hotspot.start()
    log.info("hotspot_started")


def _stop_hotspot(hotspot: LinuxHotspot) -> None:
    """Stop hotspot."""
    log.info("stopping_hotspot")
    hotspot.stop()
    log.info("hotspot_stopped")


def _start_disk_monitor(disk_monitor: DiskSpaceManager) -> None:
    """Start disk monitor."""
    log.info("starting_disk_monitor")
    disk_monitor.start_monitoring()
    log.info("disk_monitor_started")


def _stop_disk_monitor(disk_monitor: DiskSpaceManager) -> None:
    """Stop disk monitor."""
    log.info("stopping_disk_monitor")
    disk_monitor.stop_monitoring()
    log.info("disk_monitor_stopped")


def _start_mitmproxy(mitmproxy: MitmproxyManager) -> None:
    """Start mitmproxy."""
    log.info("starting_mitmproxy")
    mitmproxy.start()
    log.info("mitmproxy_started")


def _stop_mitmproxy(mitmproxy: MitmproxyManager) -> None:
    """Stop mitmproxy."""
    log.info("stopping_mitmproxy")
    mitmproxy.stop()
    log.info("mitmproxy_stopped")


def _start_tcpdump(tcpdump: TCPDumpManager) -> None:
    """Start tcpdump."""
    log.info("starting_tcpdump")
    tcpdump.start()
    log.info("tcpdump_started")


def _stop_tcpdump(tcpdump: TCPDumpManager) -> None:
    """Stop tcpdump."""
    log.info("stopping_tcpdump")
    tcpdump.stop()
    log.info("tcpdump_stopped")


def _start_pcap_exporter(pcap_exporter: StreamingPCAPExporter) -> None:
    """Start PCAP exporter."""
    log.info("starting_pcap_exporter")
    from datetime import datetime
    filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    pcap_exporter.start(filename)
    log.info("pcap_exporter_started", filename=filename)


def _stop_pcap_exporter(pcap_exporter: StreamingPCAPExporter, pcap_monitor=None) -> None:
    """Stop PCAP exporter and trigger DNS processing."""
    log.info("stopping_pcap_exporter")
    pcap_exporter.stop(pcap_monitor=pcap_monitor)
    log.info("pcap_exporter_stopped")


if __name__ == "__main__":
    main()

