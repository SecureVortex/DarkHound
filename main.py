#!/usr/bin/env python3
"""
DarkHound - Dark Web Monitoring Tool
Secure implementation following OWASP guidelines and secure coding practices.
"""
import asyncio
import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

from secure_config import SecureConfig, logger

# Conditional imports to handle missing dependencies gracefully
try:
    from modules.monitor import DarkWebMonitor
    from modules.alerting import AlertManager
    from modules.dashboard import run_dashboard
    MODULES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Some modules unavailable: {e}")
    MODULES_AVAILABLE = False


class DarkHoundApp:
    """Main application class for DarkHound with secure initialization."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize DarkHound application with secure configuration."""
        try:
            self.config = SecureConfig(config_path or "config.yaml")
            if not self.config.validate_required_settings():
                logger.warning("Running with incomplete configuration")
            
            # Initialize components with configuration
            self.monitor = None
            self.alert_manager = None
            
        except Exception as e:
            logger.error(f"Failed to initialize DarkHound: {e}")
            raise SystemExit(1)
    
    async def initialize_components(self):
        """Initialize monitoring components asynchronously."""
        if not MODULES_AVAILABLE:
            raise ImportError("Required modules are not available. Install dependencies with: pip install -r requirements.txt")
        
        try:
            self.monitor = DarkWebMonitor(self.config)
            self.alert_manager = AlertManager(self.config)
            logger.info("Components initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise
    
    async def run_monitoring(self):
        """Run the monitoring engine with proper error handling."""
        if not self.monitor or not self.alert_manager:
            await self.initialize_components()
        
        logger.info("Starting DarkHound monitoring engine...")
        
        try:
            scan_count = 0
            async for finding in self.monitor.scan():
                scan_count += 1
                logger.info(f"Processing finding #{scan_count}")
                
                try:
                    # Validate finding data before processing
                    if self._validate_finding(finding):
                        self.alert_manager.send_alert(finding)
                        self.monitor.save_finding(finding)
                        logger.info(f"Leak detected and processed: {finding.get('keyword', 'unknown')}")
                    else:
                        logger.warning(f"Invalid finding data skipped: {type(finding)}")
                        
                except Exception as e:
                    logger.error(f"Error processing finding: {e}")
                    # Continue processing other findings
                    continue
                    
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Critical error in monitoring loop: {e}")
            raise
        finally:
            logger.info("Monitoring engine shutdown")
    
    def _validate_finding(self, finding) -> bool:
        """Validate finding data structure."""
        if not isinstance(finding, dict):
            return False
        
        required_fields = ['keyword', 'context']
        return all(field in finding for field in required_fields)


def validate_arguments(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""
    if args.config and args.config != '-':
        config_path = Path(args.config)
        if not config_path.exists():
            logger.error(f"Configuration file not found: {args.config}")
            return False
        if not config_path.is_file():
            logger.error(f"Configuration path is not a file: {args.config}")
            return False
    
    return True


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser with input validation."""
    parser = argparse.ArgumentParser(
        description="DarkHound - Dark Web Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run monitoring with default config
  %(prog)s --dashboard              # Launch web dashboard
  %(prog)s --config custom.yaml     # Use custom configuration file
  %(prog)s --verbose                # Enable verbose logging
        """
    )
    
    parser.add_argument(
        "--dashboard", 
        action="store_true", 
        help="Launch web dashboard interface"
    )
    
    parser.add_argument(
        "--config", 
        type=str, 
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable verbose logging output"
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version="DarkHound 1.0.0"
    )
    
    return parser


async def main():
    """Main entry point with secure error handling."""
    try:
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Configure logging level
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Verbose logging enabled")
        
        # Validate arguments
        if not validate_arguments(args):
            return 1
        
        # Initialize application
        app = DarkHoundApp(args.config)
        
        if args.dashboard:
            if not MODULES_AVAILABLE:
                logger.error("Dashboard module unavailable. Install dependencies with: pip install -r requirements.txt")
                return 1
            logger.info("Launching dashboard interface")
            run_dashboard()
        else:
            await app.run_monitoring()
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Unhandled error: {e}")
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)