import asyncio
import argparse
import sys
import os
import yaml
from typing import Dict, Any
from modules.monitor import DarkWebMonitor
from modules.alerting import AlertManager
from modules.dashboard import run_dashboard
from modules.security import SecureLogger, InputValidator, get_env_or_config, secure_exit

# Initialize secure logger
logger = SecureLogger("darkhound.main")


def load_and_validate_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load and validate configuration file with security checks"""
    try:
        if not os.path.exists(config_path):
            logger.error(f"Configuration file not found: {config_path}")
            return {}
        
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        
        if not InputValidator.validate_config_structure(config):
            logger.error("Invalid configuration structure")
            return {}
        
        logger.info("Configuration loaded and validated successfully")
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error in configuration: {type(e).__name__}")
        return {}
    except PermissionError:
        logger.error("Permission denied reading configuration file")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error loading configuration: {type(e).__name__}")
        return {}


def validate_arguments(args: argparse.Namespace) -> bool:
    """Validate command line arguments"""
    # Dashboard argument is boolean, already validated by argparse
    if hasattr(args, 'config') and args.config:
        if not isinstance(args.config, str) or len(args.config) > 255:
            logger.error("Invalid configuration file path")
            return False
    
    return True


async def main():
    """Main monitoring function with secure error handling"""
    config = load_and_validate_config()
    if not config:
        logger.error("Failed to load valid configuration, exiting")
        secure_exit(logger, 1)
    
    try:
        monitor = DarkWebMonitor(config)
        alert_manager = AlertManager(config)
        logger.info("DarkHound monitoring engine started")
        
        async for finding in monitor.scan():
            if finding:  # Additional validation
                logger.info("Leak detected - processing alert")
                try:
                    alert_manager.send_alert(finding)
                    monitor.save_finding(finding)
                except Exception as alert_error:
                    logger.error(f"Alert processing failed: {type(alert_error).__name__}")
            
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
    except asyncio.CancelledError:
        logger.info("Monitoring cancelled")
    except Exception as e:
        logger.error(f"Monitoring engine error: {type(e).__name__}")
        secure_exit(logger, 1)


def main_cli():
    """Main CLI entry point with secure argument parsing"""
    parser = argparse.ArgumentParser(
        description="DarkHound - Dark Web Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For more information, see the documentation."
    )
    
    parser.add_argument(
        "--dashboard", 
        action="store_true", 
        help="Launch web dashboard interface"
    )
    
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    
    try:
        args = parser.parse_args()
        
        if not validate_arguments(args):
            logger.error("Invalid arguments provided")
            secure_exit(logger, 1)
        
        # Set configuration path if provided
        config_path = args.config if hasattr(args, 'config') else "config.yaml"
        
        if args.dashboard:
            logger.info("Starting dashboard mode")
            try:
                run_dashboard(config_path)
            except Exception as e:
                logger.error(f"Dashboard startup failed: {type(e).__name__}")
                secure_exit(logger, 1)
        else:
            logger.info("Starting monitoring mode")
            try:
                asyncio.run(main())
            except KeyboardInterrupt:
                logger.info("Application stopped by user")
            except Exception as e:
                logger.error(f"Application startup failed: {type(e).__name__}")
                secure_exit(logger, 1)
                
    except SystemExit:
        # Handle argparse errors gracefully
        pass
    except Exception as e:
        logger.error(f"Argument parsing error: {type(e).__name__}")
        secure_exit(logger, 1)


if __name__ == "__main__":
    main_cli()