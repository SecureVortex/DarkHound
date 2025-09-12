import aiohttp
import asyncio
from typing import Optional
from modules.security import SecureLogger, InputValidator

logger = SecureLogger("darkhound.tor_requests")

async def tor_get(url: str, timeout: int = 30) -> Optional[str]:
    """Secure Tor request with proper validation and error handling"""
    if not url or not isinstance(url, str):
        logger.error("Invalid URL provided")
        return None
    
    # Validate URL format
    if not InputValidator.validate_url(url):
        logger.error("URL validation failed")
        return None
    
    # Validate timeout
    if not isinstance(timeout, int) or timeout <= 0 or timeout > 120:
        logger.warning("Invalid timeout, using default")
        timeout = 30
    
    try:
        # Example using local Tor SOCKS5 proxy at 127.0.0.1:9050
        # Requires Tor running locally!
        proxy = "socks5://127.0.0.1:9050"
        
        # Set up secure client session
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        connector = aiohttp.TCPConnector(
            limit=10,  # Limit connections
            limit_per_host=2,  # Limit per host
            keepalive_timeout=30
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers={'User-Agent': 'Mozilla/5.0 (compatible)'}  # Basic user agent
        ) as session:
            
            async with session.get(
                url, 
                proxy=proxy,
                allow_redirects=False,  # Don't follow redirects for security
                max_line_size=8192,     # Limit line size
                max_field_size=8192     # Limit field size
            ) as response:
                
                # Validate response
                if response.status != 200:
                    logger.warning(f"HTTP error response: {response.status}")
                    return None
                
                # Check content length
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > 1024 * 1024:  # 1MB limit
                    logger.warning("Response too large, skipping")
                    return None
                
                # Read response with size limit
                content = await response.text(encoding='utf-8', errors='ignore')
                
                # Additional size check after reading
                if len(content) > 1024 * 1024:  # 1MB limit
                    logger.warning("Response content too large after reading")
                    return content[:1024 * 1024]  # Truncate
                
                logger.info("Successfully retrieved content from source")
                return content
                
    except asyncio.TimeoutError:
        logger.error("Request timeout")
        return None
    except aiohttp.ClientProxyConnectionError:
        logger.error("Proxy connection error - check Tor service")
        return None
    except aiohttp.ClientConnectorError:
        logger.error("Connection error")
        return None
    except aiohttp.ClientResponseError as e:
        logger.error(f"HTTP response error: {e.status}")
        return None
    except aiohttp.ClientError as e:
        logger.error(f"Client error: {type(e).__name__}")
        return None
    except UnicodeDecodeError:
        logger.error("Content encoding error")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in tor_get: {type(e).__name__}")
        return None