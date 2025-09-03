"""
UC Passthrough Library - Secured Authentication Manager Module

This module handles authentication with protected sensitive information.
All authentication mechanisms, tokens, and credentials are made private.
"""

import time
import threading
from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timedelta
import json
import logging
from urllib.parse import urlparse
import os
from distutils.util import strtobool

try:
    import msal
    from azure.storage.filedatalake import DataLakeServiceClient
    from azure.core.credentials import AccessToken
    from azure.identity import DefaultAzureCredential
except ImportError as e:
    raise ImportError(
        f"Required Azure libraries not found: {e}. "
        f"Please install: pip install msal azure-storage-file-datalake azure-identity"
    )

# Databricks-specific imports for user identity extraction
try:
    from pyspark.sql import SparkSession
    from pyspark.dbutils import DBUtils
except ImportError:
    # Allow for testing outside Databricks environment
    SparkSession = None
    DBUtils = None

logger = logging.getLogger(__name__)


class _TokenCache:
    """Private thread-safe token cache with automatic expiration."""
    
    def __init__(self):
        self.__cache = {}
        self.__lock = threading.RLock()
    
    def _get_token(self, key: str) -> Optional[Dict]:
        """Get cached token if still valid."""
        with self.__lock:
            if key not in self.__cache:
                return None
            
            token_data = self.__cache[key]
            # Check if token expires within next 5 minutes (300 seconds)
            if time.time() + 300 >= token_data['expires_at']:
                del self.__cache[key]
                return None
            
            return token_data
    
    def _set_token(self, key: str, token_data: Dict):
        """Cache token with expiration time."""
        with self.__lock:
            # Remove sensitive token data from logs
            safe_token_data = {k: v for k, v in token_data.items() if k != 'access_token'}
            logger.debug(f"Caching token for key: {key[:10]}... (data: {safe_token_data})")
            self.__cache[key] = token_data
    
    def _clear_all(self):
        """Clear all cached tokens."""
        with self.__lock:
            count = len(self.__cache)
            self.__cache.clear()
            logger.info(f"Cleared {count} cached tokens")
    
    def _get_stats(self) -> Dict:
        """Get cache statistics for monitoring (no sensitive data)."""
        with self.__lock:
            total = len(self.__cache)
            expired = sum(1 for t in self.__cache.values() 
                         if time.time() >= t['expires_at'])
            return {
                'total_tokens': total,
                'expired_tokens': expired,
                'valid_tokens': total - expired
            }


class _SecureCredential:
    """Private credential class that protects access tokens."""
    
    def __init__(self, access_token: str, expires_at: float):
        self.__access_token = access_token
        self.__expires_at = expires_at
    
    def get_token(self, *scopes, **kwargs) -> AccessToken:
        """Return access token for Azure SDK."""
        if time.time() >= self.__expires_at:
            raise ValueError("Token has expired")
        
        return AccessToken(
            token=self.__access_token,
            expires_on=int(self.__expires_at)
        )


class AuthenticationManager:
    """
    Secured authentication manager with protected sensitive information.
    
    All authentication mechanisms, tokens, credentials, and configuration
    are made private to prevent manipulation from user code.
    """
    
    # Private constants
    __ADLS_SCOPE = "https://storage.azure.com/.default"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AuthenticationManager with protected configuration.
        
        Args:
            config: Configuration dictionary (will be stored securely)
        """
        # Private configuration storage
        self.__config = self.__secure_config_init(config)
        self.__client_id = self.__config['client_id']
        self.__client_secret = self.__config['client_secret']
        self.__tenant_id = self.__config['tenant_id']
        self.__authority = self.__config.get('authority', f"https://login.microsoftonline.com/{self.__tenant_id}")
        self.__cache_enabled = self.__config.get('cache_tokens', True)
        self.__use_client_credentials = self.__config.get('use_client_credentials', False)
        self.__use_interactive_flow = self.__config.get('use_interactive_flow', False)
        
        # Private MSAL application
        if self.__use_client_credentials:
            self.__msal_app = msal.ConfidentialClientApplication(
                client_id=self.__client_id,
                client_credential=self.__client_secret,
                authority=self.__authority
            )
        else:
            self.__msal_app = msal.PublicClientApplication(
                client_id=self.__client_id,
                authority=self.__authority
            )
        
        # Private token cache
        self.__token_cache = _TokenCache() if self.__cache_enabled else None
        
        # Private user context
        self.__current_user = None
        self.__current_user_upn = None
        self.__current_user_object_id = None
        
        # Initialize user context during construction
        self.__initialize_user_context()
        
        logger.info("Secured AuthenticationManager initialized")
    
    def __secure_config_init(self, config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Private method to securely initialize configuration."""
        if config is None or len(config) == 0:
            value = os.getenv("PASSTHROUGH_USE_CLIENT_CREDENTIALS")
            if value is None:
                use_client_creds = False
            try:
                use_client_creds = bool(strtobool(value))
            except (ValueError, TypeError):
                use_client_creds = False
            
            value = os.getenv("PASSTHROUGH_CACHE_TOKENS")
            if value is None:
                cache_tokens = False
            try:
                cache_tokens = bool(strtobool(value))
            except (ValueError, TypeError):
                cache_tokens = False
            
            value = os.getenv("PASSTHROUGH_USE_INTERACTIVE_FLOW")
            if value is None:
                use_interactive = False
            try:
                use_interactive = bool(strtobool(value))
            except (ValueError, TypeError):
                use_interactive = False
            
            secure_config = {
                'client_id': os.getenv("PASSTHROUGH_CLIENT_ID"),
                'client_secret': os.getenv("PASSTHROUGH_CLIENT_SECRET"),
                'tenant_id': os.getenv("PASSTHROUGH_TENANT_ID"),
                'cache_tokens': cache_tokens,
                'use_client_credentials': use_client_creds,
                'use_interactive_flow': use_interactive
            }
        else:
            # Create a deep copy to prevent external modification
            secure_config = {
                'client_id': config.get('client_id'),
                'client_secret': config.get('client_secret'),
                'tenant_id': config.get('tenant_id'),
                'authority': config.get('authority'),
                'cache_tokens': config.get('cache_tokens', True),
                'use_client_credentials': config.get('use_client_credentials', False),
                'use_interactive_flow': config.get('use_interactive_flow', False)
            }

        # Validate required fields
        if not secure_config.get('client_id') or not secure_config.get('tenant_id'):
            raise ValueError("Missing required authentication configuration")
        
        return secure_config
    
    def __initialize_user_context(self, spark_session: Optional[Any] = None) -> bool:
        """Private method to initialize user context."""
        try:
            # Get Spark session if not provided
            if spark_session is None and SparkSession:
                spark_session = SparkSession.getActiveSession()
            
            if not spark_session:
                logger.warning("No active Spark session found for user context initialization")
                return False
            
            # Extract user information from Spark context
            user_info = self.__extract_user_identity(spark_session)
            
            if not user_info:
                logger.warning("Could not extract user identity from Databricks session")
                return False
            
            self.__current_user = user_info.get('username')
            self.__current_user_upn = user_info.get('upn')
            self.__current_user_object_id = user_info.get('object_id')
            
            if not self.__current_user:
                logger.warning("Failed to extract valid user identity")
                return False
            
            logger.info(f"User context initialized for: {self.__current_user[:10]}...")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize user context: {str(e)}")
            return False
    
    def initialize_user_context(self, spark_session: Optional[Any] = None) -> bool:
        """
        Public method to reinitialize user context if needed.
        
        Args:
            spark_session: Optional Spark session
            
        Returns:
            True if user context successfully initialized
        """
        return self.__initialize_user_context(spark_session)
    
    def get_adls_client(self, storage_account_url: str) -> DataLakeServiceClient:
        """
        Get authenticated ADLS client (tokens remain protected).
        
        Args:
            storage_account_url: ADLS storage account URL
            
        Returns:
            Authenticated DataLakeServiceClient
            
        Raises:
            RuntimeError: If authentication fails
        """
        if not self.__current_user:
            raise RuntimeError("User context not initialized")
        
        try:
            # Get ADLS access token (private method)
            access_token_data = self.__get_adls_access_token()
            
            # Create secure credential (private class)
            credential = _SecureCredential(
                access_token=access_token_data['access_token'],
                expires_at=access_token_data['expires_at']
            )
            
            # Create and return ADLS client
            client = DataLakeServiceClient(
                account_url=storage_account_url,
                credential=credential
            )

            logger.debug(f"Created secured ADLS client for user: {self.__current_user[:10]}...")
            return client
            
        except Exception as e:
            logger.error(f"Failed to create ADLS client: {str(e)}")
            raise RuntimeError(f"ADLS client creation failed: {str(e)}")
    
    def get_adls_access_token(self) -> str:
        """
        Get ADLS access token (WARNING: Returns sensitive data).
        
        This method is provided for backward compatibility but exposes
        sensitive token information. Use get_adls_client() instead when possible.
        
        Returns:
            Access token string
            
        Raises:
            RuntimeError: If token acquisition fails
        """
        logger.warning("Direct token access requested - consider using get_adls_client() instead")
        token_data = self.__get_adls_access_token()
        return token_data['access_token']
    
    def __get_adls_access_token(self) -> Dict[str, Any]:
        """Private method to get ADLS access token."""
        if not self.__current_user:
            raise RuntimeError("User context not initialized")
        
        # Check cache first (private method)
        cache_key = f"{self.__current_user}:adls"
        if self.__token_cache:
            cached_token = self.__token_cache._get_token(cache_key)
            if cached_token:
                logger.debug(f"Using cached ADLS token for user: {self.__current_user[:10]}...")
                return cached_token
        
        try:
            if self.__use_client_credentials:
                result = self.__msal_app.acquire_token_for_client(scopes=[self.__ADLS_SCOPE])
            elif self.__use_interactive_flow:
                result = self.__get_user_token_interactive_azure_ad(scopes=[self.__ADLS_SCOPE])
            else:
                raise RuntimeError("No valid authentication method configured")
            
            if "access_token" not in result:
                error_msg = result.get("error_description", "Unknown error")
                raise RuntimeError(f"Token acquisition failed: {error_msg}")
            
            # Calculate expiration time
            expires_in = result.get("expires_in", 3600)  # Default 1 hour
            expires_at = time.time() + expires_in
            
            token_data = {
                'access_token': result['access_token'],
                'expires_at': expires_at,
                'scope': self.__ADLS_SCOPE,
                'user': self.__current_user,
                'auth_method': 'client_credentials' if self.__use_client_credentials else 'interactive'
            }
            
            # Cache the token (private method)
            if self.__token_cache:
                self.__token_cache._set_token(cache_key, token_data)
            
            logger.debug(f"Acquired new ADLS token for user: {self.__current_user[:10]}...")
            return token_data
            
        except Exception as e:
            logger.error(f"Failed to acquire ADLS token: {str(e)}")
            raise RuntimeError(f"ADLS token acquisition failed: {str(e)}")
    
    def __get_user_token_interactive_azure_ad(self, scopes):
        """Private method for interactive Azure AD authentication."""
        try:
            # Try silent acquisition first
            accounts = self.__msal_app.get_accounts()
            if accounts:
                result = self.__msal_app.acquire_token_silent(scopes, account=accounts[0])
                if result and "access_token" in result:
                    logger.debug("Retrieved token silently")
                    return {
                        'access_token': result['access_token'],
                        'expires_at': int(time.time()) + result['expires_in']
                    }
            
            # Interactive login with device code
            flow = self.__msal_app.initiate_device_flow(scopes=scopes)
            if "user_code" not in flow:
                logger.error("Failed to create device flow")
                return None
            
            print("\nAZURE AD AUTHENTICATION REQUIRED")
            print("=" * 50)
            print(f"1. Go to: {flow['verification_uri']}")
            print(f"2. Enter code: {flow['user_code']}")
            print("3. Complete authentication in the browser")
            print("=" * 50)
            
            # Wait for user to complete authentication
            result = self.__msal_app.acquire_token_by_device_flow(flow)

            
            if "access_token" in result:
                print("Successfully authenticated!")
                return result
            else:
                logger.error(f"Authentication failed: {result.get('error_description', result)}")
                return None
                
        except Exception as e:
            logger.error(f"Error during interactive authentication: {e}")
            return None
    
    def __extract_user_identity(self, spark_session: Any) -> Optional[Dict[str, str]]:
        """Private method to extract user identity from Spark session."""
        try:
            user_info = {}
            
            # Method 1: Try Spark SQL current_user() function
            try:
                result = spark_session.sql("SELECT current_user() as username").collect()
                if result and len(result) > 0:
                    username = result[0]['username']
                    if username and username != "":
                        user_info['username'] = username
                        # Try to extract UPN if it's an email format
                        if '@' in username:
                            user_info['upn'] = username
            except Exception as e:
                logger.debug(f"Failed to get user from current_user(): {str(e)}")
            
            # Method 2: Try Spark context properties
            try:
                sc = spark_session.sparkContext
                
                # Check various Spark properties that might contain user info
                user_properties = [
                    'spark.databricks.clusterUsageTags.clusterOwnerUserId',
                    'spark.databricks.clusterUsageTags.userName', 
                    'spark.sql.execution.arrow.pyspark.enabled.user',
                    'spark.databricks.passthrough.enabled.user'
                ]
                
                for prop in user_properties:
                    try:
                        value = sc.getConf().get(prop, None)
                        if value and value != "":
                            if 'username' not in user_info:
                                user_info['username'] = value
                            if '@' in value and 'upn' not in user_info:
                                user_info['upn'] = value
                            break
                    except:
                        continue
                            
            except Exception as e:
                logger.debug(f"Failed to get user from Spark properties: {str(e)}")
            
            # Method 3: Try environment variables
            try:
                import os
                env_user = os.getenv('DATABRICKS_USER') or os.getenv('USER') or os.getenv('USERNAME')
                if env_user and 'username' not in user_info:
                    user_info['username'] = env_user
                    if '@' in env_user and 'upn' not in user_info:
                        user_info['upn'] = env_user
            except Exception as e:
                logger.debug(f"Failed to get user from environment: {str(e)}")
            
            if user_info.get('username'):
                return user_info
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error extracting user identity: {str(e)}")
            return None
    
    def refresh_tokens(self) -> bool:
        """
        Refresh all cached tokens for current user.
        
        Returns:
            True if refresh successful
        """
        try:
            if self.__token_cache:
                # Clear current user's tokens from cache
                cache_key = f"{self.__current_user}:adls"
                self.__token_cache._clear_all()
            
            # Get fresh token (private method)
            self.__get_adls_access_token()
            logger.info("Refreshed tokens successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to refresh tokens: {str(e)}")
            return False
    
    def get_current_user(self) -> Optional[str]:
        """Get current authenticated user (truncated for security)."""
        if self.__current_user:
            # Return truncated version to prevent full identity exposure
            return f"{self.__current_user[:10]}..."
        return None
    
    def get_current_user_upn(self) -> Optional[str]:
        """Get current user's UPN (truncated for security)."""
        if self.__current_user_upn:
            # Return truncated version
            parts = self.__current_user_upn.split('@')
            if len(parts) == 2:
                return f"{parts[0][:5]}...@{parts[1]}"
        return None
    
    def is_authenticated(self) -> bool:
        """Check if user context is initialized."""
        return self.__current_user is not None
    
    def clear_cache(self):
        """Clear all cached tokens."""
        if self.__token_cache:
            self.__token_cache._clear_all()
    
    def get_cache_stats(self) -> Dict:
        """Get token cache statistics (no sensitive data)."""
        if self.__token_cache:
            return self.__token_cache._get_stats()
        return {'cache_disabled': True}
    
    def test_adls_access(self, storage_account_url: str, container: str, test_path: str = "") -> Dict[str, Any]:
        """
        Test ADLS access for current user (no sensitive data in response).
        
        Args:
            storage_account_url: ADLS storage account URL
            container: Container name to test
            test_path: Optional path within container to test
            
        Returns:
            Dictionary with test results (no sensitive information)
        """
        if not self.is_authenticated():
            return {
                'success': False,
                'error': 'User context not initialized',
                'user': None
            }
        
        try:
            # Get ADLS client
            adls_client = self.get_adls_client(storage_account_url)
            file_system_client = adls_client.get_file_system_client(container)
            
            # Test basic access by listing files
            paths = file_system_client.get_paths(path=test_path, max_results=1)
            list(paths)  # Consume iterator to trigger API call
            
            return {
                'success': True,
                'user': self.get_current_user(),  # Truncated version
                'storage_account': storage_account_url,
                'container': container,
                'test_path': test_path,
                'message': 'ADLS access successful'
            }
            
        except Exception as e:
            return {
                'success': False,
                'user': self.get_current_user(),  # Truncated version
                'storage_account': storage_account_url,
                'container': container,
                'test_path': test_path,
                'error': str(e)
            }
    
    def validate_configuration(self) -> List[str]:
        """
        Validate authentication configuration (no sensitive data exposed).
        
        Returns:
            List of validation warnings/errors
        """
        warnings = []
        
        # Check required configuration (without exposing actual values)
        required_fields = ['client_id', 'tenant_id']
        for field in required_fields:
            if not self.__config.get(field):
                warnings.append(f"Missing required configuration: {field}")
        
        # Validate GUID formats (without exposing actual values)
        client_id = self.__config.get('client_id', '')
        if client_id and len(client_id) != 36:
            warnings.append("client_id should be a 36-character GUID")
        
        tenant_id = self.__config.get('tenant_id', '')
        if tenant_id and len(tenant_id) != 36:
            warnings.append("tenant_id should be a 36-character GUID")
        
        # Check if MSAL app exists (without exposing details)
        try:
            if self.__msal_app is None:
                warnings.append("Failed to create MSAL application")
        except Exception as e:
            warnings.append("MSAL application error occurred")
        
        return warnings
    
    def get_configuration_info(self) -> Dict[str, Any]:
        """
        Get non-sensitive configuration information.
        
        Returns:
            Dictionary with safe configuration details
        """
        return {
            'cache_enabled': self.__cache_enabled,
            'use_client_credentials': self.__use_client_credentials,
            'use_interactive_flow': self.__use_interactive_flow,
            'authority_domain': self.__authority.split('/')[2] if self.__authority else None,
            'tenant_id_prefix': self.__tenant_id[:8] + "..." if self.__tenant_id else None,
            'client_id_prefix': self.__client_id[:8] + "..." if self.__client_id else None,
            'authenticated': self.is_authenticated()
        }


# # Example usage and testing
# if __name__ == "__main__":
#     # Configure logging
#     logging.basicConfig(level=logging.INFO)
    
#     # Example configuration (use your actual Azure AD Service Principal)
#     config = {
#         'client_id': '12345678-1234-1234-1234-123456789012',  # Your Service Principal client ID
#         'client_secret': 'your-service-principal-secret',     # Your Service Principal client secret
#         'tenant_id': '87654321-4321-4321-4321-210987654321',  # Your Azure AD tenant ID
#         'cache_tokens': True,
#         'use_client_credentials': True  # Use client credentials flow with admin consent
#     }
    
#     try:
#         # Create authentication manager
#         auth_manager = AuthenticationManager(config)
        
#         # Validate configuration
#         warnings = auth_manager.validate_configuration()
#         if warnings:
#             print("Configuration warnings:")
#             for warning in warnings:
#                 print(f"  - {warning}")
        
#         print("AuthenticationManager created successfully")
#         print(f"MSAL Authority: {auth_manager.authority}")
#         print(f"Token caching: {'Enabled' if auth_manager.cache_enabled else 'Disabled'}")
#         print(f"Auth method: {'Client Credentials (SPN)' if auth_manager.use_client_credentials else 'OBO Flow'}")
        
#         # Example of how it would be used in Databricks:
#         # auth_manager.initialize_user_context()
#         # adls_client = auth_manager.get_adls_client("https://mystorageaccount.dfs.core.windows.net")
#         # test_result = auth_manager.test_adls_access("https://mystorageaccount.dfs.core.windows.net", "mycontainer")
        
#     except Exception as e:
#         print(f"Error: {str(e)}")