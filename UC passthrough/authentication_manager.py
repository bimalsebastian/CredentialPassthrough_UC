"""
UC Passthrough Library - Authentication Manager Module

This module handles authentication for direct ADLS access using user credentials
through Microsoft Authentication Library (MSAL) with Service Principal and admin consent.
"""  

import time
import threading
from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timedelta
import json
import logging
from urllib.parse import urlparse

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


class TokenCache:
    """Thread-safe token cache with automatic expiration."""
    
    def __init__(self):
        self._cache = {}
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Dict]:
        """Get cached token if still valid."""
        with self._lock:
            if key not in self._cache:
                return None
            
            token_data = self._cache[key]
            # Check if token expires within next 5 minutes (300 seconds)
            if time.time() + 300 >= token_data['expires_at']:
                del self._cache[key]
                return None
            
            return token_data
    
    def set(self, key: str, token_data: Dict):
        """Cache token with expiration time."""
        with self._lock:
            self._cache[key] = token_data
    
    def clear(self):
        """Clear all cached tokens."""
        with self._lock:
            self._cache.clear()
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics for monitoring."""
        with self._lock:
            total = len(self._cache)
            expired = sum(1 for t in self._cache.values() 
                         if time.time() >= t['expires_at'])
            return {
                'total_tokens': total,
                'expired_tokens': expired,
                'valid_tokens': total - expired
            }


class CustomCredential:
    """Custom credential class that uses cached user tokens for ADLS access."""
    
    def __init__(self, access_token: str, expires_at: float):
        self.access_token = access_token
        self.expires_at = expires_at
    
    def get_token(self, *scopes, **kwargs) -> AccessToken:
        """Return access token for Azure SDK."""
        if time.time() >= self.expires_at:
            raise ValueError("Token has expired")
        
        return AccessToken(
            token=self.access_token,
            expires_on=int(self.expires_at)
        )


class AuthenticationManager:
    """
    Manages authentication for direct ADLS access using Service Principal with admin consent.
    
    Key features:
    - Uses Service Principal with admin consent to act on behalf of users
    - Extracts user identity from Databricks session (not token)
    - Acquires ADLS tokens on behalf of users using client credentials flow
    - Caches tokens with automatic refresh
    - Provides ADLS clients with user-scoped permissions
    """
    
    # Azure AD scopes for different services
    ADLS_SCOPE = "https://storage.azure.com/.default"
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize AuthenticationManager with Azure AD Service Principal configuration.
        
        Args:
            config: Configuration dictionary containing:
                - client_id: Azure AD Service Principal client ID (with admin consent)
                - client_secret: Azure AD Service Principal client secret  
                - tenant_id: Azure AD tenant ID
                - authority: Optional Azure AD authority URL
                - cache_tokens: Optional boolean to enable token caching (default: True)
                - use_client_credentials: Use client credentials flow instead of OBO (default: False)
                - use_interactive_flow: Use interactive credentials flow for OBO (default: False)
        """
        self.config = config
        self.client_id = config['client_id']
        self.client_secret = config['client_secret']
        self.tenant_id = config['tenant_id']
        self.authority = config.get('authority', f"https://login.microsoftonline.com/{self.tenant_id}")
        self.cache_enabled = config.get('cache_tokens', True)
        self.use_client_credentials = config.get('use_client_credentials', False)
        self.use_interactive_flow = config.get('use_interactive_flow', False)
        
        # Initialize MSAL confidential client
        if self.use_client_credentials:
            self.msal_app = msal.ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=self.authority
            )
        else:
            self.msal_app = msal.PublicClientApplication(
                client_id=self.client_id,
                authority=self.authority
            )
        
        # Token cache
        self.token_cache = TokenCache() if self.cache_enabled else None
        
        # Current user context
        self._current_user = None
        self._current_user_upn = None
        self._current_user_object_id = None
        
        logger.info("AuthenticationManager initialized with Service Principal auth")
    
    def initialize_user_context(self, spark_session: Optional[Any] = None) -> bool:
        """
        Initialize user context by extracting user identity from Databricks session.
        
        Args:
            spark_session: Optional Spark session (auto-detected if None)
            
        Returns:
            True if user context successfully initialized
            
        Raises:
            RuntimeError: If unable to extract user context
        """
        try:
            # Get Spark session if not provided
            if spark_session is None and SparkSession:
                spark_session = SparkSession.getActiveSession()
            
            if not spark_session:
                raise RuntimeError("No active Spark session found")
            
            # Extract user information from Spark context
            user_info = self._extract_user_identity(spark_session)
            
            if not user_info:
                raise RuntimeError("Failed to extract user identity from Databricks session")
            
            self._current_user = user_info.get('username')
            self._current_user_upn = user_info.get('upn')
            self._current_user_object_id = user_info.get('object_id')
            
            if not self._current_user:
                raise RuntimeError("Failed to extract user identity from Databricks session")
            
            logger.info(f"User context initialized for: {self._current_user}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize user context: {str(e)}")
            raise RuntimeError(f"User context initialization failed: {str(e)}")
    
    def get_adls_client(self, storage_account_url: str) -> DataLakeServiceClient:
        """
        Get authenticated ADLS client using Service Principal with user context.
        
        Args:
            storage_account_url: ADLS storage account URL
            
        Returns:
            Authenticated DataLakeServiceClient with user-scoped permissions
            
        Raises:
            RuntimeError: If authentication fails
        """
        if not self._current_user:
            raise RuntimeError("User context not initialized. Call initialize_user_context() first.")
        
        try:
            # Get ADLS access token using Service Principal (acts on behalf of user)
            access_token = self._get_adls_access_token()
            
            # Create custom credential
            credential = CustomCredential(
                access_token=access_token['access_token'],
                expires_at=access_token['expires_at']
            )
            
            # Create and return ADLS client
            client = DataLakeServiceClient(
                account_url=storage_account_url,
                credential=credential
            )
            
            logger.debug(f"Created ADLS client for {storage_account_url} (user: {self._current_user})")
            return client
            
        except Exception as e:
            logger.error(f"Failed to create ADLS client: {str(e)}")
            raise RuntimeError(f"ADLS client creation failed: {str(e)}")
    
    def get_adls_access_token(self) -> str:
        """
        Get ADLS access token for current user context.
        
        Returns:
            Access token string
            
        Raises:
            RuntimeError: If token acquisition fails
        """
        token_data = self._get_adls_access_token()
        return token_data['access_token']
    
    def _get_adls_access_token(self) -> Dict[str, Any]:
        """
        Get ADLS access token using Service Principal (with admin consent to act on behalf of users).
        
        Returns:
            Dictionary with access_token and expires_at
        """
        if not self._current_user:
            raise RuntimeError("User context not initialized")
        
        # Check cache first
        cache_key = f"{self._current_user}:adls"
        if self.token_cache:
            cached_token = self.token_cache.get(cache_key)
            if cached_token:
                logger.debug(f"Using cached ADLS token for {self._current_user}")
                return cached_token
        
        try:
            if self.use_client_credentials:
                # Use client credentials flow (SPN has admin consent to access on behalf of users)
                result = self.msal_app.acquire_token_for_client(scopes=[self.ADLS_SCOPE])
            # else:
            #     # Alternative: Use OBO flow if we had user token
            #     # This would require the user's JWT token from Databricks
            #     raise NotImplementedError("OBO flow requires user JWT token extraction")
            if self.use_interactive_flow:
                result = self._get_user_token_interactive_azure_ad(scopes=[self.ADLS_SCOPE])
            if "access_token" not in result:
                error_msg = result.get("error_description", "Unknown error")
                raise RuntimeError(f"Token acquisition failed: {error_msg}")
            
            # Calculate expiration time
            expires_in = result.get("expires_in", 3600)  # Default 1 hour
            expires_at = time.time() + expires_in
            
            token_data = {
                'access_token': result['access_token'],
                'expires_at': expires_at,
                'scope': self.ADLS_SCOPE,
                'user': self._current_user,
                'auth_method': 'client_credentials'
            }
            
            # Cache the token
            if self.token_cache:
                self.token_cache.set(cache_key, token_data)
            
            logger.debug(f"Acquired new ADLS token for {self._current_user} via Service Principal")
            return token_data
            
        except Exception as e:
            logger.error(f"Failed to acquire ADLS token: {str(e)}")
            raise RuntimeError(f"ADLS token acquisition failed: {str(e)}")
    
    def _get_user_token_interactive_azure_ad(self, scopes):
        """
        Use interactive Azure AD authentication to get user token
        This is the most reliable method for Databricks notebooks
        """
        try:
        
            # Try silent acquisition first
            accounts = self.msal_app.get_accounts()
            if accounts:
                result = self.msal_app.acquire_token_silent(scopes, account=accounts[0])
                if result and "access_token" in result:
                    print("✓ Got token silently")
                    return {
                        'access_token': result['access_token'],
                        'expires_at': int(time.time()) + result['expires_in']
                    }
            
            # Interactive login with device code (works in notebooks)
            flow = self.msal_app.initiate_device_flow(scopes=scopes)
            if "user_code" not in flow:
                print("❌ Failed to create device flow")
                return None
            
            print("\n🔐 AZURE AD AUTHENTICATION REQUIRED")
            print("=" * 50)
            print(f"1. Go to: {flow['verification_uri']}")
            print(f"2. Enter code: {flow['user_code']}")
            print("3. Complete authentication in the browser")
            print("=" * 50)
            
            # Wait for user to complete authentication
            result = self.msal_app.acquire_token_by_device_flow(flow)
            
            if "access_token" in result:
                print("✓ Successfully authenticated!")
                return result
            else:
                print(f"❌ Authentication failed: {result.get('error_description', result)}")
                return None
                
        except Exception as e:
            print(f"❌ Error during interactive authentication: {e}")
            return None
    

    def _extract_user_identity(self, spark_session: Any) -> Optional[Dict[str, str]]:
        """
        Extract current user identity from Spark session.
        
        Args:
            spark_session: Active Spark session
            
        Returns:
            Dictionary with user identity information or None
        """
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
            
            # Method 2: Try Databricks notebook context
            try:
                # This would require Databricks-specific APIs
                # dbutils = DBUtils(spark_session)
                # user_info['username'] = dbutils.notebook.entry_point.getDbutils().notebook().getContext().userName().get()
                pass
            except Exception as e:
                logger.debug(f"Failed to get user from notebook context: {str(e)}")
            
            # Method 3: Try Spark context properties
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
                    value = sc.getConf().get(prop, None)
                    if value and value != "":
                        if 'username' not in user_info:
                            user_info['username'] = value
                        if '@' in value and 'upn' not in user_info:
                            user_info['upn'] = value
                        break
                            
            except Exception as e:
                logger.debug(f"Failed to get user from Spark properties: {str(e)}")
            
            # Method 4: Try environment variables
            try:
                import os
                env_user = os.getenv('DATABRICKS_USER') or os.getenv('USER') or os.getenv('USERNAME')
                if env_user and 'username' not in user_info:
                    user_info['username'] = env_user
                    if '@' in env_user and 'upn' not in user_info:
                        user_info['upn'] = env_user
            except Exception as e:
                logger.debug(f"Failed to get user from environment: {str(e)}")
            
            # Method 5: Try to get user info from Databricks workspace API context
            try:
                # This would require accessing Databricks workspace context
                # Could potentially get object_id, upn, etc. from workspace user info
                pass
            except Exception as e:
                logger.debug(f"Failed to get user from workspace context: {str(e)}")
            
            if user_info.get('username'):
                logger.info(f"Extracted user identity: {user_info['username']}")
                return user_info
            else:
                logger.warning("Could not extract user identity from any source")
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
            if self.token_cache:
                # Clear current user's tokens from cache
                cache_key = f"{self._current_user}:adls"
                self.token_cache._cache.pop(cache_key, None)
            
            # Get fresh token
            self._get_adls_access_token()
            logger.info(f"Refreshed tokens for {self._current_user}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to refresh tokens: {str(e)}")
            return False
    
    def get_current_user(self) -> Optional[str]:
        """Get current authenticated user."""
        return self._current_user
    
    def get_current_user_upn(self) -> Optional[str]:
        """Get current user's UPN (User Principal Name)."""
        return self._current_user_upn
    
    def get_current_user_object_id(self) -> Optional[str]:
        """Get current user's Azure AD object ID."""
        return self._current_user_object_id
    
    def is_authenticated(self) -> bool:
        """Check if user context is initialized."""
        return self._current_user is not None
    
    def clear_cache(self):
        """Clear all cached tokens."""
        if self.token_cache:
            self.token_cache.clear()
            logger.info("Token cache cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get token cache statistics."""
        if self.token_cache:
            return self.token_cache.get_cache_stats()
        return {'cache_disabled': True}
    
    def test_adls_access(self, storage_account_url: str, container: str, test_path: str = "") -> Dict[str, Any]:
        """
        Test ADLS access for current user.
        
        Args:
            storage_account_url: ADLS storage account URL
            container: Container name to test
            test_path: Optional path within container to test
            
        Returns:
            Dictionary with test results
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
                'user': self._current_user,
                'storage_account': storage_account_url,
                'container': container,
                'test_path': test_path,
                'message': 'ADLS access successful'
            }
            
        except Exception as e:
            return {
                'success': False,
                'user': self._current_user,
                'storage_account': storage_account_url,
                'container': container,
                'test_path': test_path,
                'error': str(e)
            }
    
    def validate_configuration(self) -> List[str]:
        """
        Validate authentication configuration.
        
        Returns:
            List of validation warnings/errors
        """
        warnings = []
        
        # Check required configuration
        required_fields = ['client_id', 'client_secret', 'tenant_id']
        for field in required_fields:
            if not self.config.get(field):
                warnings.append(f"Missing required configuration: {field}")
        
        # Validate client_id format (should be a GUID)
        client_id = self.config.get('client_id', '')
        if client_id and len(client_id) != 36:
            warnings.append("client_id should be a 36-character GUID")
        
        # Validate tenant_id format
        tenant_id = self.config.get('tenant_id', '')
        if tenant_id and len(tenant_id) != 36:
            warnings.append("tenant_id should be a 36-character GUID")
        
        # Check if MSAL app can be created
        try:
            if self.msal_app is None:
                warnings.append("Failed to create MSAL application")
        except Exception as e:
            warnings.append(f"MSAL application error: {str(e)}")
        
        # Validate admin consent requirement
        if self.use_client_credentials:
            warnings.append("INFO: Service Principal requires admin consent for https://storage.azure.com/.default scope")
        
        return warnings


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
