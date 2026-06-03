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
        self.__cache = {}
        self.__lock = threading.RLock()

    def get(self, key: str) -> Optional[Dict]:
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

    def set(self, key: str, token_data: Dict):
        """Cache token with expiration time."""
        with self.__lock:
            self.__cache[key] = token_data

    def remove(self, key: str):
        """Remove a specific key from the cache."""
        with self.__lock:
            self.__cache.pop(key, None)

    def clear(self):
        """Clear all cached tokens."""
        with self.__lock:
            self.__cache.clear()

    def get_cache_stats(self) -> Dict:
        """Get cache statistics for monitoring."""
        with self.__lock:
            total = len(self.__cache)
            expired = sum(1 for t in self.__cache.values()
                         if time.time() >= t['expires_at'])
            return {
                'total_tokens': total,
                'expired_tokens': expired,
                'valid_tokens': total - expired
            }

    def __repr__(self):
        return f"TokenCache(entries={len(self.__cache)})"

    def __str__(self):
        return self.__repr__()


class CustomCredential:
    """
    Azure SDK credential that auto-refreshes via AuthenticationManager.

    The Azure SDK calls get_token() before every ADLS request.  Rather than
    snapshotting a token at client-creation time (which causes expiry errors
    mid-session), this credential holds a reference to the manager and
    re-acquires a token on demand whenever the current one is within 5 minutes
    of expiry.  The manager's TokenCache handles deduplication so there is no
    extra network round-trip while the token remains valid.
    """

    def __init__(self, auth_manager: 'AuthenticationManager'):
        self.__auth_manager = auth_manager
        # Eagerly fetch a token so any auth errors surface at construction time
        self._refresh()

    def _refresh(self):
        token_data = self.__auth_manager._get_adls_access_token()
        self.__access_token = token_data['access_token']
        self.__expires_at   = token_data['expires_at']

    def get_token(self, *scopes, **kwargs) -> 'AccessToken':
        """Return a valid access token, refreshing if within 5 minutes of expiry."""
        if time.time() + 300 >= self.__expires_at:
            self._refresh()
        return AccessToken(
            token=self.__access_token,
            expires_on=int(self.__expires_at)
        )

    def __repr__(self):
        return "CustomCredential(token=***)"

    def __str__(self):
        return self.__repr__()


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

    __slots__ = (
        '_AuthenticationManager__config',
        '_AuthenticationManager__client_id',
        '_AuthenticationManager__client_secret',
        '_AuthenticationManager__tenant_id',
        '_AuthenticationManager__authority',
        '_AuthenticationManager__msal_app',
        '_AuthenticationManager__token_cache',
        '_AuthenticationManager__current_user',
        '_AuthenticationManager__current_user_upn',
        '_AuthenticationManager__current_user_object_id',
        '_AuthenticationManager__cache_enabled',
        '_AuthenticationManager__use_client_credentials',
        '_AuthenticationManager__use_interactive_flow',
    )

    # Azure AD scopes for different services
    ADLS_SCOPE = "https://storage.azure.com/.default"

    @staticmethod
    def _coerce_bool(value) -> bool:
        """
        Safely coerce a config value to bool.
        Handles Python booleans, integers, and the string representations that
        come from os.environ ('true', 'false', '1', '0', 'yes', 'no').
        Non-empty strings are NOT treated as truthy — only recognised true-words are.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return bool(value)
        return str(value).strip().lower() in ('1', 'true', 'yes')

    @staticmethod
    def _safe_path(path: str) -> str:
        """Return a truncated path safe for logging (container + first segment only)."""
        if not path:
            return "<empty>"
        parts = path.strip('/').split('/')
        if len(parts) <= 2:
            return path
        return f"{parts[0]}/{parts[1]}/..."

    def _scrub_options(self, options: dict) -> dict:
        """Return a copy of options with sensitive values redacted."""
        if not options:
            return {}
        sensitive_keys = {
            'sas_token', 'account_key', 'credential', 'token',
            'client_secret', 'client_id', 'tenant_id',
            'adls_chunk_size_bytes'
        }
        return {k: '***' if k in sensitive_keys else v for k, v in options.items()}

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
        self.__config = config
        self.__client_id = config['client_id']
        self.__client_secret = config['client_secret']
        self.__tenant_id = config['tenant_id']
        self.__authority = config.get('authority', f"https://login.microsoftonline.com/{self.__tenant_id}")
        self.__cache_enabled = self._coerce_bool(config.get('cache_tokens', True))
        self.__use_client_credentials = self._coerce_bool(config.get('use_client_credentials', False))
        self.__use_interactive_flow = self._coerce_bool(config.get('use_interactive_flow', False))

        # Initialize MSAL confidential client
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

        # Token cache
        self.__token_cache = TokenCache() if self.__cache_enabled else None

        # Current user context
        self.__current_user = None
        self.__current_user_upn = None
        self.__current_user_object_id = None

        logger.info("AuthenticationManager initialized with Service Principal auth")

    def __repr__(self):
        return f"AuthenticationManager(authenticated={self.is_authenticated}, user=***)"

    def __str__(self):
        return self.__repr__()

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

            self.__current_user = user_info.get('username')
            self.__current_user_upn = user_info.get('upn')
            self.__current_user_object_id = user_info.get('object_id')

            if not self.__current_user:
                raise RuntimeError("Failed to extract user identity from Databricks session")

            logger.info(f"User context initialized for: {self.__current_user}")
            return True

        except Exception as e:
            logger.error("Failed to initialize user context")
            raise RuntimeError("User context initialization failed")

    def _get_adls_client(self, storage_account_url: str) -> DataLakeServiceClient:
        """
        Get authenticated ADLS client using Service Principal with user context.

        Args:
            storage_account_url: ADLS storage account URL

        Returns:
            Authenticated DataLakeServiceClient with user-scoped permissions

        Raises:
            RuntimeError: If authentication fails
        """
        if not self.__current_user:
            raise RuntimeError("User context not initialized. Call initialize_user_context() first.")

        try:
            # Create a self-refreshing credential — no static token snapshot
            credential = CustomCredential(auth_manager=self)

            # Create and return ADLS client
            client = DataLakeServiceClient(
                account_url=storage_account_url,
                credential=credential
            )

            logger.debug(f"Created ADLS client for storage account (user: {self.__current_user})")
            return client

        except Exception as e:
            logger.error("Failed to create ADLS client")
            raise RuntimeError("ADLS client creation failed")

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
        if not self.__current_user:
            raise RuntimeError("User context not initialized")

        # Check cache first
        cache_key = f"{self.__current_user}:adls"
        if self.__token_cache:
            cached_token = self.__token_cache.get(cache_key)
            if cached_token:
                logger.debug("Using cached ADLS token")
                return cached_token

        try:
            if self.__use_client_credentials:
                # Use client credentials flow (SPN has admin consent to access on behalf of users)
                result = self.__msal_app.acquire_token_for_client(scopes=[self.ADLS_SCOPE])
            if self.__use_interactive_flow:
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
                'user': self.__current_user,
                'auth_method': 'client_credentials'
            }

            # Cache the token
            if self.__token_cache:
                self.__token_cache.set(cache_key, token_data)

            logger.debug("Acquired new ADLS token via Service Principal")
            return token_data

        except Exception as e:
            logger.error("Failed to acquire ADLS token")
            raise RuntimeError("ADLS token acquisition failed")

    def _get_user_token_interactive_azure_ad(self, scopes):
        """
        Use interactive Azure AD authentication to get user token
        This is the most reliable method for Databricks notebooks
        """
        try:

            # Try silent acquisition first
            accounts = self.__msal_app.get_accounts()
            if accounts:
                result = self.__msal_app.acquire_token_silent(scopes, account=accounts[0])
                if result and "access_token" in result:
                    # Validate it's actually a user token before returning
                    try:
                        parts = result['access_token'].split('.')
                        import base64
                        payload = json.loads(base64.b64decode(parts[1] + '=='))
                        if payload.get('upn') or payload.get('unique_name'):
                            logger.debug("Got valid user token silently")
                            return result
                        else:
                            logger.warning("Silent token has no upn — forcing device flow")
                    except Exception:
                        logger.warning("Token validation failed — forcing device flow")

            # Interactive login with device code (works in notebooks)
            flow = self.__msal_app.initiate_device_flow(scopes=scopes)
            if "user_code" not in flow:
                print("Failed to create device flow")
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
                print(f"Authentication failed: {result.get('error_description', 'Unknown error')}")
                return None

        except Exception as e:
            print("Error during interactive authentication")
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
                logger.debug("Failed to get user from current_user()")

            # Method 2: Try Databricks notebook context
            try:
                pass
            except Exception as e:
                logger.debug("Failed to get user from notebook context")

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
                logger.debug("Failed to get user from Spark properties")

            # Method 4: Try environment variables
            try:
                import os
                env_user = os.getenv('DATABRICKS_USER') or os.getenv('USER') or os.getenv('USERNAME')
                if env_user and 'username' not in user_info:
                    user_info['username'] = env_user
                    if '@' in env_user and 'upn' not in user_info:
                        user_info['upn'] = env_user
            except Exception as e:
                logger.debug("Failed to get user from environment")

            # Method 5: Try to get user info from Databricks workspace API context
            try:
                pass
            except Exception as e:
                logger.debug("Failed to get user from workspace context")

            if user_info.get('username'):
                logger.info(f"Extracted user identity: {user_info['username']}")
                return user_info
            else:
                logger.warning("Could not extract user identity from any source")
                return None

        except Exception as e:
            logger.error("Error extracting user identity")
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
                self.__token_cache.remove(cache_key)

            # Get fresh token
            self._get_adls_access_token()
            logger.info("Refreshed tokens for current user")
            return True

        except Exception as e:
            logger.error("Failed to refresh tokens")
            return False

    def get_current_user(self) -> Optional[str]:
        """Get current authenticated user."""
        return self.__current_user

    def get_current_user_upn(self) -> Optional[str]:
        """Get current user's UPN (User Principal Name)."""
        return self.__current_user_upn

    def get_current_user_object_id(self) -> Optional[str]:
        """Get current user's Azure AD object ID."""
        return self.__current_user_object_id

    @property
    def is_authenticated(self) -> bool:
        """Check if user context is initialized."""
        return self.__current_user is not None

    def clear_cache(self):
        """Clear all cached tokens."""
        if self.__token_cache:
            self.__token_cache.clear()
            logger.info("Token cache cleared")

    def get_cache_stats(self) -> Dict:
        """Get token cache statistics."""
        if self.__token_cache:
            return self.__token_cache.get_cache_stats()
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
        if not self.is_authenticated:
            return {
                'success': False,
                'error': 'User context not initialized',
                'user': None
            }

        try:
            # Get ADLS client
            adls_client = self._get_adls_client(storage_account_url)
            file_system_client = adls_client.get_file_system_client(container)

            # Test basic access by listing files
            paths = file_system_client.get_paths(path=test_path, max_results=1)
            list(paths)  # Consume iterator to trigger API call

            return {
                'success': True,
                'user': self.__current_user,
                'storage_account': storage_account_url,
                'container': container,
                'test_path': self._safe_path(test_path),
                'message': 'ADLS access successful'
            }

        except Exception as e:
            return {
                'success': False,
                'user': self.__current_user,
                'storage_account': storage_account_url,
                'container': container,
                'test_path': self._safe_path(test_path),
                'error': 'ADLS access test failed'
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
            if not self.__config.get(field):
                warnings.append(f"Missing required configuration: {field}")

        # Validate client_id format (should be a GUID)
        client_id = self.__config.get('client_id', '')
        if client_id and len(client_id) != 36:
            warnings.append("client_id should be a 36-character GUID")

        # Validate tenant_id format
        tenant_id = self.__config.get('tenant_id', '')
        if tenant_id and len(tenant_id) != 36:
            warnings.append("tenant_id should be a 36-character GUID")

        # Check if MSAL app can be created
        try:
            if self.__msal_app is None:
                warnings.append("Failed to create MSAL application")
        except Exception as e:
            warnings.append("MSAL application error")

        # Validate admin consent requirement
        if self.__use_client_credentials:
            warnings.append("INFO: Service Principal requires admin consent for https://storage.azure.com/.default scope")

        return warnings
