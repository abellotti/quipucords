"""Authentication support for HashiCorp Vault."""

# At this time, we support a single HashiCorp Vault set
# of credentials for Discovery.

HASHICORP_VAULT_NAME = "hashicorp-vault-credentials"
HASHICORP_VAULT_TYPE = "hashicorp-vault"


class HashiCorpVaultAuthError(Exception):
    """Class for HashiCorp Vault authentication."""

    def __init__(self, message, *args):
        """Take message as mandatory attribute."""
        super().__init__(message, *args)
        self.message = message
