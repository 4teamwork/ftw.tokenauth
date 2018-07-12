from ftw.upgrade import UpgradeStep
from ftw.tokenauth.pas.storage import CredentialStorage


class AddUserIdToAccessTokens(UpgradeStep):
    """Add user id to access tokens and log entries.
    """

    def __call__(self):
        uf = self.getToolByName('acl_users')
        plugin = uf['token_auth']
        storage = CredentialStorage(plugin)

        # Add user id to access tokens
        for access_token in storage._access_tokens.values():
            if 'user_id' not in access_token:
                key_id = access_token['key_id']
                service_key = storage._service_keys[key_id]
                access_token['user_id'] = service_key['user_id']

        # Add user id to log entries
        for key_id, log_entries in storage._usage_logs.items():
            service_key = storage._service_keys.get(key_id)
            # The log may contain entries for deleted service keys
            # No need to migrate as those entries are not shown anywhere
            if service_key is None:
                continue
            for log_entry in log_entries:
                if 'user_id' not in log_entry:
                    service_key = storage._service_keys.get(key_id)
                    log_entry['user_id'] = service_key['user_id']
