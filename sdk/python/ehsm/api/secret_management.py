from ehsm.serializers.secret_management import *
from ehsm.api.base import EHSMBaseClient

from typing import Optional


class SecretManagementMixin(EHSMBaseClient):
    def create_secret(
        self,
        secret_name: str,
        secret_data: str,
        encryption_key_id: Optional[str] = None,
        description: Optional[str] = None,
        rotation_interval: Optional[str] = None,
    ):
        """
        Creates a secret and stores its initial version
        """
        resp = self._session.post(
            "",
            params={"Action": "CreateSecret"},
            data={
                "secretName": secret_name,
                "secretData": secret_data,
                "encryptionKeyId": encryption_key_id,
                "description": description,
                "rotationInterval": rotation_interval,
            },
        )
        return CreateSecretResponse.from_response(resp)

    def update_secret_description(
        self, secret_name: str, description: Optional[str] = None
    ):
        """
        Update the description of a secret
        """
        resp = self._session.post(
            "",
            params={"Action": "UpdateSecretDesc"},
            data={
                "secretName": secret_name,
                "description": description,
            },
        )
        return UpdateSecretDescResponse.from_response(resp)

    def put_secret_value(self, secret_name: str, secret_data: str):
        """
        Stores the secret value of a new version into a secret object
        """
        resp = self._session.post(
            "",
            params={"Action": "PutSecretValue"},
            data={
                "secretName": secret_name,
                "secretData": secret_data,
            },
        )
        return PutSecretValueResponse.from_response(resp)

    def list_secret_version_ids(self, secret_name: str):
        """
        Queries all versions of a secret. Maximum 4000 line
        """
        resp = self._session.post(
            "",
            params={"Action": "ListSecretVersionIds"},
            data={
                "secretName": secret_name,
            },
        )
        return ListSecretVersionIdsResponse.from_response(resp)

    def list_secrets(self, secret_name: Optional[str] = None):
        """
        Queries all secrets created by your appid. Maximum 4000 line
        """
        resp = self._session.post(
            "",
            params={"Action": "ListSecrets"},
            data={
                "secretName": secret_name,
            },
        )
        return ListSecretsResponse.from_response(resp)

    def describe_secret(self, secret_name: str):
        """
        Obtains the metadata of a secret
        """
        resp = self._session.post(
            "",
            params={"Action": "DescribeSecret"},
            data={
                "secretName": secret_name,
            },
        )
        return DescribeSecretResponse.from_response(resp)

    def delete_secret(
        self,
        secret_name: str,
        recovery_period: Optional[int] = None,
        force_delete: Optional[bool] = None,
    ):
        """
        Force delete secret or schedule a time to delete secret
        """
        resp = self._session.post(
            "",
            params={
                "Action": "DeleteSecret",
            },
            data={
                "secretName": secret_name,
                "recoveryPeriod": recovery_period,
                "force_delete": "true" if force_delete else "false",
            },
        )
        return DeleteSecretResponse.from_response(resp)

    def get_secret_value(self, secret_name: str, version_id: Optional[int] = None):
        """
        Obtains a secret value
        """
        resp = self._session.post(
            "",
            params={
                "Action": "GetSecretValue",
            },
            data={
                "secretName": secret_name,
                "versionId": version_id,
            },
        )
        return GetSecretValueResponse.from_response(resp)

    def restore_secret(self, secret_name: str):
        """
        Restores a deleted secret
        """
        resp = self._session.post(
            "",
            params={
                "Action": "RestoreSecret",
            },
            data={
                "secretName": secret_name,
            },
        )
        return RestoreSecretResponse.from_response(resp)
