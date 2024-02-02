"""OpenShift Base task runner."""

from abc import ABCMeta

from api.models import ScanTask
from api.vault import decrypt_data_as_unicode
from scanner.openshift.api import OpenShiftApi
from scanner.runner import ScanTaskRunner


class OpenShiftTaskRunner(ScanTaskRunner, metaclass=ABCMeta):
    """Base OpenShift task runner."""

    supports_partial_results = False

    @classmethod
    def _get_connection_info(cls, scan_task: ScanTask):
        host = scan_task.source.get_hosts()[0]
        port = scan_task.source.port
        ssl_enabled, ssl_verify = cls._ssl_options(scan_task)
        credential = scan_task.source.single_credential
        conn_info = {
            "host": host,
            "port": port,
            "protocol": "https" if ssl_enabled else "http",
            "ssl_verify": ssl_verify,
        }
        if credential.auth_token:
            conn_info.update(auth_token=decrypt_data_as_unicode(credential.auth_token))
        else:
            conn_info.update(
                username=credential.username,
                password=decrypt_data_as_unicode(credential.password),
            )

        return conn_info

    @classmethod
    def get_ocp_client(cls, scan_task: ScanTask) -> OpenShiftApi:
        """Get an OpenShiftApi properly initialized with source/credential info."""
        ocp_kwargs = cls._get_connection_info(scan_task)
        return OpenShiftApi.with_config_info(**ocp_kwargs)

    @classmethod
    def _ssl_options(cls, scan_task: ScanTask):
        """
        Get ssl related options for scan_task.

        Note: this logic should be enforced on SourceOptionsSerializer.
        Should be fixed in a subsequent PR.

        :return: ssl_enabled, ssl_verify
        :rtype: (bool, bool)
        """
        ssl_enabled = not scan_task.source.disable_ssl
        if ssl_enabled is None:
            ssl_enabled = True

        ssl_verify = False
        if ssl_enabled:
            ssl_verify = scan_task.source.ssl_cert_verify
            if ssl_verify is None:
                ssl_verify = True

        return ssl_enabled, ssl_verify
