"""Abstraction for retrieving data from OpenShift/Kubernetes API."""

from pathlib import Path
from unittest import mock
from uuid import UUID

import httpretty
import pytest

from scanner.openshift.api import OpenShiftApi
from scanner.openshift.entities import (
    ClusterOperator,
    LifecycleOperator,
    NodeResources,
    OCPCluster,
    OCPError,
    OCPNode,
    OCPPod,
    OCPWorkload,
)
from tests.asserts import assert_elements_type
from tests.constants import ConstantsFromEnv, VCRCassettes


def data_path(filename) -> Path:
    """Path object for testing data."""
    return Path(__file__).parent / "test_data" / filename


class TestData:
    """
    Constants holding path for OCP Rest Api responses.

    They are based on real data and then were tweaked/reduced for testing purposes.
    """

    API_RESOURCE_LIST = data_path("api_resource_list.json")
    UNAUTHORIZED_RESPONSE = data_path("unauthorized_response.json")


def patch_ocp_api(path, **kwargs):
    """Shortcut for patching ocp requests."""
    ocp_uri = ConstantsFromEnv.TEST_OCP_URI.value
    httpretty.register_uri(
        httpretty.GET,
        f"{ocp_uri.protocol}://{ocp_uri.host}:{ocp_uri.port}/{path}",
        **kwargs,
    )


def dynamic_scope(fixture_name, config):
    """Set scope to session when running with --refresh-cassettes."""
    if config.getoption("--refresh-cassettes", None):
        return "session"
    return "function"


@pytest.fixture(scope=dynamic_scope)
def discoverer_cache(request, testrun_uid):
    """OCP dynamic client "discoverer" cache."""
    fname = "ocp-discovery.json"
    if request.config.getoption("--refresh-cassettes"):
        # persist cache file for whole test suite execution
        _file = Path("/tmp/qpc") / testrun_uid / fname
        _file.parent.mkdir(parents=True, exist_ok=True)
        yield _file

    else:
        yield request.getfixturevalue("tmp_path") / fname


@pytest.fixture(scope=dynamic_scope)
def ocp_client(request, discoverer_cache):
    """OCP client for testing."""
    ocp_uri = ConstantsFromEnv.TEST_OCP_URI.value
    auth_token = getattr(request, "param", ConstantsFromEnv.TEST_OCP_AUTH_TOKEN.value)
    client = OpenShiftApi.with_config_info(
        auth_token=auth_token,
        host=ocp_uri.host,
        port=ocp_uri.port,
        protocol=ocp_uri.protocol,
        ssl_verify=ConstantsFromEnv.TEST_OCP_SSL_VERIFY.value,
    )
    client._discoverer_cache_file = discoverer_cache
    yield client


@pytest.mark.vcr_primer(VCRCassettes.OCP_UNAUTHORIZED)
@pytest.mark.vcr(match_on=["method", "scheme", "host", "port", "query"])
@pytest.mark.parametrize("ocp_client", ["<INVALID_AUTH_TOKEN>"], indirect=True)
@pytest.mark.parametrize("api_method", ["_dynamic_client"])
def test_unauthorized_token(ocp_client: OpenShiftApi, api_method):
    """Test calling OCP with an invalid token."""
    with pytest.raises(OCPError) as exc_info:
        client_attr = getattr(ocp_client, api_method)
        # if error wasn't thrown in previous line, let's assume attribute is a callable
        client_attr()
    assert exc_info.value.status == 401
    assert exc_info.value.reason == "Unauthorized"


@pytest.mark.vcr_primer(VCRCassettes.OCP_DISCOVERER_CACHE)
def test_dynamic_client_cache(ocp_client: OpenShiftApi):
    """
    Test dynamic_client cache.

    Whenever a new "api resource" is added to ocp_client we need to add it to this test
    and run `pytest --refresh-cassettes` using a valid OCP connection.
    """
    assert (
        not ocp_client._discoverer_cache_file.exists()
    ), "Cache file exists prior to test excecution!"
    # just accessing the attribute will trigger "introspection" requests at ocp
    ocp_client._dynamic_client
    ocp_client._cluster_api
    ocp_client._node_api
    ocp_client._namespace_api
    ocp_client._pod_api
    ocp_client._cluster_operator_api
    ocp_client._subscription_api
    ocp_client._cluster_service_version_api
    ocp_client._managed_cluster_api
    assert Path(ocp_client._discoverer_cache_file).exists()


@pytest.mark.vcr_primer(VCRCassettes.OCP_CLUSTER, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_cluster_api(ocp_client: OpenShiftApi):
    """Test _cluster_api."""
    clusters = ocp_client._list_clusters()
    assert clusters


@pytest.mark.vcr_primer(
    VCRCassettes.OCP_CLUSTER_OPERATORS, VCRCassettes.OCP_DISCOVERER_CACHE
)
def test_cluster_operators_api(ocp_client: OpenShiftApi):
    """Test _cluster_api."""
    cluster_operators = ocp_client._list_cluster_operators()
    assert cluster_operators


@pytest.mark.vcr_primer(
    VCRCassettes.OCP_SUBSCRIPTIONS, VCRCassettes.OCP_DISCOVERER_CACHE
)
def test_subscriptions_api(ocp_client: OpenShiftApi):
    """Test _cluster_api."""
    subscriptions = ocp_client._list_subscriptions()
    assert subscriptions


@pytest.mark.vcr_primer(VCRCassettes.OCP_CSV, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_csv_api(ocp_client: OpenShiftApi):
    """Test _list_cluster_service_versions."""
    csv_list = ocp_client._list_cluster_service_versions()
    assert csv_list


@pytest.mark.vcr_primer(VCRCassettes.OCP_ACM, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_cluster_acm_api(ocp_client: OpenShiftApi):
    """Test _managed_cluster_api."""
    acm_metrics = ocp_client._list_managed_clusters()
    assert acm_metrics


@pytest.mark.vcr(VCRCassettes.OCP_CLUSTER, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_retrieve_cluster(ocp_client: OpenShiftApi):
    """Test retrieve cluster method."""
    cluster = ocp_client.retrieve_cluster()
    assert isinstance(cluster, OCPCluster)
    assert UUID(cluster.uuid)
    assert cluster.version


@pytest.mark.vcr(
    VCRCassettes.OCP_CLUSTER_OPERATORS,
    VCRCassettes.OCP_SUBSCRIPTIONS,
    VCRCassettes.OCP_CSV,
    VCRCassettes.OCP_DISCOVERER_CACHE,
)
def test_retrieve_operators(ocp_client: OpenShiftApi):
    """Test retrieve operators method."""
    operators = ocp_client.retrieve_operators()
    assert isinstance(operators, list)
    assert isinstance(operators[0], ClusterOperator)
    # OCP instance used on VCR preparation should have at least one lifecycle operator
    # installed (doesn't matter which one)
    assert isinstance(operators[-1], LifecycleOperator)


@pytest.mark.vcr(
    VCRCassettes.OCP_ACM,
    VCRCassettes.OCP_DISCOVERER_CACHE,
)
def test_retrieve_acm_metrics(ocp_client: OpenShiftApi):
    """Test retrieve acm metrics method."""
    # OCP instance used on VCR preparation should have ACM operator installed,
    # with active multiClusterHub instance
    acm_metrics = ocp_client.retrieve_acm_metrics()
    assert isinstance(acm_metrics, list)
    min_cluster_msg = "This test requires at least 1 cluster managed through ACM."
    assert len(acm_metrics) >= 1, min_cluster_msg

    # The following assertion is based on the assumption that the provisioned cluster
    # has not undergone any additional config modifications. When creating the
    # multiClusterHub instance, it is expected that at least one managed cluster will
    # be discovered, the hub itself. An associated set of keys is expected.
    # The "available" key within these metrics is expected to be True, indicating that
    # the cluster is available and configured properly.

    expected_keys = [
        "vendor",
        "cloud",
        "version",
        "managed_cluster_id",
        "available",
        "core_worker",
        "socket_worker",
        "created_via",
    ]
    expected_data = [{key: mock.ANY for key in expected_keys}] * len(acm_metrics)
    assert acm_metrics == expected_data
    # at least one cluster is available
    assert any(cluster_metrics["available"] for cluster_metrics in acm_metrics)


@pytest.mark.parametrize(
    "status_info, expected_metrics",
    [
        (
            {
                "conditions": [{"reason": "ManagedClusterAvailable"}],
                "capacity": {"core_worker": 4, "socket_worker": 2},
            },
            [
                {
                    "available": True,
                    "cloud": "cloud1",
                    "core_worker": 4,
                    "created_via": "via1",
                    "managed_cluster_id": "id1",
                    "socket_worker": 2,
                    "vendor": "vendor1",
                    "version": "version1",
                }
            ],
        ),
        (
            {
                "conditions": [
                    {"reason": "ManagedClusterWaitForImporting"},
                    {"reason": "HubClusterAdminAccepted"},
                ],
            },
            [
                {
                    "available": False,
                    "cloud": "cloud1",
                    "core_worker": None,
                    "created_via": "via1",
                    "managed_cluster_id": "id1",
                    "socket_worker": None,
                    "vendor": "vendor1",
                    "version": "version1",
                }
            ],
        ),
        (
            {
                "conditions": [
                    {"reason": "ManagedClusterWaitForImporting"},
                    {"reason": "ManagedClusterAvailable"},
                ],
                "capacity": {"cpu": 24},
            },
            [
                {
                    "available": True,
                    "cloud": "cloud1",
                    "core_worker": None,
                    "created_via": "via1",
                    "managed_cluster_id": "id1",
                    "socket_worker": None,
                    "vendor": "vendor1",
                    "version": "version1",
                }
            ],
        ),
    ],
)
def test_init_managed_cluster(
    ocp_client: OpenShiftApi, mocker, status_info, expected_metrics
):
    """Test logic creating managed cluster metrics dict."""
    mock_managed_cluster = {
        "metadata": {
            "labels": {
                "vendor": "vendor1",
                "cloud": "cloud1",
                "openshiftVersion": "version1",
                "clusterID": "id1",
            },
            "annotations": {"open-cluster-management/created-via": "via1"},
        },
        "status": status_info,
    }

    mocker.patch.object(
        ocp_client,
        "_list_managed_clusters",
        return_value=mocker.Mock(items=[mock_managed_cluster]),
    )

    acm_metrics = ocp_client.retrieve_acm_metrics()

    assert acm_metrics == expected_metrics


def test_olm_operator_construction(ocp_client: OpenShiftApi, mocker, faker):
    """Test logic creating LifecycleOperator."""
    operator_csv = "papaya_operator.v1.2.3"
    operator_display_name = "Papaya Operator"

    subscription = mocker.Mock()
    subscription.status.currentCSV = operator_csv
    subscription.metadata.name = faker.slug()
    subscription.metadata.creationTimestamp = faker.date_time()
    subscription.status.lastUpdated = faker.date_time()
    subscription.metadata.namespace = faker.slug()
    subscription.spec.channel = faker.slug()
    subscription.spec.source = faker.slug()

    csv = mocker.Mock()
    csv.metadata.name = operator_csv
    csv.spec.displayName = operator_display_name

    mocker.patch.object(OpenShiftApi, "_list_cluster_operators")
    mocker.patch.object(
        OpenShiftApi,
        "_list_subscriptions",
        return_value=mocker.Mock(items=[subscription]),
    )
    mocker.patch.object(
        OpenShiftApi,
        "_list_cluster_service_versions",
        return_value=mocker.Mock(items=[csv]),
    )

    operators = ocp_client.retrieve_operators()
    assert len(operators) == 1
    assert operators[0].display_name == operator_display_name
    assert operators[0].cluster_service_version == operator_csv


@pytest.mark.vcr_primer(VCRCassettes.OCP_NODE, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_node_api(ocp_client: OpenShiftApi):
    """Test _node_api."""
    nodes = ocp_client._list_nodes()
    assert nodes


@pytest.mark.vcr(VCRCassettes.OCP_NODE, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_retrieve_node(ocp_client: OpenShiftApi):
    """Test retrieve node method."""
    list_nodes = ocp_client.retrieve_nodes()
    for node in list_nodes:
        assert isinstance(node, OCPNode)
        assert isinstance(node.allocatable, NodeResources)
        assert isinstance(node.capacity, NodeResources)
        assert node.name


def test_with_config_info_using_auth_token(mocker):
    """Test factory method with_config_info with auth_token."""
    patched_kube_config = mocker.patch("scanner.openshift.api.KubeConfig")
    patched_api_client = mocker.patch("scanner.openshift.api.ApiClient")
    client = OpenShiftApi.with_config_info(
        host="HOST", protocol="PROT", port="PORT", auth_token="TOKEN"
    )
    assert isinstance(client, OpenShiftApi)
    assert patched_kube_config.mock_calls == [
        mocker.call(
            host="PROT://HOST:PORT",
            api_key={"authorization": "bearer TOKEN"},
        )
    ]
    assert patched_api_client.mock_calls == [
        mocker.call(configuration=patched_kube_config()),
    ]
    assert client._api_client == patched_api_client()


@httpretty.activate
def test_can_connect(ocp_client: OpenShiftApi):
    """Test if connection to OCP host is succesful when it should be."""
    patch_ocp_api(
        "api/v1/",
        body=TestData.API_RESOURCE_LIST.read_text(),
    )
    assert ocp_client.can_connect()


@httpretty.activate
def test_cannot_connect(
    ocp_client: OpenShiftApi,
    caplog,
):
    """Test if connection to OCP host is not sucessful when it should not be."""
    patch_ocp_api(
        "api/v1/",
        body=TestData.UNAUTHORIZED_RESPONSE.read_text(),
        status=401,
    )
    assert not ocp_client.can_connect()
    assert caplog.messages[-1] == "Unable to connect to OCP/K8S api (status=401)"


@pytest.mark.vcr_primer(VCRCassettes.OCP_PODS, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_pods_api(ocp_client: OpenShiftApi):
    """Test pods api."""
    pods = ocp_client._list_pods()
    assert pods


@pytest.mark.vcr(VCRCassettes.OCP_PODS, VCRCassettes.OCP_DISCOVERER_CACHE)
def test_retrieve_pods(ocp_client: OpenShiftApi):
    """Test retrieving pods."""
    pods = ocp_client.retrieve_pods()
    assert_elements_type(pods, OCPPod)


@pytest.mark.vcr(
    VCRCassettes.OCP_PODS,
    VCRCassettes.OCP_DISCOVERER_CACHE,
    allow_playback_repeats=True,
)
def test_retrieve_workloads(ocp_client: OpenShiftApi):
    """Test retrieving workloads."""
    pods = ocp_client.retrieve_pods()
    workloads = ocp_client.retrieve_workloads()
    assert_elements_type(workloads, OCPWorkload)
    assert len(workloads) < len(pods)
    assert {p.app_name for p in pods} == {a.name for a in workloads}
