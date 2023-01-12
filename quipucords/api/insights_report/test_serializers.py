# Copyright (C) 2022  Red Hat, Inc.

# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv3
# along with this software; if not, see
# https://www.gnu.org/licenses/gpl-3.0.txt.

"""Test insigths serializers."""

import pytest

from api.common.entities import ReportEntity
from api.insights_report.serializers import (
    FactsetSerializer,
    YupanaMetadataSerializer,
    YupanaPayloadSerializer,
)
from tests.factories import DeploymentReportFactory


@pytest.fixture
def report_entity():
    """Return a ReportEntity with 10 hosts."""
    deployment_report = DeploymentReportFactory.create(number_of_fingerprints=10)
    return ReportEntity.from_report_id(deployment_report.id)


@pytest.mark.dbcompat
def test_factset_serializer(db, report_entity):
    """Test FactsetSerializer."""
    serializer = FactsetSerializer(
        report_entity.hosts[0],
        many=True,
    )
    assert isinstance(serializer.data, list)
    assert isinstance(serializer.data[0]["facts"], dict)


@pytest.mark.dbcompat
def test_metadata_serializer(db, report_entity):
    """Test YupanaMetadataSerializer."""
    serializer = YupanaMetadataSerializer(report_entity)
    data = serializer.data
    assert data["report_slices"] == {
        str(report_slice_id): {"number_hosts": report_slice.number_of_hosts}
        for report_slice_id, report_slice in report_entity.slices.items()
    }


@pytest.mark.dbcompat
def test_payload_serializer(db, report_entity: ReportEntity):
    """Test YupanaPayloadSerializer."""
    serializer = YupanaPayloadSerializer(report_entity)
    data = serializer.data
    metadata_key = f"report_id_{report_entity.report_id}/metadata.json"
    metadata = data.pop(metadata_key)
    assert metadata["report_slices"] == {
        str(s.slice_id): {"number_hosts": len(s.hosts)}
        for s in report_entity.slices.values()
    }