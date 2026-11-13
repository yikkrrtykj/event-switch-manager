"""Shared vocabulary for planned devices and platform observations."""

from enum import StrEnum


class DeviceFamily(StrEnum):
    CATALYST_2960X = "catalyst-2960x"
    CATALYST_3850 = "catalyst-3850"
    CATALYST_9200 = "catalyst-9200"
    CATALYST_9300 = "catalyst-9300"
    CATALYST_C1000 = "catalyst-c1000"


class DeviceRole(StrEnum):
    CORE = "core"
    ACCESS = "access"
    EXTERNAL_DISTRIBUTION = "external-distribution"
