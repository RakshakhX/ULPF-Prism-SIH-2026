"""Built-in Source Pack normalization mappings."""

from src.normalization.mappings.cisco_asa import CiscoASAMapping
from src.normalization.mappings.fortinet_fortigate import FortinetFortigateMapping
from src.normalization.mappings.generic_linux_syslog import GenericLinuxSyslogMapping

__all__ = ["CiscoASAMapping", "FortinetFortigateMapping", "GenericLinuxSyslogMapping"]
