# Object Identifiers (OIDs) used to query network devices.
# See http://tools.cisco.com/Support/SNMP/do/BrowseOID.do for full description.

# Device Information
sysDescrOid = '1.3.6.1.2.1.1.1.0'
sysUptimeOid = '1.3.6.1.2.1.1.3.0'
sysContactOid = '1.3.6.1.2.1.1.4.0'
sysNameOid = '1.3.6.1.2.1.1.5.0'
sysLocationOid = '1.3.6.1.2.1.1.6.0'
entPhysicalSerialNumOid = '1.3.6.1.2.1.47.1.1.1.1.11'
chassisSerialNumberStringOid = '1.3.6.1.4.1.9.5.1.2.19'

# for associating mac addresses to a port
atPhysAddressOid = '1.3.6.1.2.1.3.1.1.2'
vtpVlanStateOid = '1.3.6.1.4.1.9.9.46.1.3.1.1.'         # List of VLans to use for indexing
dot1dTpFdbAddressOid = '1.3.6.1.2.1.17.4.3.1.1'         # List of MACs
dot1dTpFdbPortOid = '1.3.6.1.2.1.17.4.3.1.2'            # Port associated to MAC
dot1dBasePortIfIndexOid = '1.3.6.1.2.1.17.1.4.1.2'      # Name of port

# Cisco Discovery Pprotocol (CDP) Neighbors
cdpCacheAddressOid = '1.3.6.1.4.1.9.9.23.1.2.1.1.4'     # HEX of IP address W\ Marker
cdpCacheDeviceIdOid = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'    # NAME of neighbors W\ Marker
cdpCacheDevicePortOid = '1.3.6.1.4.1.9.9.23.1.2.1.1.7'  # PORT of neighbors W\ Marker
cdpCachePlatformOid = '1.3.6.1.4.1.9.9.23.1.2.1.1.8'    # Neighbor's Hardware Platform.

# Interface specific information
ifIndexOid = '1.3.6.1.2.1.2.2.1.1'
ifNameOid = '1.3.6.1.2.1.31.1.1.1.1'
ifAdminStatusOid = '1.3.6.1.2.1.2.2.1.7'
ifOperStatusOid = '1.3.6.1.2.1.2.2.1.8'
ifAliasOid = '1.3.6.1.2.1.31.1.1.1.18'
ifSpeedOid = '1.3.6.1.2.1.2.2.1.5'
ifInErrorsOid = '1.3.6.1.2.1.2.2.1.14'
ifOutErrorsOid = '1.3.6.1.2.1.2.2.1.20'
vlanTrunkPortDynamicStatusOid = '1.3.6.1.4.1.9.9.46.1.6.1.1.14'
vmVlanOid = '1.3.6.1.4.1.9.9.68.1.2.2.1.2'
dot3StatsDuplexStatusOid = '1.3.6.1.2.1.10.7.2.1.19'
