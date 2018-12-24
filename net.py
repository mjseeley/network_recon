import re
import sys
import time
from collections import defaultdict

__author__ = 'Mike Seeley'

"""
net.py
 Creates a Device object that contains varying information regard network ports attached devices and other details.

"""

# Todo: Find bottlenecks: Regex, str searches, snmp walk vs bulkget, Etc... Currently doubles overall runtime. :(


# Try import of pysnmp module, won't work without it.
try:
    from pysnmp.entity.rfc3413.oneliner import cmdgen
except Exception as e:
    print("FATAL: failed to load required module 'pysnmp'", e)
    sys.exit(1)

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

# for asscoiating mac addresses to a port
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


# Description:        SNMP helper function: BULKGET a list of OIDs.
# Returns:            A list of values returned from the Network Device.
def snmp_get_bulk_oid(ip, community, oid_list):
    """
    :param ip: IP Address
    :param community: Community String
    :param oid_list: List of OID string
    :return result: list of values related to the supplied OID
    """
    cg = cmdgen.CommandGenerator()
    err_indicator, err_status, err_index, result_t = cg.getCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((ip, 161), timeout=2, retries=1),
        *oid_list
    )
    result = []
    for row in result_t:
        result.append(row[1].prettyPrint())
    return result


# Description:        SNMP helper function: GET a single OID and return.
# Returns:            The value of the 'oid' passed in as an argument.
def snmp_get_single_oid(ip, community, oid):
    """
    :param ip: IP Address
    :param community: Community String
    :param oid: OID String
    :return result: A value related to the supplied OID
    """
    cg = cmdgen.CommandGenerator()
    err_indicator, err_status, err_index, result = cg.getCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((ip, 161), timeout=2, retries=0),
        oid
    )
    if err_indicator:
        result = ''
    else:
        for key, value in result:
            result = value.prettyPrint()
    return result


# Description:        SNMP helper function: WALK an OID.
# Returns:            [ (oid, value), (oid_next, value_next) ... ]
def snmp_walk_oid(ip, community, oid):
    """
    :param ip: IP Address
    :param community: Community String
    :param oid: OID String
    :return result: A list of OID values related to the supplied OID base
    """
    cg = cmdgen.CommandGenerator()
    err_indicator, err_status, err_index, result = cg.nextCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((ip, 161), timeout=3, retries=1),
        oid
    )
    if err_indicator:
        result = ''
    return result


# Description:        Get the people friendly interface names.
# Returns:            Dict of interface index and name {'10001': 'Fa0/1'}
def get_ifname(ip, community):
    """
    *** No longer used - Was rolled into get device ports. ***
    Dictionary of interface index number and name {'10001': 'Fa0/1'}
    A static key, value pair of '0': 'MfPkt/0' is added to the dict at creation to handle malformed packets that
    are given an interface index without an associtated interface name causing errors.
    :param ip: IP Address
    :param community: Community String
    :return ifname_dict:  key is  port id, value is friendly name {'10001': 'Fa0/1'}
    """
    ifname_dict = {'0': 'MfPkt/0'}
    ifnames = snmp_walk_oid(ip, community, ifNameOid)
    for ifname in ifnames:
        for val, name in ifname:
            val = '.'.join(val.prettyPrint().split('.')[-1:])
            name = name.prettyPrint()
            ifname_dict[val] = name
    return ifname_dict


# Description:        Detect whether or not a SNMP connection is made.
# Returns:            Boolean
def get_device_status(ip, community):
    """
    :param ip: IP Address
    :param community: Community String
    :return Boolean
    """
    snmp_check = snmp_get_single_oid(ip, community, sysNameOid)
    if snmp_check:
        return True
    else:
        return False


# Description:        Get physically attached devices.
# Returns:            List of tuples [(IP, MAC), (IP, MAC)]
def get_arp_table(ip, community):
    """
    :param ip: IP Address
    :param community: Community String
    :return arp_ip_list: List of tuples [(IP, MAC), (IP, MAC)]
    """
    arp_ip_list = []
    arp_table = snmp_walk_oid(ip, community, atPhysAddressOid)
    for entry in arp_table:
        for name, val in entry:
            name = '.'.join(name.prettyPrint().split('.')[-4:])
            val = val.prettyPrint().replace('0x', '')
            arp_ip_list.append((name, val))
    return arp_ip_list


# Description:        Get information about the device.
# Returns:            List of values containing device info.
def get_device_info(ip, community):
    """
    Collect General information about the device.
    :param ip: IP Address
    :param community: Community String
    :return result: [syslocation, sysname, sysdescr, sysuptime, syscontact]
    """
    bulkget = [sysLocationOid,  # sysLocationOid
               sysNameOid,  # sysNameOid
               sysDescrOid,  # sysDescrOid (hex)
               sysUptimeOid,  # sysUptimeOid (timeticks, 1/100 sec)
               sysContactOid]  # sysContactOid

    bulkreturn = snmp_get_bulk_oid(ip, community, bulkget)
    syslocation, sysname, sysdescr, sysuptime, syscontact = bulkreturn

    if syslocation is None:
        syslocation = 'unknown'

    if syscontact is None:
        syscontact = 'unknown'

    if sysname is None:
        sysname = 'unknown'

    # Convert hex sysDescrOid to ASCII
    if sysdescr is None:
        sysdescr = 'unknown'

    if get_is_cisco(sysdescr):
        # TODO: this needs work to verify cisco....
        sysdescr = "".join([chr(int(sysdescr[x:x + 2], 16)) for x in range(2, len(sysdescr), 2)])

    seconds = int(sysuptime) / 100
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    sysuptime = '{days}:{hours}:{mins}:{secs}'.format(days=str(d), hours=str(h), mins=str(m), secs=str(s))

    result = [syslocation, sysname, sysdescr, sysuptime, syscontact]
    return result


# Description:        Get Cisco Serial number.
# Returns:            String containing serial number
def get_serial(ip, community):
    """
    Get Cisco physical serial Number .
    :param ip: IP Address
    :param community: SNMP Community string
    :return:
    """
    serial_nums = []
    chasis_result = snmp_walk_oid(ip, community, chassisSerialNumberStringOid)
    device_result = snmp_walk_oid(ip, community, entPhysicalSerialNumOid)
    # print chasis_result
    # print device_result
    if chasis_result:
        for X in chasis_result:
            # print X
            if X:
                x_oid, x_serial = X[0]
                # print x_serial
                if len(x_serial) == 11:
                    serial_nums.append(str(x_serial).strip())

    if device_result:
        for X in device_result:
            # print X
            if X:
                x_oid, x_serial = X[0]
                # print x_serial
                if len(x_serial) == 11:
                    serial_nums.append(str(x_serial).strip())

    for serialX in serial_nums:
        if len(serialX) < 10:
            serial_nums.remove(serialX)
    # print serial_nums
    return serial_nums


# Description:        Converts a Cisco serial number into the manufacture date (year and month).
# Returns:            A text string '1996 10'
def get_mfg_date(serial_nums):
    """
    Cisco serial to manufacture date, I'm sure this could be simplified.
    :param serial_nums:
    :return:
    """
    serialnum_mfgdate = {}
    date_stamp = 5052
    # print serial_nums
    for serial_num in serial_nums:
        # print serial_num
        ser_year = serial_num[3:5]
        ser_month = int(serial_num[5:7])
        base_year = 1996
        mfg_year = str(base_year + int(ser_year))
        if int(serial_num[3:7]) < date_stamp:
            mfg_month = '0'
            if ser_month in range(1, 6):
                mfg_month = '1'
            if ser_month in range(6, 10):
                mfg_month = '2'
            if ser_month in range(10, 15):
                mfg_month = '3'
            if ser_month in range(15, 19):
                mfg_month = '4'
            if ser_month in range(19, 23):
                mfg_month = '5'
            if ser_month in range(23, 28):
                mfg_month = '6'
            if ser_month in range(28, 32):
                mfg_month = '7'
            if ser_month in range(32, 36):
                mfg_month = '8'
            if ser_month in range(36, 41):
                mfg_month = '9'
            if ser_month in range(41, 45):
                mfg_month = '10'
            if ser_month in range(45, 49):
                mfg_month = '11'
            if ser_month in range(49, 53):
                mfg_month = '12'
            serialnum_mfgdate.clear()
            serialnum_mfgdate[serial_num] = '{year} {month}'.format(year=mfg_year, month=mfg_month)
    serialnum_mfgdate = serialnum_mfgdate.items()
    return serialnum_mfgdate


# Description:        Get and manipulate vlan information.
# Returns:            A list of vlans.
def get_vlans(ip, community):
    """
    :param ip: IP Address
    :param community: Community String
    :return filtered_vlans: Returns list of VLANS
    """
    filtered_vlans = []
    vlan_list = snmp_walk_oid(ip, community, vtpVlanStateOid)
    for vlan_obj in vlan_list:
        for vlans in vlan_obj:
            oid, vlan = vlans
            vlan = str(oid).split('.')[-1]
            if re.search(r'100[2345]', vlan):
                continue
            if vlan not in filtered_vlans:
                filtered_vlans.append(vlan)
    return filtered_vlans


# Description:        create a list of macs from each vlan(community index).
# Returns:            A dict of decimal mac to hex mac address
def get_vlan_macs(ip, community, vlans):
    """
    *** No longer in use. ***
    :param ip: IP Address
    :param community: Community String
    :param vlans: list of vlans
    :return macs: A dictionarry of Dec Mac(key) to Hex Mac(value)
    """
    macs = {}
    for vlan in vlans:
        results = snmp_walk_oid(ip, community + '@{vlan_index}'.format(vlan_index=vlan), dot1dTpFdbAddressOid)
        for result in results:
            if result:
                dec_mac, hex_mac = result[0]
                dec_mac = dec_mac.prettyPrint().replace(dot1dTpFdbAddressOid + '.', '')
                hex_mac = hex_mac.prettyPrint().replace('0x', '')
                macs[dec_mac] = hex_mac
    return macs


# Description:        Tertiary index of port to interface
# Returns:            A dict, index of interface to port ID.
def get_port_if_index(ip, community, vlans):
    """
    :param ip: IP Address
    :param community: Community String
    :param vlans: list of vlans
    :return port_index: A dictionarry of Interface Index(key) to Port ID(value)
    """
    port_index = {'0': '0'}
    for vlan in vlans:
        results = snmp_walk_oid(ip, community + '@{vlan_index}'.format(vlan_index=vlan), dot1dBasePortIfIndexOid)
        for result in results:
            if result[0]:
                iface, port_id = result[0]
                iface = '.'.join(x for x in str(iface).split('.')[-1:])
                port_id = port_id.prettyPrint()

                port_index[iface] = port_id
    return port_index


# Description:        Collect MAC, Port relationship.
# Returns:            A defaultdict of lists, port and list of macs
def get_iface_macs(ip, community, vlans):
    """
    :param ip: IP Address
    :param community: Community String
    :param vlans: list of vlans
    :return iface_dec_macs: A Defaultdict of Port Id(key) to list of Decimal Macs(value)
    """
    iface_dec_macs = defaultdict(list)
    for vlan in vlans:
        results = snmp_walk_oid(ip, community + '@{vlan_index}'.format(vlan_index=vlan), dot1dTpFdbPortOid)
        for result in results:
            if result[0]:
                dec_mac, port_id = result[0]
                dec_mac = '.'.join(x for x in str(dec_mac).split('.')[-6:])
                port_id = port_id.prettyPrint()
                iface_dec_macs[port_id].append(dec_mac)
    return iface_dec_macs


# Description:        Collect information about CDP (Cisco Discovery Protocol) neighbors
# Returns:            A list of lists of containing cdp_neighbor information.
# Todo: This needs work... Could be simplified. Use Bulkget to possibly reduce the request times
def get_neighbors(ip, community, ifname, trunks):
    """
    :param trunks:
    :param ip: IP Address
    :param community: Community String
    :param ifname:
    :return result:
    """
    result = []
    if trunks:
        for idx in trunks:
            # TODO: Build list and do Bulkget?...

            n_address = snmp_walk_oid(ip, community, cdpCacheAddressOid + '.{index}'.format(index=idx))
            # print n_address

            if n_address:
                tbl_idx = (str(n_address[0][0][0]).split('.'))[-2:]
                tbl_idx = '.'.join(i for i in tbl_idx)
                bulkget = [cdpCacheDeviceIdOid,
                           cdpCacheDevicePortOid,
                           cdpCachePlatformOid]
                for i in range(len(bulkget)):  # Building list
                    bulkget[i] = "{bulk}.{table_index}".format(bulk=bulkget[i],
                                                               table_index=tbl_idx)
                bulkreturn = snmp_get_bulk_oid(ip, community, bulkget)
                n_deviceid = bulkreturn[0]
                n_port = bulkreturn[1]
                n_platform = bulkreturn[2]

                n_address = n_address[0][0][1].pprint().replace('0x', '')
                n_address = re.findall('..', n_address)  # Slow?
                n_address = '.'.join(str(int(i, 16)) for i in n_address)  # Slow?

                if n_port:
                    p = re.compile(r'([A-Z].)[a-zA-Z]*(\d.*)')
                    x = re.findall(p, n_port)  # Slow?
                    ''' It appears that on rare instances these will be empty '''
                    try:
                        n_port = x[0][0] + x[0][1]
                    except IndexError:
                        pass

                neighbor = [ip, ifname[idx], n_address, n_deviceid, n_port, n_platform]
                result.append(neighbor)

            else:
                continue
    return result


# Description:        Get and manipulate port information.
# Returns:            A list of lists of containing port information.
def get_deviceports(ip, community, ifindex, datetime):
    """
    :param ip: IP Address
    :param community: Community String
    :param ifindex:
    :param datetime:
    :return:
    """
    result = []
    ifname_dict = {'0': 'MfPkt/0'}
    trunks = []
    if ifindex:
        for iface in ifindex:
            for name, idx in iface:
                bulkget = [ifNameOid + '.',
                           ifAdminStatusOid + '.',
                           ifOperStatusOid + '.',
                           ifAliasOid + '.',
                           ifSpeedOid + '.',
                           dot3StatsDuplexStatusOid + '.',
                           vlanTrunkPortDynamicStatusOid + '.',
                           vmVlanOid + '.',
                           ifInErrorsOid + '.',
                           ifOutErrorsOid + '.']

                for i in range(len(bulkget)):  # Bulding list
                    bulkget[i] = "{bulk}{index}".format(bulk=bulkget[i], index=idx)
                bulkreturn = snmp_get_bulk_oid(ip, community, bulkget)
                ifname = bulkreturn[0]

                ifadminstatus = bulkreturn[1]
                ifoperstatus = bulkreturn[2]
                ifalias = bulkreturn[3]
                ifspeed = bulkreturn[4]
                dot3statsduplexstatus = bulkreturn[5]

                is_trunk = bulkreturn[6]
                vlan = bulkreturn[7]

                val = '.'.join(idx.prettyPrint().split('.')[-1:])
                ifname_dict[val] = ifname

                if bulkreturn[8].isdigit():
                    ifinerror = bulkreturn[8]
                else:
                    ifinerror = None
                if bulkreturn[9].isdigit():
                    ifouterror = bulkreturn[9]
                else:
                    ifouterror = None

                # Skip 'Vlan' and 'Null' interfaces
                if re.search(r'(Vl.*)|(Nu.*)', str(ifname), re.IGNORECASE):
                    continue

                # If ifname is its full form, e.g. "TenGigabitEthernet 0/1",
                # truncate it to "Te0/1"
                if re.match(r'\w+\s.*$', str(ifname)):
                    # print 'regex name truncate hit: {name}'.format(name=ifname)
                    s = str(ifname)
                    ifname = s.split(' ', 1)[0][:2] + s.split(' ', 1)[1]

                # Interface operational status
                if ifadminstatus == '2':
                    ifstatus = 'shutdown'
                else:
                    if ifoperstatus == '1':
                        ifstatus = 'up'
                    elif ifoperstatus == '2':
                        ifstatus = 'down'
                    else:
                        ifstatus = ''

                # Last time seen (Unix time)
                if ifstatus == 'up':
                    seen = datetime
                else:
                    seen = False

                # Alias clean-up
                if str(ifalias) == '0x0000':
                    ifalias = ''

                # Interface speed and duplex
                if ifstatus == 'up':
                    ifspeed = int(ifspeed) / 1000000  # convert to Mbps
                    if dot3statsduplexstatus == '3':
                        dot3statsduplexstatus = 'full'
                    elif dot3statsduplexstatus == '2':
                        dot3statsduplexstatus = 'half'
                    else:
                        dot3statsduplexstatus = ''
                else:
                    ifspeed = ''
                    dot3statsduplexstatus = ''

                # Desired output format of "speed-duplex"
                if ifspeed and dot3statsduplexstatus:
                    speed_duplex = "{speed}-{status}".format(speed=ifspeed, status=dot3statsduplexstatus)
                else:
                    speed_duplex = ''

                # VLAN
                # This is Cisco specific but in this environment it is OK.
                if is_trunk == '1':
                    vlan = 'trunk'
                    trunks.append(val)
                else:
                    if vlan:
                        try:
                            vlan = int(vlan)
                        except ValueError:
                            vlan = ''
                    else:
                        vlan = ''

                iface = [ifname, ifstatus, seen, ifalias, vlan, speed_duplex, ifinerror, ifouterror]
                result.append(iface)
    return result, ifname_dict, trunks


# Description:        Returns True if the string contains cisco.
# Returns:            Boolean
def get_is_cisco(descr):
    """
    Returns True if the string descr contains "cisco".
    :param descr: Text string containing the system desctiption
    :return boolean:
    """
    if re.search(r'.*cisco.*', descr, re.IGNORECASE):
        return True
    else:
        return False


# Description:        Returns index of port ID to human name and associated MACS..
# Returns:            defaultdict list {'port0':['mac1', 'mac2'], 'port1':['mac3', 'mac4']}
def get_mac_port(port_macs: defaultdict, ifname, if_index):
    """
    :param port_macs: A Defaultdict of Cisco Port Id(key) to list of Decimal Macs(value)
    :param ifname:  A Dict where the key is a port id, value is friendly name {'10001': 'Fa0/1'}
    :param if_index: A dictionary of the Interface Index(key) to Port ID(value)
    :return port_mac_index: defaultdict list {'port0':['mac1', 'mac2'], 'port1':['mac3', 'mac4']}
    """
    port_mac_index = defaultdict(list)
    for k, v in port_macs.items():
        for dec_mac in v:
            dec_mac = dec_mac.split(".")
            hex_mac = ''.join(str(hex(int(i)).lstrip('0x')).zfill(2) for i in dec_mac).lower()
            try:
                port_mac_index[ifname[if_index[k]]].append(hex_mac)
            except KeyError:
                pass
    return port_mac_index


# Description:        NetDevice is a collection of information regarding ports, macs and IPs
# Returns:            NetDevice Object
# Todo: Create class runtype to do FULL or PART runs
class Device:
    """
    Create a Device class for storing elements of a network device regarding ports, macs and IPs.
    """
    def __init__(self, ip, community, run_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), dev_type='unknown'):
        """
        :param ip: IP Address
        :param community: Community String
        :param run_time: A time value used to group multiple devices in a session or "run."
        :param dev_type: Type of Device ['Wap', 'Switch', 'Router']
        :return Object: A Device Object
        """
        self.run = run_time
        self.ip = ip
        self.type = dev_type
        self.community = community
        self.datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.name = "unknown"
        try:
            self.alive = get_device_status(ip, community)
        except:
            raise NameError("This ip:{ip_addr} is dead Jim!".format(ip_addr=ip))
        if self.alive:
            self.syslocation, self.sysname, self.sysdescr, self.sysuptime, self.syscontact = \
                get_device_info(ip, community)
            self.ifindex = snmp_walk_oid(ip, community, ifIndexOid)
            self.deviceports, self.ifname, self.trunkports = get_deviceports(ip, community, self.ifindex, self.datetime)
            self.arp_table = get_arp_table(ip, community)
            self.vlans = get_vlans(ip, community)
            self.is_cisco = get_is_cisco(self.sysdescr)
            self.note = 0  # TODO: Why is this here?
            self.archive_date = 'NULL'
            if self.is_cisco:
                # WTF AM I DOING HERE?...
                self.serial_num = get_serial(ip, community)
                if self.serial_num:
                    self.serial_mfg_date = get_mfg_date(self.serial_num)
                    self.serial_num, self.mfg_date = self.serial_mfg_date[0]
            self.if_index = get_port_if_index(ip, community, self.vlans)
            self.port_macs = get_iface_macs(ip, community, self.vlans)
            self.port_mac_index = get_mac_port(self.port_macs, self.ifname, self.if_index)
            self.neighbors = get_neighbors(ip, community, self.ifname, self.trunkports)


if __name__ == '__main__':
    ip = input("enter ip: ")
    secret = input("Community string: ")
    scan_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    test_obj = Device(ip, secret, scan_time, 'Testing')
    print('\n'.join("%s: %s" % item for item in vars(test_obj).items()))
