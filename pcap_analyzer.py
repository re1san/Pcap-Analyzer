from scapy.all import *

def processor(packets):
    main_dict = {}
    sub_dict = {}
    sub_dict["ethernet"] = [["Packet number","Source MAC address","Destination MAC address","Network layer protocol"]]
    sub_dict["STP"] = [["Packet number","root id", "bridge id", "port id", "max age", "hello time"]]
    sub_dict["ieee 802.11"] = [["Packet number", "Source MAC", "Destination MAC", "BSSID", "Transmitter MAC", "type", "subtype"]]
    list_arp = [["Packet number","data-link layer protocol","Network layer protocol","Sender hardware address","Receiver hardware address","Sender protocol address","Receiver protocol address","ARP type"]]
    sub_net_dict = {}
    sub_net_dict["ipv4"] = [["Packet number","Source IP address", "Destination IP address","protocol"]]
    sub_net_dict["ipv6"] = [["Packet number","Source IP address", "Destination IP address","protocol"]]
    list_icmp = [["Packet number","network layer protocol","Source IP address", "Destination IP address","messsage"]]
    sub_trans_dict = {}
    sub_trans_dict["tcp"] = [["Packet number","network layer protocol","Source IP address", "Destination IP address","Source IP port", "Destination IP port","protocol"]]
    sub_trans_dict["udp"] = [["Packet number","network layer protocol","Source IP address", "Destination IP address","Source IP port", "Destination IP port","protocol"]]
    list_dns = [["Packet number","Source IP address", "Destination IP address","Query","Query type","Answer"]]
    system_port = {}
    reserved_port = {}
    for i in range(1,len(packets)+1):
        packet = packets[i-1]
        if Ether in packet:
            src_mac = packet[Ether].src
            dest_mac = packet[Ether].dst
            ether_type = packet[Ether].type
            if ether_type == 0x0800:
                ether_type_name = "ipv4"
            elif ether_type == 0x0806:
                ether_type_name = "arp"
            elif ether_type == 0x86DD:
                ether_type_name = "ipv6"
            else:
                ether_type_name = "unknown"
            sub_list = [i,src_mac,dest_mac,ether_type_name]
            sub_dict["ethernet"].append(sub_list)
        elif STP in packet:
            packet_stp = packet[STP]
            sub_list = [i, packet_stp.rootid, packet_stp.bridgeid, packet_stp.portid, packet_stp.maxage, packet_stp.hellotime]
            sub_dict["STP"].append(sub_list)
        elif Dot11 in packet:
            src_mac = packet.addr2
            dest_mac = packet.addr1
            bssid = packet.addr3
            transmitter_mac = packet.addr4
            subtype1_name = {
                0x00: 'Association Request',
                0x01: 'Association Response',
                0x02: 'Reassociation Request',
                0x03: 'Reassociation Response',
                0x04: 'Probe Request',
                0x05: 'Probe Response',
                0x08: 'Beacon',
                0x09: 'ATIM',
                0x0A: 'Disassociation',
                0x0B: 'Authentication',
                0x0C: 'Deauthentication',}
            subtype2_name = {
                0x08: 'Block Ack Request',
                0x09: 'Block Ack',
                0x0A: 'PS-Poll',
                0x0B: 'RTS',
                0x0C: 'CTS',
                0x0D: 'ACK'}
            subtype3_name = {
                0x08: 'QOS Data',
                0x09: 'QOS Data + CF-ACK',
                0x0A: 'QOS Data + CF-Poll',
                0x0B: 'QOS Data + CF-ACK + CF-Poll',
                0x0C: 'QOS Null Function (no data)'}
            wifi_subtype = packet.subtype
            wifi_type = packet.type
            type_name = ""
            subtype_name = ""
            if wifi_type == 0:
                type_name = "Management Frame"
                subtype_name = subtype1_name.get(wifi_subtype,'Unknown') + " Frame"
            elif wifi_type == 1:
                type_name = "Control Frame"
                subtype_name = subtype2_name.get(wifi_subtype,"Unknown") + " Frame"
            elif wifi_type == 2:
                type_name = "Data Frame"
                subtype_name = subtype3_name.get(wifi_subtype,"Unknown") + " Frame"
            else:
                type_name == "Unknown Frame"
                subtype_name = "Unknown"
            sub_list = [i, src_mac, dest_mac, bssid, transmitter_mac, type_name, subtype_name]
            sub_dict["ieee 802.11"].append(sub_list)
        if ARP in packet:
            list_arp.append(pack_arp(i,packet))
        else:
            network_layer_name, network_layer_list = pack_network_layer(i,packet)
            if len(network_layer_list) != 0:
                sub_net_dict[network_layer_name].append(network_layer_list)
                if ICMP in packet:
                    list_icmp.append(pack_icmp(i,network_layer_name,network_layer_list[1],network_layer_list[2],packet))
                else:
                    transport_layer_name, transport_layer_list = pack_transport_layer(i,network_layer_name,network_layer_list[1],network_layer_list[2],packet)
                    if len(transport_layer_list) != 0:
                        sub_trans_dict[transport_layer_name].append(transport_layer_list)
                        source_port = packet.sport
                        destination_port = packet.dport
                        if source_port < 1024:
                            if source_port in system_port:
                                system_port[source_port] += 1
                            else:
                                system_port[source_port] = 0
                        if destination_port < 1024 and destination_port != source_port:
                            if destination_port in system_port:
                                system_port[destination_port] += 1
                            else:
                                system_port[destination_port] = 0
                        if source_port >= 1024 and source_port < 49151:
                            if source_port in reserved_port:
                                reserved_port[source_port] += 1
                            else:
                                reserved_port[source_port] = 0
                        if destination_port >= 1024 and destination_port < 49151 and destination_port != source_port:
                            if destination_port in reserved_port:
                                reserved_port[destination_port] += 1
                            else:
                                reserved_port[destination_port] = 0
                        if packet.sport == 53 or packet.dport == 53:
                            list_dns.append(pack_dns(i,network_layer_list[1],network_layer_list[2],packet))
    main_dict["datalink_layer"] = sub_dict
    main_dict["arp"] = list_arp
    main_dict["network_layer"] = sub_net_dict
    main_dict["icmp"] = list_icmp
    main_dict["transport_layer"] = sub_trans_dict
    main_dict["dns"] = list_dns
    return main_dict, system_port, reserved_port

def pack_arp(i,packet):
    arp = packet[ARP]
    sender_mac = arp.hwsrc
    receiver_mac = arp.hwdst
    sender_ip = arp.psrc
    receiver_ip = arp.pdst
    if arp.op == 1:
        if sender_ip == receiver_ip:
            arp_type = "Gratuitous ARP Request"
        else:
            arp_type = "ARP Request"
    elif arp.op == 2:
        if sender_ip == receiver_ip:
            arp_type = "Gratuitous ARP Reply"
        else:
            arp_type = "ARP Reply"
    else:
        arp_type = "Unknown"
    arp_hardware_types_set = {
        1: "Ethernet",
        15: "Frame Relay",
        16: "Asynchronous Transfer Mode (ATM)",
        17: "HDLC",
        18: "Fibre Channel",
    }
    arp_protocol_types_set = {
        0x0800: "IPv4",
        0X86DD: "IPv6",
        0x8847: "Multiprotocol Label Switching"
    }
    arp_hardware_type = arp_hardware_types_set.get(arp.hwtype,"Unknown")
    arp_protocol_type = arp_protocol_types_set.get(arp.ptype,"Unknown")
    sub_list = [i,arp_hardware_type,arp_protocol_type,sender_mac,receiver_mac,sender_ip,receiver_ip,arp_type]
    return sub_list

def pack_network_layer(i,packet):
    if IP in packet:
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        transport_protocol_number = packet[IP].proto
        if transport_protocol_number == 1:
            transport_protocol = "ICMP"
        elif transport_protocol_number == 2:
            transport_protocol = "IGMP"
        elif transport_protocol_number == 6:
            transport_protocol = "TCP"
        elif transport_protocol_number == 17:
            transport_protocol = "UDP"
        else:
            transport_protocol = "Unknown" 
        sub_list = [i, src_ip, dest_ip, transport_protocol]
        return "ipv4", sub_list
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dest_ip = packet[IPv6].dst
        transport_protocol_number = packet[IPv6].nh
        if transport_protocol_number == 1:
            transport_protocol = "ICMP"
        elif transport_protocol_number == 2:
            transport_protocol = "IGMP"
        elif transport_protocol_number == 6:
            transport_protocol = "TCP"
        elif transport_protocol_number == 17:
            transport_protocol = "UDP"
        else:
            transport_protocol = "Unknown"
        sub_list = [i, src_ip, dest_ip, transport_protocol]
        return "ipv6", sub_list
    else:
        return "Unknown", []

def pack_icmp(i,net_name,ip_src,ip_dest,packet):
    msg = ""
    icmp_type = packet[ICMP].type
    icmp_code = packet[ICMP].code
    if icmp_type == 0:
        msg += "Echo reply "
    elif icmp_type == 3:
        msg += "Destination unreachable "
        if icmp_code == 0:
            msg += "Net is unreachable"
        elif icmp_code == 1:
            msg += "Host is unreachable"
        elif icmp_code == 2:
            msg += "Protocol is unreachable"
        elif icmp_code == 3:
            msg += "Port is unreachable"
        elif icmp_code == 4:
            msg += "Fragmentation is needed and Don't Fragment was set"
        elif icmp_code == 5:
            msg += "Source route failed"
        elif icmp_code == 6:
            msg += "Destination network is unknown"
        elif icmp_code == 7:
            msg += "Destination host is unknown"
        elif icmp_code == 8:
            msg += "Source host is isolated"
        elif icmp_code == 9:
            msg += "Communication with destination network is administratively prohibited"
        elif icmp_code == 10:
            msg += "Communication with destination host is administratively prohibited"
        elif icmp_code == 11:
            msg += "Destination network is unreachable for type of service"
        elif icmp_code == 12:
            msg += "Destination host is unreachable for type of service"
        elif icmp_code == 13:
            msg += "Communication is administratively prohibited"
        elif icmp_code == 14:
            msg += "Host precedence violation"
        elif icmp_code == 15:
            msg += "Precedence cutoff is in effect"
    elif icmp_type == 4:
        msg += "Source quench"
    elif icmp_type == 5:
        msg += "Redirect "
        if icmp_code == 0:
            msg += "Redirect datagram for the network (or subnet)"
        elif icmp_code == 1:
            msg += "Redirect datagram for the host"
        elif icmp_code == 2:
            msg += "Redirect datagram for the type of service and network"
        elif icmp_code == 2:
            msg += "Redirect datagram for the type of service and host"
    elif icmp_type == 8:
        msg += "Echo request"
    elif icmp_type == 9:
        msg += "Router advertisement"
    elif icmp_type == 10:
        msg += "Router selection"
    elif icmp_type == 11:
        msg += "Time exceeded "
        if icmp_code == 0:
            msg += "Time to Live exceeded in transit"
        elif icmp_code == 1:
            msg += "Fragment reassembly time exceeded"
    elif icmp_type == 12:
        msg += "Parameter problem "
        if icmp_code == 0:
            msg += "Pointer indicates the error"
        elif icmp_code == 1:
            msg += "Missing a required option"
        elif icmp_code == 2:
            msg += "Bad length"
    elif icmp_type == 13:
        msg += "Timestamp"
    elif icmp_type == 14:
        msg += "Timestamp Reply"
    elif icmp_type == 15:
        msg += "Information request"
    elif icmp_type == 16:
        msg += "Information reply"
    elif icmp_type == 17:
        msg += "Address mask request"
    elif icmp_type == 18:
        msg += "Address mask reply"
    temp_list = [i,net_name,ip_src,ip_dest,msg]
    return temp_list

def pack_transport_layer(i,net_name,ip_src,ip_dest,packet):
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        msg = display_tcp_port(src_port,dst_port)
        t_list = [i,net_name,ip_src,ip_dest,src_port, dst_port, msg]
        return "tcp", t_list
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        msg = display_udp_port(src_port,dst_port)
        t_list = [i,net_name,ip_src,ip_dest,src_port, dst_port, msg]
        return "udp", t_list
    else:
        return "Unknown", []

def display_tcp_port(src,dest):
    msg = ""
    if src == 7 or dest == 7:
        msg += "TCP Echo"
    if src == 53 or dest == 53:
        msg += "Application layer: DNS"
    if src == 20 or dest == 20:
        msg += "FTP data connection"
    if src == 21 or dest == 21:
        msg += "FTP control connection"
    if src == 23 or dest == 23:
        msg += "Telnet"
    if src == 25 or dest == 25:
        msg += "SMTP"
    if src == 80 or dest == 80:
        msg += "HTTP"
    if src == 443 or dest == 443:
        msg += "HTTPS"
    if src == 993 or dest == 993:
        msg += "Internet Message Access Protocol"
    if src == 995 or dest == 995:
        msg += "Post Office Protocol 3"
    return msg

def display_udp_port(src,dest):
    msg = ""
    if src == 7 or dest == 7:
        msg += "UDP Echo"
    if src == 53 or dest == 53:
        msg += "DNS"
    if src == 67 or dest == 67:
        msg += "DHCP server"
    if src == 68 or dest == 68:
        msg += "DHCP client"
    if src == 161 or dest == 161:
        msg += "SNMP query"
    if src == 162 or dest == 162:
        msg += "SNMP trap"
    if src == 514 or dest == 514:
        msg += "Syslog"
    if src == 500 or dest == 500 or src == 4500 or dest == 4500:
        msg += "IPsec VPN tunnel"
    if src == 69 or dest == 69:
        msg += "Trivial File Transfer Protocol"
    if src == 443 or dest == 443:
        msg += "HTTPS"
    if src == 5353 or dest == 5353:
        msg += "MDNS"
    if src == 546 or dest == 546:
        msg += "DHCPv6 client"
    if src == 547 or dest == 547:
        msg += "DHCPv6 server"
    if (src >= 137 and src <= 139) or (dest >= 137 and dest <= 139):
        msg += "NetBIOS name service"
    if src == 1900 or dest == 1900:
        msg += "Simple service discovery protocol"
    if src == 47808 or dest == 47808:
        msg += "BACnet protocol"
    if src == 5355 or dest == 5355:
        msg += "Link-Local Multicast Name Resolution"
    return msg

def pack_dns(i,ip_src,ip_dest,packet):
    dns_query = packet[DNS].qd.qname.decode()
    if packet[DNS].qr == 0:
        dns_query_name = "Query Request"
    elif packet[DNS].qr == 1:
        dns_query_name = "Query Response"
    else:
        dns_query_name = "Unknown"
    dns_answer = []
    if packet[DNS].an:
        for answer in packet[DNS].an:
            dns_answer.append(answer.rdata)
    dns_list = [i,ip_src,ip_dest,dns_query,dns_query_name,dns_answer]
    return dns_list