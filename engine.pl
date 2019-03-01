request(Adapter, EthernetProtocolID, EthernetVID, IPType, SrcAddress, DstAddress, PortType, SrcPort, DstPort, ICMPType, ICMPProtocol, ICMPMessage) :-
			
			(atom_length(SrcAddress, SrcAddressLength), SrcAddressLength > 0; atom_length(DstAddress, DstAddressLength), DstAddressLength > 0),
			(atom_length(SrcPort, SrcPortLength), SrcPortLength > 0; atom_length(DstPort, DstPortLength), DstPortLength > 0),
			(atom_length(ICMPProtocol, ProtocolLength), ProtocolLength > 0; atom_number(ICMPMessage, MessageLength), MessageLength > 0),

			consult("rulebase.pl"),
			adapterClause(Adapter),
			ethernetClause(EthernetProtocolID, EthernetVID),

			(IPType == "ip", ICMPType == "icmp",
			  ipv4Clause(SrcAddress, DstAddress), 
			  icmpClause(ICMPProtocol, ICMPMessage) );

			(IPType == "ipv6", ipv6Clause(SrcAddress, DstAddress),
			 ICMPType == "icmpv6", icmpv6Clause(ICMPProtocol, ICMPMessage)),

			(PortType == "tcp", tcpClause(SrcPort, DstPort));
			(PortType == "udp", udpClause(SrcPort, DstPort)).


request(Adapter, EthernetProtocolID, IPType, SrcAddress, DstAddress, PortType, SrcPort, DstPort, ICMPType, ICMPProtocol, ICMPMessage) :-
			
			(atom_length(SrcAddress, SrcAddressLength), SrcAddressLength > 0; atom_length(DstAddress, DstAddressLength), DstAddressLength > 0),
			(atom_length(SrcPort, SrcPortLength), SrcPortLength > 0; atom_length(DstPort, DstPortLength), DstPortLength > 0),
			(atom_length(ICMPProtocol, ProtocolLength), ProtocolLength > 0; atom_number(ICMPMessage, MessageLength), MessageLength > 0),

			consult("rulebase.pl"),
			adapterClause(Adapter),
			ethernetClause(EthernetProtocolID),

			(IPType == "ip", ICMPType == "icmp",
			 ipv4Clause(SrcAddress, DstAddress),
			 ICMPType == "icmp", icmpClause(ICMPProtocol, ICMPMessage) );

			(IPType == "ipv6", ipv6Clause(SrcAddress, DstAddress),
			 ICMPType == "icmpv6", icmpv6Clause(ICMPProtocol, ICMPMessage)),

			(PortType == "tcp", tcpClause(SrcPort, DstPort));
			(PortType == "udp", udpClause(SrcPort, DstPort)).

request(Adapter, EthernetVID, IPType, SrcAddress, DstAddress, PortType, SrcPort, DstPort, ICMPType, ICMPProtocol, ICMPMessage) :-
			
			(atom_length(SrcAddress, SrcAddressLength), SrcAddressLength > 0; atom_length(DstAddress, DstAddressLength), DstAddressLength > 0),
			(atom_length(SrcPort, SrcPortLength), SrcPortLength > 0; atom_length(DstPort, DstPortLength), DstPortLength > 0),
			(atom_length(ICMPProtocol, ProtocolLength), ProtocolLength > 0; atom_number(ICMPMessage, MessageLength), MessageLength > 0),
			
			consult("rulebase.pl"),
			adapterClause(Adapter),
			ethernetClause(EthernetVID),

			(IPType == "ip", ICMPType == "icmp",
			  ipv4Clause(SrcAddress, DstAddress),
			  icmpClause(ICMPProtocol, ICMPMessage) );

			(IPType == "ipv6", ipv6Clause(SrcAddress, DstAddress),
			 ICMPType == "icmpv6", icmpv6Clause(ICMPProtocol, ICMPMessage)),

			(PortType == "tcp", tcpClause(SrcPort, DstPort));
			(PortType == "udp", udpClause(SrcPort, DstPort)).


