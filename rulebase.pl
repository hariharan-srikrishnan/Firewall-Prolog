/* Adapter Clause */

range(X, LowerBound, UpperBound) :-
		(X >= LowerBound),
		X < UpperBound.

adapterClause(Adapter) :- checkAdapter(Adapter).%adapterChar(Adapter).

adapterChar("A").
adapterChar("B").
adapterChar("C").
adapterChar("D").
adapterChar("E").
adapterChar("F").
adapterChar("G").
adapterChar("H").
adapterChar("any").

checkAdapter(Adapter) :-
		adapterChar(Adapter),
		consult('database.pl'),
		findall(X, reject("adapter", X), ListOfBlockedAdapters),
		findall(Y, drop("adapter", Y), ListOfDroppedAdapters),
		checkRejectedAdapter(Adapter, ListOfBlockedAdapters),
		checkDroppedAdapter(Adapter, ListOfDroppedAdapters).

checkAdapter().

checkRejectedAdapter(Value, [Head | Tail]) :-
		(Value == Head, write("Packet Rejected!"), nl);
		checkRejectedAdapter(Value, Tail).

checkRejectedAdapter(_, []).

checkDroppedAdapter(Value, [Head | Tail]) :-
		(Value == Head, write("Packet Dropped!"), nl);
		checkDroppedAdapter(Value, Tail).		

checkDroppedAdapter(_, []).

/* Ethernet Clause */

num(1).
num(X) :-
		Y is X-1,
		(Y >= 1),
		num(Y).


ethernetClause(ProtocolID, VID) :- 
		ethernetProtocol(ProtocolID),
		ethernetID(VID).

ethernetClause(VID) :-
		ethernetID(VID).

ethernetClause(ProtocolID) :-
		ethernetProtocol(ProtocolID).

ethernetProtocol("arp").
ethernetProtocol("aarp").
ethernetProtocol("atalk").
ethernetProtocol("ipx").
ethernetProtocol("mpls").
ethernetProtocol("netbui").
ethernetProtocol("pppoe").
ethernetProtocol("rarp").
ethernetProtocol("sna").
ethernetProtocol("xns").

ethernetID(VID) :-
		(atom_number(VID, Value), num(Value));

		% for handling ranges
		split_string(VID, ",", "", List),
		listOfIDs(List).

listOfIDs([Head | Tail]) :- 
		atom_number(Head, Value), 
		num(Value), 
		range(Value, 0, 256),
		listOfIDs(Tail).

listOfIDs([]).

/* IPv4 Clause */

ipv4Clause(SrcAddress, DstAddress) :-
		validIPv4(SrcAddress),
		validIPv4(DstAddress),
		consult('database.pl'),
		findall(X, reject("ip", "src", X), ListOfBlockedSourceIPs),
		findall(Y, reject("ip", "dst", Y), ListOfBlockedDestinationIPs),
		findall(W, drop("ip", "src", W), ListOfDroppedSourceIPs),
		findall(Z, drop("ip", "dst", Z),ListOfDroppedDestinationIPs),
		checkIfBlockedSourceIP(SrcAddress, ListOfBlockedSourceIPs),
		checkIfBlockedDestinationIP(DstAddress, ListOfBlockedDestinationIPs),
		checkIfDroppedSourceIP(SrcAddress, ListOfDroppedSourceIPs),
		checkIfDroppedDestinationIP(DstAddress, ListOfDroppedDestinationIPs).


checkIfBlockedSourceIP(Address, [Head | Tail]) :-
		(Address == Head, write("Packet Rejected!"), nl);
		(checkIfBlockedSourceIP(Address, Tail)).

checkIfBlockedSourceIP(_ , []).

checkIfBlockedDestinationIP(Address, [Head | Tail]) :-
		(Address == Head, write("Packet Rejected!"), nl);
		(checkIfBlockedDestinationIP(Address, Tail)).

checkIfBlockedDestinationIP(_ , []).


checkIfDroppedSourceIP(Address, [Head|Tail]) :-
		(Address == Head, write("Packet Dropped!"), nl);
		(checkIfDroppedSourceIP(Address, Tail)).

checkIfDroppedSourceIP(_ , []).

checkIfDroppedDestinationIP(Address, [Head | Tail]) :-
		(Address == Head, write("Packet Dropped!"), nl);
		(checkIfDroppedDestinationIP(Address, Tail)).

checkIfDroppedDestinationIP(_ , []).


validIPv4(Address) :-
		split_string(Address, ".", "", List),
		list_length(List, 4),
		inRange(List).

validIPv4("").

validIPv4Protocol(ProtocolType) :-
		atom_number(ProtocolType, Value),
		range(Value, 0, 256).

inRange([X|Y]) :- 
		atom_number(X, Z),
		range(Z, 0, 256),
		inRange(Y).

inRange([Y]) :-
		atom_number(Y, Z),
		range(Z, 0, 256).

list_length(Xs, Length) :- list_length(Xs, 0, Length).

list_length([], Length, Length).
list_length([_ | Xs], T, Length) :-
	  	T1 is T+1 ,
	  	list_length(Xs, T1, Length).


/* IPv6 Clauses */

ipv6Clause(SrcAddress, DstAddress) :-
		validIPv6(SrcAddress),
		validIPv6(DstAddress),
		consult('database.pl'),
		findall(X, reject("ipv6", "src", X), ListOfBlockedSourceIPs),
		findall(Y, reject("ipv6", "dst", Y), ListOfBlockedDestinationIPs),
		findall(W, drop("ipv6", "src", W), ListOfDroppedSourceIPs),
		findall(Z, drop("ipv6", "dst",Z), ListOfDroppedDestinationIPs),
		checkIfBlockedSourceIPv6(SrcAddress, ListOfBlockedSourceIPs),
		checkIfBlockedDestinationIPv6(DstAddress, ListOfBlockedDestinationIPs),
		checkIfDroppedSourceIPv6(SrcAddress, ListOfDroppedSourceIPs),
		checkIfDroppedDestinationIPv6(DstAddress, ListOfDroppedDestinationIPs).


validIPv6(Address) :-
		split_string(Address, ":", "", SubValues),
		list_length(SubValues, 8),
		SubValues = [Value1, Value2, Value3, Value4, Value5, Value6, Value7, Value8],
		checkValidHexLength(Value1),
		checkValidHexLength(Value2),
		checkValidHexLength(Value3),
		checkValidHexLength(Value4),
		checkValidHexLength(Value5),
		checkValidHexLength(Value6),
		checkValidHexLength(Value7),
		checkValidHexLength(Value8).

validIPv6("").

checkIfBlockedSourceIPv6(Address, [Head | Tail]) :-
		(Address == Head, write("Packet Rejected!"), nl);
		(checkIfBlockedSourceIPv6(Address, Tail)).

checkIfBlockedSourceIPv6(_ , []).

checkIfBlockedDestinationIPv6(Address, [Head | Tail]) :-
		(Address == Head, write("Packet Rejected!"), nl);
		(checkIfBlockedDestinationIPv6(Address, Tail)).

checkIfBlockedDestinationIPv6(_ , []).


checkIfDroppedSourceIPv6(Address, [Head | Tail]) :-
		(Address == Head, write("Packet Dropped!"), nl);
		(checkIfDroppedSourceIPv6(Address, Tail)).

checkIfDroppedSourceIPv6(_ , []).

checkIfDroppedDestinationIPv6(Address, [Head | Tail]) :-
		(Address == Head, write("Packet Dropped!"), nl);
		(checkIfDroppedDestinationIPv6(Address, Tail)).

checkIfDroppedDestinationIPv6(_ , []).


checkValidHex(Value) :-
		atom_string(Value, StrVal),
		( (StrVal >= 48, StrVal =< 57); (StrVal >= 65, StrVal =< 70)).

checkValidHexLength(Number) :-
		string_chars(Number, Digits),
		list_length(Digits, L),
		(L =< 4, L >= 1),
		checkValidHexNumber(Digits).

checkValidHexNumber([FirstDigit | Rest]) :-
		checkValidHex(FirstDigit),
		checkValidHexNumber(Rest).

checkValidHexNumber([]).

/* TCP and UDP clauses */

tcpClause(SrcPort, DstPort) :-
		validTCPPort(SrcPort),
		validTCPPort(DstPort),
		checkTCPPort(SrcPort, DstPort).

validTCPPort(Port) :-
		(atom_number(Port, Value), range(Value, 0, 65536));

		split_string(Port, ",", "", List),
		listOfPorts(List).

validTCPPort("").

checkTCPPort(SrcPort, DstPort) :-
		consult('database.pl'),
		findall(DstPorts, reject("tcp", "dst", "port", DstPorts, _, _, _), BlockedTCPDstPorts), 
		findall(SrcPorts, reject("tcp", _, _, _, "src", "port", SrcPorts), BlockedTCPSrcPorts), 
		checkRejectedTCPPorts(DstPort, BlockedTCPSrcPorts), 
		checkRejectedTCPPorts(SrcPort, BlockedTCPDstPorts),

		findall(DstPorts, drop("tcp", "dst", "port", DstPorts, _, _, _), DroppedTCPDstPorts), 
		findall(SrcPorts, drop("tcp", _, _, _, "src", "port", SrcPorts), DroppedTCPSrcPorts), 
		checkDroppedTCPPorts(DstPort, DroppedTCPSrcPorts),
		checkDroppedTCPPorts(SrcPort, DroppedTCPDstPorts).

checkRejectedTCPPorts(Port, [Head | Tail]) :-
		(Head == Port, write("Packet Rejected!"), nl);
		checkRejectedTCPPorts(Port, Tail).

checkRejectedTCPPorts(_, []).

checkDroppedTCPPorts(Port, [Head | Tail]) :-
		(Head == Port, write("Packet Dropped!"), nl);
		checkDroppedTCPPorts(Port, Tail).

checkDroppedTCPPorts(_, []).

udpClause(SrcPort, DstPort) :-
		validUDPPort(SrcPort),
		validUDPPort(DstPort),
		checkUDPPort(SrcPort, DstPort).

validUDPPort(Port) :-
		(atom_number(Port, Value), range(Value, 0, 65536));

		split_string(Port, ",", "", List),
		listOfPorts(List).

validUDPPort("").

checkUDPPort(SrcPort, DstPort) :-	
		consult('database.pl'),
		findall(DstPorts, reject("udp", "dst", "port", DstPorts, _, _, _), BlockedUDPDstPorts), 
		findall(SrcPorts, reject("udp", _, _, _, "src", "port", SrcPorts), BlockedUDPSrcPorts), 
		checkRejectedUDPPorts(DstPort, BlockedUDPSrcPorts), 
		checkRejectedUDPPorts(SrcPort, BlockedUDPDstPorts),

		findall(DstPorts, drop("tcp", "dst", "port", DstPorts, _, _, _), DroppedUDPDstPorts), 
		findall(SrcPorts, drop("tcp", _, _, _, "src", "port", SrcPorts), DroppedUDPSrcPorts), 
		checkDroppedUDPPorts(DstPort, DroppedUDPSrcPorts),
		checkDroppedUDPPorts(SrcPort, DroppedUDPDstPorts).

checkRejectedUDPPorts(Port, [Head | Tail]) :-
		(Head == Port, write("Packet Rejected!"), nl);
		checkRejectedTCPPorts(Port, Tail).

checkRejectedUDPPorts(_, []).
		
checkDroppedUDPPorts(Port, [Head | Tail]) :-
		(Head == Port, write("Packet Dropped!"), nl);
		checkDroppedTCPPorts(Port, Tail).

checkDroppedUDPPorts(_, []).

listOfPorts([Head | Tail]) :- 
		atom_number(Head, Value), 
		num(Value), 
		%% checkTCPPort(Head),
		range(Value, 0, 65536),
		listOfPorts(Tail).

listOfPorts([]).

/* ICMP clauses */

icmpClause(ProtocolType, MessageCode) :-
		validICMPProtocol(ProtocolType),
		validICMPMessage(MessageCode),
		consult('database.pl'),
		findall(X, reject("icmp", "type", X), ListOfBlockedProtocols),
		findall(Y, reject("icmp", "code", Y), ListOfBlockedMessageCodes),
		findall(W, drop("icmp", "type", W), ListOfDroppedProtocols),
		findall(Z, drop("icmp", "code", Z), ListOfDroppedMessageCodes),
		checkIfBlockedProtocolType(ProtocolType, ListOfBlockedProtocols),
		checkIfBlockedMessageCode(MessageCode, ListOfBlockedMessageCodes),
		checkIfDroppedProtocolType(ProtocolType, ListOfDroppedProtocols),
		checkIfDroppedMessageCode(MessageCode, ListOfDroppedMessageCodes).

checkIfBlockedProtocolType(ProtocolType, [Head | Tail]) :-
		(ProtocolType == Head, write("Packet Rejected!"), nl);
		checkIfBlockedProtocolType(ProtocolType, Tail).

checkIfBlockedProtocolType(_, []).

checkIfBlockedMessageCode(MessageCode, [Head | Tail]) :-
		(MessageCode == Head, write("Packet Rejected!"), nl);
		checkIfBlockedMessageCode(MessageCode, Tail).

checkIfBlockedMessageCode(_, []).


checkIfDroppedProtocolType(ProtocolType, [Head | Tail]) :-
		(ProtocolType == Head, write("Packet Dropped!"), nl);
		checkIfDroppedProtocolType(ProtocolType, Tail).

checkIfDroppedProtocolType(_, []).

checkIfDroppedMessageCode(MessageCode, [Head | Tail]) :-
		(MessageCode == Head, write("Packet Dropped!"), nl);
		checkIfDroppedMessageCode(MessageCode, Tail).

checkIfDroppedMessageCode(_, []).


validICMPProtocol(ProtocolType) :-
		(atom_number(ProtocolType, Value), range(Value, 0, 256));

		split_string(ProtocolType, ",", "", List),
		listOfIDs(List).

validICMPProtocol("").

validICMPMessage(MessageCode) :- 
		(atom_number(MessageCode, Value), range(Value, 0, 256));

		split_string(MessageCode, ",", "", List),
		listOfIDs(List).

validICMPMessage("").

/* ICMPv6 clauses */

icmpv6Clause(ProtocolType, MessageCode) :-	
		validICMPv6Protocol(ProtocolType),
		validICMPv6Message(MessageCode),
		consult('database.pl'),
		findall(X, reject("icmpv6", "type", X), ListOfBlockedProtocols),
		findall(Y, reject("icmpv6", "code", Y), ListOfBlockedMessageCodes),
		findall(W, drop("icmpv6", "type", W), ListOfDroppedProtocols),
		findall(Z, drop("icmpv6", "code", Z), ListOfDroppedMessageCodes),
		checkIfBlockedProtocolTypev6(ProtocolType, ListOfBlockedProtocols),
		checkIfBlockedMessageCodev6(MessageCode, ListOfBlockedMessageCodes),
		checkIfDroppedProtocolTypev6(ProtocolType, ListOfDroppedProtocols),
		checkIfDroppedMessageCodev6(MessageCode, ListOfDroppedMessageCodes).


validICMPv6Protocol(ProtocolType) :-
		(atom_number(ProtocolType, Value), range(Value, 0, 256));

		split_string(ProtocolType, ",", "", List),
		listOfIDs(List).

validICMPv6Protocol("").

validICMPv6Message(MessageCode) :- 
		(atom_number(MessageCode, Value), range(Value, 0, 256));

		split_string(MessageCode, ",", "", List),
		listOfIDs(List).

validICMPv6Message("").

checkIfBlockedProtocolTypev6(ProtocolType, [Head | Tail]) :-
		(ProtocolType == Head, write("Packet Rejected!"), nl);
		checkIfBlockedProtocolTypev6(ProtocolType, Tail).

checkIfBlockedProtocolTypev6(_, []).

checkIfBlockedMessageCodev6(MessageCode, [Head | Tail]) :-
		(MessageCode == Head, write("Packet Rejected!"), nl);
		checkIfBlockedMessageCodev6(MessageCode, Tail).

checkIfBlockedMessageCodev6(_, []).


checkIfDroppedProtocolTypev6(ProtocolType, [Head | Tail]) :-
		(ProtocolType == Head, write("Packet Dropped!"), nl);
		checkIfDroppedProtocolTypev6(ProtocolType, Tail).

checkIfDroppedProtocolTypev6(_, []).

checkIfDroppedMessageCodev6(MessageCode, [Head | Tail]) :-
		(MessageCode == Head, write("Packet Dropped!"), nl);
		checkIfDroppedMessageCodev6(MessageCode, Tail).

checkIfDroppedMessageCodev6(_, []).