% Grammar

% Helper functions
range(X, L, H) :-
		%% atom_number(X, Y),
		(X >= L),
		X < H.

% to handle (int) a-b in range L-H
range(X, L, H) :- 
		X =.. Y,
		Y = [-, P|Q],
		(Q > P),
		range(P, L, H),
		range(Q, L, H). 

% for handling ips
inRange([X|Y]) :- 
		atom_number(X, Z),
		range(Z, 0, 256),
		inRange(Y).

inRange([Y]) :-
		atom_number(Y, Z),
		range(Z, 0, 256).

list_length(Xs,L) :- list_length(Xs,0,L).

list_length([], L, L).
list_length([_|Xs], T, L) :-
	  	T1 is T+1 ,
	  	list_length(Xs,T1,L).

/* Adapter Clauses */
aClause([adapter, X]) :- aChar(X).

aChar(any).
aChar(a).
aChar(b).
aChar(c).
aChar(d).
aChar(e).
aChar(f).
aChar(g).
aChar(h).


/* IPV4 clauses */

% Parse out 'ip'
ipClause([ip|X]) :- ipClause1(X).

% if no clause specified
ipClause1([]).

% to handle addr and proto clause
ipClause1([addr|X]) :- ipv4_addr(X).
ipClause1([proto|X]) :- proto_ipv4(X).

% to handle dst chained commands
ipClause1([dst, addr|X]) :- ipClauseDst(X).

ipClauseDst([X|Y]) :- 
		ipv4_addr(X),
		ipClauseDst2(Y).

ipClauseDst2([proto|X]) :- proto_ipv4(X).
ipClauseDst2([]).

% to handle src commands- assuming src comes before dst in all commands
ipClause1([src, addr|X]) :- ipClauseSrc(X).

ipClauseSrc([X|Y]) :- 
		ipv4_addr(X),
		ipClauseSrc2(Y).

ipClauseSrc2([]).
ipClauseSrc2([dst, addr|X]) :- ipClauseDst(X).
ipClauseSrc2([proto|X]) :- proto_ipv4(X).

/* predicate to check if a given input IP satisfies the IPv4 protocol standards */
ipv4_addr([X]) :-
		atomic_list_concat(L, '.', X),
		list_length(L, 4),
		inRange(L).

ipv4_addr(X) :-
		atomic_list_concat(L, '.', X),
		list_length(L, 4),
		inRange(L).


proto_ipv4([X]) :- 
		atom_number(X, Y),
		range(Y, 256).


/* IPV6 Clauses */

ipvClause([ipv6|X]) :- ipvClause1(X), write(X).

% if no clause specified
ipvClause1([]).

% to handle proto and addr commands
ipvClause1([addr|X]) :- ipv6_addr(X), write(X).
ipvClause1([proto|X]) :- proto_ipv6(X).

% to handle dst chained commands
ipvClause1([dst, addr|X]) :- ipvClauseDst(X).

ipvClauseDst([X|Y]) :- 
		ipv6_addr(X),
		ipvClauseDst2(Y).

ipvClauseDst2([proto|X]) :- proto_ipv6(X).
ipvClauseDst2([]).

% to handle src commands- assuming src comes before dst in all commands
ipvClause1([src, addr|X]) :- ipvClauseSrc(X).

ipvClauseSrc([X|Y]) :- 
		ipv6_addr(X),
		ipvClauseSrc2(Y).

ipvClauseSrc2([]).
ipvClauseSrc2([dst, addr|X]) :- ipvClauseDst(X).
ipvClauseSrc2([proto|X]) :- proto_ipv6(X).


/* predicates to check if a given input IP satisfies the IPv6 protocol standards */ 
checkHexValue([A|B]) :-
		atom_string(A, Test),
		string_to_list(Test, Test1),
		Test1 = [First_char | Rest1],
		Test2 = [Second_char | Rest2],
		First_char = 48,
		Second_char = 120,
		atom_number(A, A1),
		range(A1, 0, 65536),
		checkHexValue(B).

checkHexValue([A]) :-
		atom_string(A, Test),
		string_to_list(Test, Test1),
		Test1 = [First_char | Rest1],
		Test2 = [Second_char | Rest2],
		First_char = 48,
		Second_char = 120,
		atom_number(A, A1),
		range(A1, 0, 65536).

ipv6_addr([X]) :-
		write(X),
		atomic_list_concat(Y1, ':', X),
		checkHexValue(Y1).

ipv6_addr(X) :-
		atomic_list_concat(Y1, ':', X),
		checkHexValue(Y1).

proto_ipv6([X]) :- 
		atom_number(X, Y),
		range(Y, 0, 256).

/* Ethernet clauses */

num(1).
num(X) :-
		Y is X-1,
		(Y >= 1),
		num(Y).

eClause([ether|X]) :- eClause1(X).

% proto keyword- it always occurs at the end of command
eClause1([proto|X]) :- proto_ethernet(X).

% to handle vid- only 1 vid occurs in 1 command
eClause1([vid|X]) :- eClause2(X).
eClause2([X]) :- 
		num(X),
		consult('database.pl'),
		findall(Vids, reject([_, vid, Vids, _]), VidList), 
		ethernetReject(X, VidList).

eClause2([X|Y]) :- num(X), eClause3(Y). 

eClause3().
eClause3([proto|X]) :- proto_ethernet(X).

proto_ethernet([X]) :-
		eChar(X),
		consult('database.pl'),
		findall(Protocols, reject([_, proto, Protocols]), ProtocolList), 
		ethernetReject(X, ProtocolList).

ethernetReject(X, [Head|Tail]) :- 
		((Head == X), write("Packet Rejected!"), false); 
		ethernetReject(X, Tail).

ethernetReject(_, []).

eChar(arp).
eChar(aarp).
eChar(atalk).
eChar(ipx).
eChar(mpls).
eChar(netbui).
eChar(pppoe).
eChar(rarp).
eChar(sna).
eChar(xns).

/* TCP and UDP conditions */

tcpClause([tcp|X]) :- tcpClause1(X).
tcpClause([udp|X]) :- tcpClause1(X).

% handle src commands
tcpClause1([src, port|X]) :- tcp_port(X).

% handle dst commands
tcpClause1([dst, port|X]) :- tcpClauseDst(X).

tcpClauseDst([X]) :- tcp_port(X).
tcpClauseDst([X|Y]) :- 
		tcp_port(X), 
		tcpClauseDst2(Y).

tcpClauseDst2([src, port|X]):- tcp_port(X).

% port number should be between 0-65535
tcp_port(X) :- 
		range(X, 0, 65536),
		consult('database.pl'),
		findall(Ports, reject([_, _, port, Ports]), PortList),
		tcpReject(X, PortList).

tcpReject(X, [Head|Tail]) :-
		((Head == X), write("Packet Rejected!"), false); 
		tcpReject(X, Tail).

tcpReject(_, []).

/* ICMP conditions */
 
icmpClause([icmp|X]) :- icmpClause1(X).

% handle code commands
icmpClause1([code|X]) :- msgCodeICMP(X).

% handle type commands
icmpClause1([type|X]) :- icmpClauseType(X).

icmpClauseType([X]) :- 
		(atom_number(X, Y); term_to_atom(Y, X)), 
		proto_icmp(Y).

icmpClauseType([X|Y]) :- 
		(atom_number(X, Z); term_to_atom(Z, X)),
		proto_icmp(Z),
		icmpClauseType2(Y).

icmpClauseType2([code|X]) :- msgCodeICMP(X).

% message code and protocol type should be between 0-255
proto_icmp(X) :- range(X, 0, 256).
%% proto_icmp(X) :- atom_number(X, Y), range(Y, 255).
msgCodeICMP(X) :- range(X, 0, 256).


/* ICMPv6 conditions */

icmpvClause([icmpv6|X]) :- icmpvClause1(X).

% to handle code commands
icmpvClause1([code|X]) :- msgCodeICMPv6(X).

% to handle type commands
icmpvClause1([type|X]) :- icmpvClauseType(X).

icmpvClauseType([X]) :- proto_icmpv6(X).
icmpvClauseType([X|Y]) :- 
		proto_icmpv6(X),
		icmpvClauseType2(Y).

icmpvClauseType2([code|X]) :- msgCodeICMPv6(X).

% message code and protocol type should be between 0-255
proto_icmpv6(X) :- range(X, 0, 256).
msgCodeICMPv6(X) :- range(X, 0, 256).
