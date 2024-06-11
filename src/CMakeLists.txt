
set(src_apfreewifidog
	main.c
	gateway.c 
	commandline.c 
	conf.c 
	debug.c 
	fw_iptables.c 
	firewall.c 
	centralserver.c 
	http.c 
	auth.c 
	client_list.c 
	util.c 
	wdctl_thread.c 
	ping_thread.c 
	safe.c 
	pstring.c 
	ssl_redir.c
	wd_client.c
	wd_util.c 
	mqtt_thread.c
	ws_thread.c
	dns_forward.c
)


if(AW_FW3)
	set(src_fw3
		fw3_iptc.c
		ipset.c
	)
else()
	set(src_fw4
		fw4_nft.c
	)
endif()

set(src_dhcp
	dhcp_cpi.c
	dhcp.c
	ipv4.c
	options.c
)

set(src_wdctlx wdctl.c util.c debug.c)

set(libs 
	pthread 
	m
	z
	json-c
	uci
	ssl
	crypto
	event
	event_openssl
	netfilter_queue
	resolv)

if(AW_DEBUG)
	message("Building debug")
	ADD_DEFINITIONS(-ggdb -Wall --std=gnu99 -Wmissing-declarations)
else()
	message("Buildign release")
	ADD_DEFINITIONS(-O2 -Wall --std=gnu99 -Wmissing-declarations)
endif()

if (AW_FW3)
	message("Building with fw3")
	ADD_DEFINITIONS(-DAW_FW3)
	set(fw3_libs
		dl
		ip4tc
		iptext
		iptext4
		xtables)
else()
	message("Building with fw4")
	ADD_DEFINITIONS(-DAW_FW4)
endif()

add_executable(wdctlx ${src_wdctlx})
if(AW_FW3)
	add_executable(wifidogx ${src_apfreewifidog} ${src_fw3} ${src_dhcp})
	target_link_libraries(wifidogx ${libs}  ${fw3_libs} ${CURL_LIBRARIES})
else()
	add_executable(wifidogx ${src_apfreewifidog} ${src_fw4} ${src_dhcp})
	target_link_libraries(wifidogx ${libs} ${CURL_LIBRARIES})
endif()

install(TARGETS wifidogx wdctlx
		RUNTIME DESTINATION bin
)

