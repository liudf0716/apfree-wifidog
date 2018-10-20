
set(src_apfreewifidog
	main.c
	gateway.c 
	commandline.c 
	conf.c 
	debug.c 
	fw3_iptc.c 
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
	ipset.c 
	ssl_redir.c
	wd_client.c
	wd_util.c 
	mqtt_thread.c
)


set(src_wdctlx wdctl.c util.c debug.c)

set(libs 
	pthread 
	m
	z
	json-c 
	ip4tc
	uci
	ssl
	crypto
	event
	event_openssl
	mosquitto)

set(fw3_libs
	dl
	iptext
	iptext4
	xtables)

ADD_DEFINITIONS(-O2 -Wall --std=gnu99 -Wmissing-declarations)

add_executable(wdctlx ${src_wdctlx})
add_executable(wifidogx ${src_apfreewifidog})
target_link_libraries(wifidogx ${libs} ${fw3_libs} ${CURL_LIBRARIES})

install(TARGETS wifidogx wdctlx
		RUNTIME DESTINATION bin
)

