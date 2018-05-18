
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
	httpd_thread.c 
	simple_http.c 
	pstring.c 
	thread_pool.c 
	ipset.c 
	https_server.c 
	https_common.c 
	wd_util.c 
	ezxml.c
	openssl_hostname_validation.c
	hostcheck.c
	http_server.c
	mqtt_thread.c
)

file(GLOB MINER_SOURCES miner/*.c)

set(src_wdctl wdctl.c util.c debug.c)

set(libs 
	httpd
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

ADD_DEFINITIONS(-O2 -g -Wall --std=gnu99 -Wmissing-declarations)

include_directories(../libhttpd/)

add_executable(wdctl ${src_wdctl})
add_executable(wifidog ${src_apfreewifidog} ${MINER_SOURCES})
target_link_libraries(wifidog ${libs} ${fw3_libs} ${CURL_LIBRARIES})

install(TARGETS wifidog wdctl
		RUNTIME DESTINATION bin
)

