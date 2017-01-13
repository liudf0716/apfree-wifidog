set(src_apfreewifidog
	main.c
    commandline.c 
	conf.c 
	debug.c 
    fw_iptables.c 
    firewall.c 
    gateway.c 
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
)

set(src_wdctl wdctl.c util.c debug.c)

set(libs 
	httpd
	pthread 
	m
	z
	json-c 
	ip4tc 
	ssl
	crypto
	event
	event_openssl)

ADD_DEFINITIONS(-O2 -Wall --std=gnu99 -Wmissing-declarations)

include_directories(../libhttpd/)


add_executable(wdctl ${src_wdctl})
add_executable(wifidog ${src_apfreewifidog})
target_link_libraries(wifidog ${libs})

install(TARGETS wifidog wdctl
        RUNTIME DESTINATION bin
)

    
