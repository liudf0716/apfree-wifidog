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
    threadpool.c 
    ipset.c 
	http_parser.c
    https_server.c 
	uvhttp_server.c
    uvhttp_base.c 
    uvhttp_ssl_server.c 
    uvhttp_util.c 
    wd_util.c 
)

set(src_wdctl wdctl.c)

set(libs 
	httpd
	pthread 
	m 
	json-c 
	ip4tc 
	openssl
	event2)

ADD_DEFINITIONS(-Os -Wall --std=gnu99 -g3 -Wmissing-declarations)

include_directories(../libhttpd/)


add_executable(wdctl ${src_wdctl})
add_executable(wifidog ${src_apfreewifidog})
target_link_libraries(wifidog ${libs})

install(TARGETS wifidog wdctl
        RUNTIME DESTINATION bin
)

    
