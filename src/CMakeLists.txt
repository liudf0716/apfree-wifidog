# Define source file groups
set(src_apfreewifidog
	main.c gateway.c commandline.c conf.c debug.c
	firewall.c centralserver.c http.c auth.c client_list.c
	util.c wdctlx_thread.c ping_thread.c safe.c
	tls_thread.c wd_client.c wd_util.c mqtt_thread.c
	ws_thread.c api_handlers.c
	bypass_user.c dns_monitor.c
)

set(src_fw3
	fw_iptables.c fw3_iptc.c ipset.c
)

set(src_fw4
	fw_nft.c
)

set(src_vpp
	fw_vpp.c
)



set(src_wdctlx 
	wdctlx.c util.c debug.c
)

# Define common libraries
set(common_libs
	pthread m z json-c ssl crypto
	event event_openssl netfilter_queue
	resolv mosquitto uci
)

# Set compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall --std=gnu99 -Wmissing-declarations")
if(AW_DEBUG)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
	message(STATUS "Building in DEBUG mode")
else()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
	message(STATUS "Building in RELEASE mode")
endif()

# Handle firewall version
if(AW_FW3)
	set(fw_source ${src_fw3})
	set(fw_libs dl ip4tc iptext iptext4 xtables)
	add_definitions(-DAW_FW3)
	message(STATUS "Building with fw3")
	set(src_fw3
		fw_iptables.c fw3_iptc.c ipset.c
	)
elseif(AW_VPP)
	set(fw_source ${src_vpp})
	add_definitions(-DAW_VPP)
	message(STATUS "Building with VPP")
	set(src_vpp
		fw_vpp.c
	)
else()
	set(fw_source ${src_fw4})
	set(fw_libs nftnl mnl bpf)
	add_definitions(-DAW_FW4)
	message(STATUS "Building with fw4")
	set(src_fw4
		fw_nft.c
	)
endif()

# Build targets
add_executable(wdctlx ${src_wdctlx})

add_executable(wifidogx 
	${src_apfreewifidog}
	${fw_source}
)

target_link_libraries(wifidogx
	${common_libs}
	${fw_libs}
	${CURL_LIBRARIES}
)

target_link_libraries(wdctlx
	event
)

# Installation
install(TARGETS wifidogx wdctlx
	RUNTIME DESTINATION bin
)
