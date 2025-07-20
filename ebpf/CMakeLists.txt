# xDPI功能控制选项
option(ENABLE_XDPI_FEATURE "Enable xDPI protocol detection and session tracking" ON)

# 如果启用xDPI功能，添加编译定义
if(ENABLE_XDPI_FEATURE)
    add_compile_definitions(ENABLE_XDPI_FEATURE)
    message(STATUS "xDPI feature enabled")
else()
    message(STATUS "xDPI feature disabled")
endif()

add_executable(aw-bpfctl aw-bpfctl.c)
target_link_libraries(aw-bpfctl PRIVATE bpf json-c uci)

add_executable(event_daemon event_daemon.c)
target_link_libraries(event_daemon PRIVATE bpf elf pthread uci)

add_executable(dns-monitor dns-monitor.c)
target_link_libraries(dns-monitor PRIVATE bpf)

install(TARGETS aw-bpfctl event_daemon dns-monitor
	RUNTIME DESTINATION bin
)