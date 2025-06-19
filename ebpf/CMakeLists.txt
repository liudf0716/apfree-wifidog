add_executable(aw-bpfctl aw-bpfctl.c)
target_link_libraries(aw-bpfctl PRIVATE bpf json-c uci)

add_executable(event_daemon event_daemon.c)
target_link_libraries(event_daemon PRIVATE bpf elf pthread)

install(TARGETS aw-bpfctl event_daemon
	RUNTIME DESTINATION bin
)