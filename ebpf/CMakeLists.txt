add_executable(aw-bpfctl aw-bpfctl.c)
target_link_libraries(aw-bpfctl PRIVATE bpf json-c uci)

install(TARGETS aw-bpfctl
	RUNTIME DESTINATION bin
)