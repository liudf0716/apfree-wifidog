add_executable(aw-bpfctl aw-bpfctl.c)
target_link_libraries(aw-bpfctl PRIVATE bpf json-c)

install(TARGETS aw-bpfctl
	RUNTIME DESTINATION bin
)