set(src_libhttpd
    api.c
    ip_acl.c
    protocol.c
    version.c
)

add_library(httpd SHARED ${src_libhttpd})

install(TARGETS httpd
        DESTINATION ${LIB_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
