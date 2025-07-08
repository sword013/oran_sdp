# SPA Controller Listener XApp
add_executable(spa_ctrl_listener
    spa_server_controller.c
    controller.c
    spa_common.c
)

target_include_directories(spa_ctrl_listener
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(spa_ctrl_listener
    PUBLIC
    e42_xapp
    -lssl
    -lcrypto
    -lm
    -lpcap
    -pthread
)

# mTLS Controller Listener XApp
add_executable(mtls_ctrl_listener
    handle_connections_controller.c
    controller.c
    spa_common.c
)

target_include_directories(mtls_ctrl_listener
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(mtls_ctrl_listener
    PUBLIC
    e42_xapp
    -lssl
    -lcrypto
    -lm
    -lpcap
    -pthread
)

