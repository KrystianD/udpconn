get_filename_component(UDPCONN_CLIENT_CUR_DIR ${CMAKE_CURRENT_LIST_FILE} PATH) # for cmake before 2.8.3

include_directories("${UDPCONN_CLIENT_CUR_DIR}")
