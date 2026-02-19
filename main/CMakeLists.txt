file(GLOB MAIN_SRCS "${CMAKE_CURRENT_LIST_DIR}/*.c")

idf_component_register(
    SRCS ${MAIN_SRCS}
    INCLUDE_DIRS "."
)