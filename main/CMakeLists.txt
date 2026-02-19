file(GLOB MAIN_SRCS "st25r3916_irq.c" "*.c")

idf_component_register(
    SRCS ${MAIN_SRCS}
    INCLUDE_DIRS "."
)

