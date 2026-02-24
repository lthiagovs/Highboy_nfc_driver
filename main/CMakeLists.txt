file(GLOB MAIN_SRCS "mf_classic_writer.c" "main_write_example.c" "hb_nfc_spi.c" "mf_classic_emu.c" "main.c" "nfc_reader.c" "nfc_card_info.c" "${CMAKE_CURRENT_LIST_DIR}/*.c")

idf_component_register(
    SRCS ${MAIN_SRCS}
    INCLUDE_DIRS "."
)