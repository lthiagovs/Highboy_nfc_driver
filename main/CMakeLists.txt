set(MAIN_SRCS
    "app/main.c"
    "hal/hb_nfc_hal.c"
    "driver/st25r3916.c"
    "stack/iso14443a/iso14443a.c"
    "stack/mifare/mifare.c"
    "stack/mifare/mf_classic_emu.c"
    "app/nfc_app.c"
)

idf_component_register(
    SRCS ${MAIN_SRCS}
    INCLUDE_DIRS
        "include"
        "include/hal"
        "include/driver"
        "include/stack/iso14443a"
        "include/stack/mifare"
        "include/app"
)
