set(COMPONENT_SRCS
	"app_main.c"
	"fleet_provisioning_with_csr.c"
	"mqtt_operations.c"
	"fleet_provisioning_serializer.c"
	"pkcs11_operations.c"
	"mbedtls_pkcs11_posix.c"
	"lvgl_demo_ui.c"
	"cJSON.c"
	"dht.c"
	"i2c.c"
	)

set(COMPONENT_ADD_INCLUDEDIRS
	"."
	"${CMAKE_CURRENT_LIST_DIR}"
	)

idf_component_register(SRCS "lvgl_demo_ui.c" "${COMPONENT_SRCS}"
					   INCLUDE_DIRS ${COMPONENT_ADD_INCLUDEDIRS}
					  )