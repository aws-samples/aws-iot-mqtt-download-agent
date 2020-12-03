#This target is to ensure accidental execution of Makefile as a bash script will not execute commands like rm in unexpected directories and exit gracefully.
.prevent_execution:
	exit 0

ifeq ($(origin CC),default)
CC = gcc
endif

#remove @ for no make command prints
DEBUG = @

#Use MbedTLS as default tls adapter.
TLS_ADAPTER ?= mbedtls
VALID_TLS_ADAPTER := mbedtls openssl
ifneq ($(filter $(TLS_ADAPTER),$(VALID_TLS_ADAPTER)),)
    $(info TLS_ADAPTER=$(TLS_ADAPTER))
else
    $(error invalid TLS_ADAPTER value)
endif

APP_DIR = .
APP_INCLUDE_DIRS += -I $(APP_DIR)
APP_NAME = execute_cmd_job_sample
APP_SRC_FILES = $(APP_NAME).c

#IoT client directory
IOT_CLIENT_DIR = ../../..

ifeq ($(TLS_ADAPTER),mbedtls)
	PLATFORM_DIR = $(IOT_CLIENT_DIR)/platform/linux/mbedtls
endif

ifeq ($(TLS_ADAPTER),openssl)
	PLATFORM_DIR = $(IOT_CLIENT_DIR)/platform/linux/openssl
endif

PLATFORM_COMMON_DIR = $(IOT_CLIENT_DIR)/platform/linux/common

IOT_INCLUDE_DIRS += -I $(IOT_CLIENT_DIR)/include
IOT_INCLUDE_DIRS += -I $(IOT_CLIENT_DIR)/sdk_config
IOT_INCLUDE_DIRS += -I $(IOT_CLIENT_DIR)/external_libs/jsmn
IOT_INCLUDE_DIRS += -I $(PLATFORM_COMMON_DIR)
IOT_INCLUDE_DIRS += -I $(PLATFORM_DIR)

IOT_SRC_FILES += $(shell find $(IOT_CLIENT_DIR)/src/ -name '*.c')
IOT_SRC_FILES += $(shell find $(IOT_CLIENT_DIR)/external_libs/jsmn -name '*.c')
IOT_SRC_FILES += $(shell find $(PLATFORM_DIR)/ -name '*.c')
IOT_SRC_FILES += $(shell find $(PLATFORM_COMMON_DIR)/ -name '*.c')

ifeq ($(TLS_ADAPTER),mbedtls)
	#TLS - mbedtls
	MBEDTLS_DIR = $(IOT_CLIENT_DIR)/external_libs/mbedTLS
	TLS_LIB_DIR = $(MBEDTLS_DIR)/library
	CRYPTO_LIB_DIR = $(MBEDTLS_DIR)/crypto/library
	TLS_INCLUDE_DIR = -I $(MBEDTLS_DIR)/include
	EXTERNAL_LIBS += -L$(TLS_LIB_DIR)
	LD_FLAG += -Wl,-rpath,$(TLS_LIB_DIR)
	LD_FLAG += -ldl $(TLS_LIB_DIR)/libmbedtls.a $(CRYPTO_LIB_DIR)/libmbedcrypto.a $(TLS_LIB_DIR)/libmbedx509.a -lpthread
	TLS_MAKE_CMD = $(MAKE) -C $(MBEDTLS_DIR)
	PRE_MAKE_CMD = $(TLS_MAKE_CMD) lib
endif

ifeq ($(TLS_ADAPTER),openssl)
	#TLS - openssl
	LD_FLAG += -lcrypto -lssl
	TLS_MAKE_CMD = @:
	PRE_MAKE_CMD = @:
	POST_MAKE_CMD = @:
endif

#Aggregate all include and src directories
INCLUDE_ALL_DIRS += $(IOT_INCLUDE_DIRS)
INCLUDE_ALL_DIRS += $(TLS_INCLUDE_DIR)
INCLUDE_ALL_DIRS += $(APP_INCLUDE_DIRS)

SRC_FILES += $(APP_SRC_FILES)
SRC_FILES += $(IOT_SRC_FILES)

# Logging level control
LOG_FLAGS += -DENABLE_IOT_DEBUG
LOG_FLAGS += -DENABLE_IOT_INFO
LOG_FLAGS += -DENABLE_IOT_WARN
LOG_FLAGS += -DENABLE_IOT_ERROR

COMPILER_FLAGS += $(LOG_FLAGS)
#If the processor is big endian uncomment the compiler flag
#COMPILER_FLAGS += -DREVERSED

MAKE_CMD = $(CC) $(SRC_FILES) $(COMPILER_FLAGS) -o $(APP_NAME) $(LD_FLAG) $(EXTERNAL_LIBS) $(INCLUDE_ALL_DIRS)

all:
	$(PRE_MAKE_CMD)
	$(DEBUG)$(MAKE_CMD)
	$(POST_MAKE_CMD)

clean:
	rm -f $(APP_DIR)/$(APP_NAME)
	$(TLS_MAKE_CMD) clean
