APPLICATION = tiny_crypto_benchmark
RIOTBASE ?= $(RIOT_DIR)
BOARD ?= native

USEMODULE += xtimer
USEMODULE += random

EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_c25519/c25519/src/
USEMODULE += c25519
INCLUDES += -I$(CURDIR)/tbench_c25519/c25519/src/

ifeq ($(TBENCH), 1)
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=(THREAD_STACKSIZE_DEFAULT + 2048)'
USEPKG += tweetnacl
INCLUDE += -I$(RIOTPKG)/tweetnacl/

EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_tweetnacl/
USEMODULE += tbench_tweetnacl
INCLUDES += -I$(CURDIR)/tbench_tweetnacl/
endif

ifeq ($(TBENCH), 2)
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=(THREAD_STACKSIZE_DEFAULT + 2048)'
EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_c25519/
USEMODULE += tbench_c25519
INCLUDES += -I$(CURDIR)/tbench_c25519/
endif

ifeq ($(TBENCH), 3)
EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_tinyDTLS/
USEMODULE += tbench_tinydtls
INCLUDES += -I$(CURDIR)/tbench_tinyDTLS/
endif

ifeq ($(TBENCH), 4)
EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_nanoecc/
USEMODULE += tbench_nanoecc
INCLUDES += -I$(CURDIR)/tbench_nanoecc/
endif

ifeq ($(TBENCH), 5)
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=(THREAD_STACKSIZE_DEFAULT + 4096)'
EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_ref10/
USEMODULE += tbench_ref10
INCLUDES += -I$(CURDIR)/tbench_ref10/
endif

ifeq ($(TBENCH), 6)
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=(THREAD_STACKSIZE_DEFAULT + 3000)'
EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_p256_mj32/
USEMODULE += tbench_p256_mj32
INCLUDES += -I$(CURDIR)/tbench_p256_mj32/
endif

ifeq ($(TBENCH),7)
CFLAGS += '-DTHREAD_STACKSIZE_MAIN=(THREAD_STACKSIZE_DEFAULT + 2048)'
USEPKG += relic
INCLUDE += $(RIOTPKG)/relic/
ifeq ($(BOARD), native)
	RELIC_CONFIG_FLAGS += -DARCH=X64
	RELIC_CONFIG_FLAGS += -DOPSYS=LINUX
	RELIC_CONFIG_FLAGS += -DWORD=32
	RELIC_CONFIG_FLAGS += -DTIMER=HPROC
	RELIC_CONFIG_FLAGS += -DSEED=UDEV
else
	RELIC_CONFIG_FLAGS += -DARCH=ARM
	RELIC_CONFIG_FLAGS += -DWORD=32
	RELIC_CONFIG_FLAGS += -DOPSYS=None
	RELIC_CONFIG_FLAGS += -DTIMER=CYCLE
	RELIC_CONFIG_FLAGS += -DSEED=LIBC
endif
RELIC_CONFIG_FLAGS += -DALLOC=STACK
RELIC_CONFIG_FLAGS += -DARITH=easy
RELIC_CONFIG_FLAGS += -DDOCUM=off
RELIC_CONFIG_FLAGS += -DQUIET=off
RELIC_CONFIG_FLAGS += -DSTRIP=on
RELIC_CONFIG_FLAGS += '-DWITH=(;BN;FP;DV;MD;EP;CP;)'

export RELIC_CONFIG_FLAGS

EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_relic/
USEMODULE += tbench_relic
INCLUDES += -I$(CURDIR)/tbench_relic/
endif

ifeq ($(TBENCH), 8)
EXTERNAL_MODULE_DIRS += $(CURDIR)/tbench_c25519/
USEMODULE += tbench_c25519
INCLUDES += -I$(CURDIR)/tbench_c25519/
endif

ifndef TBENCH
	TBENCH = 0
endif

ifdef TBENCH
	CFLAGS += '-DTBENCH=$(TBENCH)'
endif

QUIET ?= 1
WERROR = 0
VALGRIND_FLAGS += --tool=massif --stacks=yes #--time-unit=ms --detailed-freq=1

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

FEATURES_REQUIRED += periph_timer

include $(RIOTBASE)/Makefile.include