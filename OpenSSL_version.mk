ifeq ($(OPENSSL_DIR),)
	OPENSSL_DIR=.
endif


ifeq ($(LIB),)


ifeq ($(OS),Windows_NT)
    EXE=.exe
    LIB=bin
else
    EXE=
    LIB=lib
endif

#CC=gcc
ifneq ($(OPENSSL_DIR),)
    ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
    # $(OPENSSL_DIR) is relative path
        OPENSSL_LIB=$(OPENSSL_DIR)
    else
    # $(OPENSSL_DIR) is absolute path
        OPENSSL_LIB=$(OPENSSL_DIR)/$(LIB)
    endif
    CFLAGS+=-I$(OPENSSL_DIR)/include
    LDFLAGS+=-L$(OPENSSL_DIR) -L$(OPENSSL_LIB) -Wl,-rpath=$(OPENSSL_DIR) -Wl,-rpath=$(OPENSSL_LIB)
endif
LDLIBS=-lcrypto

.phony: show build run clean

show: build run clean

build: OpenSSL_version

run:	build
	@./OpenSSL_version$(EXE)

clean:
	rm -f OpenSSL_version$(EXE)


else ifeq ($(LIB),h)


OPENSSL_NUMBER_SEL=head -n 1 | sed -r 's/.*?OpenSSL //' | awk '{print ($$0+0)}'
OPENSSLV_H=$(OPENSSL_DIR)/include/openssl/opensslv.h
ifeq ($(shell fgrep OPENSSL_VERSION_MAJOR "$(OPENSSLV_H)"),)
OPENSSL_VERSION=$(shell grep 'OPENSSL_VERSION_TEXT\s* "OpenSSL ' "$(OPENSSLV_H)" | $(OPENSSL_NUMBER_SEL))
else
OPENSSL_VERSION=$(shell fgrep OPENSSL_VERSION_M "$(OPENSSLV_H)" | head -n 2 | awk -v RS="" '{print $$4"."$$8 }')
endif

ifeq ($(OPENSSL_VERSION),1)
    OPENSSL_VERSION=1.0
endif


else # $(LIB)


OPENSSL_VERSION=$(shell strings "$(LIB)" | grep -E 'OpenSSL [0-9]+\.[0-9]+\.' | head -n 1 | sed -r 's/.*?OpenSSL //' | awk -v FS="." '{print $$1"."$$2}')


endif # $(LIB)


.phony: detect

detect:
	$(info $(OPENSSL_VERSION))
