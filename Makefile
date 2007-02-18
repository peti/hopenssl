TOP=..
include $(TOP)/mk/boilerplate.mk

# ---------------------------------------------------------------

ALL_DIRS =      \
    OpenSSL

PACKAGE		:= hopenssl
RELEASEDAY	:= 2005-02-14
VERSION		:= 0.0-$(RELEASEDAY)
PACKAGE_DEPS	:= base mtl
SRC_HC_OPTS	+= '-\#include <openssl/evp.h>'

SRC_HADDOCK_OPTS += -t "OpenSSL FFI Bindings ($(PACKAGE) package)"

# ---------------------------------------------------------------

-include $(TOP)/mk/crypto.mk
include $(TOP)/mk/target.mk
