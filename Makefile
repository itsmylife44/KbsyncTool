TARGET := iphone:clang:14.5:14.5
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = itunesstored
GO_EASY_ON_ME = 1
# export THEOS_DEVICE_IP = 192.168.5.238
# export THEOS_DEVICE_PORT = 58422

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = KbsyncTweak

KbsyncTweak_FILES = Tweak.m
KbsyncTweak_CFLAGS += -fobjc-arc
KbsyncTweak_CFLAGS += -Wno-unused-variable
KbsyncTweak_LIBRARIES += sandy
KbsyncTweak_PRIVATE_FRAMEWORKS = Accounts AppSupport StoreServices
include $(THEOS_MAKE_PATH)/tweak.mk

SUBPROJECTS = kbsynctool
include $(THEOS_MAKE_PATH)/aggregate.mk

after-install::
	install.exec "killall -9 AppStore; killall -9 itunesstored; killall -9 appstored 2>/dev/null &"
