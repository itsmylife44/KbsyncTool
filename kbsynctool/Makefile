TARGET := iphone:clang:14.5:14.5
# THEOS_DEVICE_IP = 192.168.5.238
# THEOS_DEVICE_PORT = 58422

include $(THEOS)/makefiles/common.mk

TOOL_NAME = kbsynctool

kbsynctool_FILES = main.m $(wildcard GCDWebServer/*/*.m)
kbsynctool_CFLAGS = -fobjc-arc -IGCDWebServer/Core -IGCDWebServer/Requests -IGCDWebServer/Responses
kbsynctool_LIBRARIES = z
kbsynctool_FRAMEWORKS = CFNetwork CoreServices UIKit
kbsynctool_PRIVATE_FRAMEWORKS = AppSupport
kbsynctool_CODESIGN_FLAGS = -Sentitlements.plist
kbsynctool_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk
