#
# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

# GMS
PRODUCT_GMS_CLIENTID_BASE := android-huawei

# Kernel
PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
PRODUCT_ENABLE_UFFD_GC := false
OVERRIDE_ENABLE_UFFD_GC := false

# Partitions
PRODUCT_USE_DYNAMIC_PARTITIONS := true

# Shipping API
BOARD_SHIPPING_API_LEVEL := 29
PRODUCT_SHIPPING_API_LEVEL := $(BOARD_SHIPPING_API_LEVEL)

# Soong namespaces
PRODUCT_SOONG_NAMESPACES += \
    $(LOCAL_PATH)

# Inherit from the proprietary files makefile.
$(call inherit-product, vendor/huawei/kirin970-common/kirin970-common-vendor.mk)
