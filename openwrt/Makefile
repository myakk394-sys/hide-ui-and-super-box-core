#
# OpenWrt Package Makefile for Hidekey (Super Box) VPN Core
#

include $(TOPDIR)/rules.mk

PKG_NAME:=super-box
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host

include $(INCLUDE_DIR)/package.mk

define Package/super-box
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Hidekey Zero-Legacy Polymorphic VPN Client Core
  DEPENDS:=+kmod-tun +ca-bundle +librt
  URL:=https://github.com/SuperBox/super_box
endef

define Package/super-box/description
  An ultra-lightweight, zero-legacy polymorphic VPN tunnel core written in Rust.
  Features state-of-the-art BLAKE3-KDF X25519 handshakes and ChaCha20-Poly1305
  WebRTC Opus RTP steganographic framing to bypass advanced DPI censoring on routers.
endef

# Custom build environment variables to pass Cargo configurations to host rust compiler
TARGET_CFLAGS += $(FPIC)
TARGET_LDFLAGS += -Wl,--gc-sections

define Build/Compile
	# Build the Rust release package using cargo for the specified target architecture
	cd $(PKG_BUILD_DIR) && \
		cargo build --release \
			--target $(GNU_TARGET_NAME) \
			--offline
endef

define Package/super-box/install
	# Install compiled binary
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(GNU_TARGET_NAME)/release/super_box $(1)/usr/bin/super_box

	# Install UCI system config
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./super-box.config $(1)/etc/config/super-box

	# Install Procd init system service script
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./super-box.init $(1)/etc/init.d/super-box
endef

$(eval $(call BuildPackage,super-box))
