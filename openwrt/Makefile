#
# Copyright (C) 2026 tachyon-core developers
#
# This is free software, licensed under the GNU General Public License v3.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tachyon-core
PKG_VERSION:=0.0.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Dushnilin/tachyon-core.git
PKG_SOURCE_DATE:=2026-10-09

PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Dushnilin

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/tachyon-core/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=High-performance pure-Rust proxy core (sing-box compatible)
  URL:=https://github.com/Dushnilin/tachyon-core
  DEPENDS:=+ca-bundle +kmod-nft-tproxy +kmod-tun +ip-full
endef

define Package/tachyon-core
$(call Package/tachyon-core/Default)
  TITLE+= (Full build, all 39 protocols)
  PROVIDES:=sing-box
  CONFLICTS:=tachyon-core-lite
endef

define Package/tachyon-core-lite
$(call Package/tachyon-core/Default)
  TITLE+= (Lite build, <=6MB stripped binary for 16-32MB flash)
  PROVIDES:=sing-box
  CONFLICTS:=tachyon-core
endef

define Package/tachyon-core/description
 tachyon-core is a pure-Rust, zero-C-crypto proxy core for OpenWrt routers.
 It provides 100% sing-box compatibility with native CLI drop-in support,
 Clash REST API, transparent proxy (TProxy and TUN), and comprehensive
 protocol support (VLESS, VMess, Reality, Shadowsocks, WireGuard/AmneziaWG,
 Trojan, Hysteria2, TUIC, and direct steering).
endef

define Package/tachyon-core-lite/description
 Low-footprint edition of tachyon-core designed for resource-constrained
 OpenWrt devices with 16MB/32MB flash and 128MB RAM.
 Strips desktop/experimental protocols while preserving core routing,
 VLESS/Reality, Shadowsocks, WireGuard, TProxy, TUN and DNS hijacking.
endef

define Build/Compile/tachyon-core
	cargo build --release --target $(RUSTC_TARGET_ARCH)-unknown-linux-musl --bin tachyon-core
endef

define Build/Compile/tachyon-core-lite
	cargo build --release --no-default-features --features "lite" --target $(RUSTC_TARGET_ARCH)-unknown-linux-musl --bin tachyon-core
endef

define Package/tachyon-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)-unknown-linux-musl/release/tachyon-core $(1)/usr/bin/tachyon-core
	$(LN) tachyon-core $(1)/usr/bin/sing-box

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/tachyon-core.init $(1)/etc/init.d/tachyon-core
	$(LN) tachyon-core $(1)/etc/init.d/sing-box

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/tachyon-core.config $(1)/etc/config/tachyon-core

	$(INSTALL_DIR) $(1)/etc/tachyon-core
	$(INSTALL_DATA) ./files/config.json $(1)/etc/tachyon-core/config.json
endef

define Package/tachyon-core-lite/install
	$(Package/tachyon-core/install)
endef

$(eval $(call BuildPackage,tachyon-core))
$(eval $(call BuildPackage,tachyon-core-lite))
