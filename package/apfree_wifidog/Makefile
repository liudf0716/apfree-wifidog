include $(TOPDIR)/rules.mk

PKG_NAME:=apfree_wifidog
PKG_VERSION:=1.11.565
PKG_RELEASE=1


PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=Liu Dengfeng <liudengfeng@kunteng.org>
PKG_LICENSE_FILES:=COPYING

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/liudf0716/apfree_wifidog.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_VERSION:=master
PKG_SOURCE_VERSION:=5d1696eae50f048ac1a6739e4bb71a466d907066
#PKG_SOURCE_VERSION:=01160737d4c73c1adeef0eaae7e89cf7a40de7a2
#PKG_SOURCE_VERSION:=ee9781ee58c72cfbe8df655fb64d00dac43bc17f
#PKG_SOURCE_VERSION:=3d4769c8a2ff28d9c28b3b2773e0b5332818be74
#PKG_SOURCE_VERSION:=2ae9afb9bd77dddec04843dd39abceba9ebd8c68
#PKG_SOURCE_VERSION:=9926ac3197be0fca9551540f08d15de8c3f5c726
#PKG_SOURCE_VERSION:=dcb919818bab1095906b48c01734a258c7f3fe71
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz


PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/apfree_wifidog
  CATEGORY:=ApFree
  DEPENDS:=+iptables-mod-extra +iptables-mod-ipopt +kmod-ipt-nat +iptables-mod-nat-extra +libpthread +libopenssl +libjson-c +base-files +curl +ipset +fping +ktpriv +libip4tc +libevent2 +libevent2-openssl
  TITLE:=ApFree wireless captive portal solution
  URL:=http://www.kunteng.org
endef

define Package/apfree_wifidog/description
	The ApFree Wifidog project is a complete and embeddable captive
	portal solution for wireless community groups or individuals
	who wish to open a free Hotspot while still preventing abuse
	of their Internet connection.
endef

define Package/apfree_wifidog/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wifidog $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wdctl $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libhttpd.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/wdping $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/wifidog_op $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/verify_wifidog $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/watch_wifidog $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-msg.html $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-redir.html $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-redir.html.front $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-redir.html.rear $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/authserver-offline.html $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/internet-offline.html $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/wifidog.init $(1)/etc/init.d/wifidog
	$(INSTALL_DIR) $(1)/etc/config
	$(CP) ./files/wifidog.conf $(1)/etc/config/wifidog
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/08_add-wifidog-conf-gatewayid $(1)/etc/uci-defaults/
	$(INSTALL_DIR) $(1)/etc/market
	$(INSTALL_DIR) $(1)/etc/market/$(PKG_NAME)
	$(CP) ./files/apfree.* $(1)/etc/
endef

$(eval $(call BuildPackage,apfree_wifidog))
