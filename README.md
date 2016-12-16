# Apfree WiFiDog: Efficient captive protal solution

Apfree-WiFidog is an open source captive protal solution for wireless router which with embeddabled linux([LEDE](https://github.com/lede-project/source)/[Openwrt](https://github.com/openwrt/openwrt)). 


**[中文介绍]()**

# Awesome

It has some awesome features:

* *Compatible with original wifodog protocol*. You can seamless migration Apfree WiFidog to connect your auth server if you runned traditional wifidog.

* *HTTPS support*. Not only `HTTP`, Apfree WiFiDog can capture `HTTPS` URL request. It's a big deference between traditional WiFiDog.

* *Efficient performance*. Run shell command `time curl --compressed` to test the Apfree WiFiDog reaction rate, `HTTP` response time is 0.05s and `HTTPS` is about 0.2s.

* *Dynamical bulk loading*. Support MAC address and IP address bulk loading with out restart Apfree WiFiDog.

* *Wide application of business*. Apfree WiFidog has been installed and used in tens of thousands routers from KunTeng.Org and partners. Users have been affirmed, fully embodies the applicability, reliability.


----

# How To Compile

Fork and clone the Apfree WiFiDog project:

    git clone https://github.com/KerwinKoo/apfree_wifidog.git 
	cd apfree_wifidog

Assuming you have a working [LEDE](https://github.com/lede-project/source)/[Openwrt](https://github.com/openwrt/openwrt) setup, taking `LEDE` as an example, and assuming your LEDE root path is `LEDE_ROOT`:

	cp -r package/apfree_wifidog/ /LEDE_ROOT/package/

To support `HTTPS`, you need install `libevent` with version 2.1.7 or latest in your LEDE environment, Or using the package copied in Apfree WiFiDog git project:

    cp -r package/libevent2/ /LEDE_ROOT/package/libs/

Now Apfree WiFiDog package has been installed in LEDE packages environment.

    cd /LEDE_ROOT/
	make menuconfig

Chose your `Target System` and `ApFree --> apfree_wifidog`. `SAVE` and `EXIT`.

After Doing `make V=s`, Apfree WiFiDog package is in the path `bin/packages/YOUR-TARGET-ARCH/base/apfree_wifidog_VERSION-RELEASE_YOUR-TARGET-ARCH.ipk `. You can using `opkg install ` command to install this `ipk` in your router.


**The CA-Certificate in this project is ONLY for Apfree WiFiDog HTTPS captive testing, CAN NOT be used for business scene**


