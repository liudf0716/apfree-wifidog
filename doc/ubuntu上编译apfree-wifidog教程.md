> 编译环境

ubuntu 20.04 LTS版本

> 安装依赖库
+ 安装libubox

```shell
git clone https://github.com/xfguo/libubox.git
cd libubox
cmake -DBUILD_LUA=off
sudo make install
```

+ 安装libuci

```shell
git clone https://github.com/jkjuopperi/uci.git
cd uci
cmake -DBUILD_LUA=off
sudo make install
```
+ 安装其他依赖库

```shell
sudo apt-get update -y
sudo apt-get install -y libjson-c-dev
sudo apt-get install -y libssh2-1-dev
sudo apt-get install -y libevent-dev
```

+ 安装支持apfree wifidog的iptables库

```shell
git clone https://github.com/liudf0716/iptables-apfree-wifidog.git
cd iptables-apfree-wifidog
./autogen.sh
./configure --disable-nftables
make
sudo make install
```

> 编译apfree wifidog

```shell
git clone https://github.com/liudf0716/apfree_wifidog.git
cd apfree_wifidog
mkdir build
cd build
cmake ..
make
```
