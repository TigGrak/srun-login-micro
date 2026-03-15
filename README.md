# srun-login-micro

🚀 **专门为储存吃紧的Linux设备设计的深澜认证保活方案**

作者想为手头一个储存极小的linux设备挂深澜网络自动登录脚本，可是搜了一圈发现全是python脚本，本人的设备由于环境和储存限制，无法配置python环境，于是根据 [Sztu-srun-login-script](https://github.com/AdamXuD/Sztu-srun-login-script) Vibe-coding了一个Shell + C的方案，点击即用！


---

## ✨ 核心特性

- **极致小巧**：静态编译后的二进制文件约 **46KB**(arm-musl)，加上脚本共**49KB**，完美适配闪存极小的设备。
- **零依赖**：不需要 Python 运行时，仅依赖 `curl` 即可实现秒级重连。
---

## 🛠️ 编译与部署
教程仅提供大致方向，具体可问AI

### 一、编译 (Linux环境)
```bash
git clone git@github.com:TigGrak/srun-login-micro.git
cd srun-login-micro
```
项目提供 `Makefile`，自行补全编译环境
- **本地测试**: `make`
- **交叉编译**: `make CC=/path/to/CC`
例如使用`arm-linux-musleabi-cross`
```bash
wget https://musl.cc/arm-linux-musleabi-cross.tgz
tar -xf arm-linux-musleabi-cross.tgz
make CC=arm-linux-musleabi-cross/bin/arm-linux-musleabi-cc
```

### 二、 部署到路由器
1. 将编译好的 `srun_crypto`(位于`build/`) 放入 `/usr/bin/`(默认`/usr/bin/`添加到`PATH`)
2. 将 `srun_login.sh` 放入你自己的目录(例如`~/`)。
3. 修改`srun_login.sh`内的`USER_ID`和`PASSWORD`字段
4. 授权
```bash
chmod +x /usr/bin/srun_crypto
chmod +x /path/to/srun_login.sh
```

### 三、自行配置定时任务
```
/usr/bin/nohup /bin/sh -c "while true; do /path/to/srun_login.sh; sleep 10; done" > /dev/null 2>&1 &
```
或使用`/etc/rc.local`,`cron`,`systemd`都可，自行选择,本质是定时运行`srun_login.sh`脚本

## 🪲 遇到问题？
1. 无法登录？
- 检查`AC_ID`和url中的`theme`是否和平时在浏览器登录的一致

2. 如何找到适合自己设备的C交叉编译器
- 带着自己的设备型号/目标平台/架构搜索或问AI
- 大部分轻量arm设备如一些路由器等，可使用`arm-linux-musleabi-cross`
