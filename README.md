这是一个基于 [Misaka-blog](https://github.com/Misaka-blog/hysteria-install) 原版脚本进行深度优化和修复的 Shell 脚本。
针对原版脚本中存在的逻辑漏洞、语法错误以及部分配置过时的问题进行了全面修正，旨在提供更稳定、更安全且更符合当前网络环境的 Hysteria 2 部署体验。

##  一键安装

使用 root 用户登录 VPS，执行以下命令：
```bash
wget -N --no-check-certificate [https://raw.githubusercontent.com/Aki1106_0116/hy2-install/main/hysteria.sh](https://raw.githubusercontent.com/Aki1106_0116/hy2-install/main/hysteria.sh) && bash hysteria.sh



## 主要修改与优化 
本项目尊重原作者劳动成果，在此基础上进行了以下核心改进：

### 逻辑与语法修复
1. **修复证书申请逻辑**：移除了原脚本中依赖不稳定第三方 API (`ipget.net`) 进行 IP 比对的逻辑，解决了双栈服务器或 API 宕机导致无法申请证书的问题。现在直接调用 acme.sh，由 CA 机构验证，更精准。
2. **修复配置链接生成错误**：修正了原脚本生成的 `hysteria2://` 分享链接格式错误，并解决了 V2RayN 等客户端因端口格式无法识别而导入失败的问题。

### 性能与抗阻断优化
1. 优化伪装策略 ：
* 原版：默认为 Proxy 模式（反代网页），消耗服务器 CPU 且易被作为跳板攻击。
* 新版：默认改为 String 模式（返回 403 Forbidden）。模拟 Nginx 静态服务器拒绝访问，性能开销极低，隐蔽性更好。

2. 默认开启端口跳跃 ：
* 默认引导用户配置端口跳跃（不仅是单端口），并自动处理 iptables/ip6tables 转发规则。
* 将默认跳跃间隔调整为 25秒，有效对抗运营商的针对性阻断和 QoS 限速。

3. 服务端限速保护：
* 新增“服务端带宽限制”功能，默认设为 100Mbps。
* 适当限制带宽可大幅降低被运营商检测为异常流量的概率，使连接更持久。

### 用户体验改进：
1. 快捷管理指令：安装完成后，自动创建 `/usr/bin/hy2` 快捷方式。以后只需输入 `hy2` 即可随时呼出管理菜单。
2. 提示语优化：重写了大量交互提示，明确指出了自签证书的风险、端口跳跃的优势以及配置建议，对新手更友好。

### 快捷命令：
安装完毕后，直接输入以下命令即可管理服务：
```bash
hy2
```

支持功能：
* 启动 / 停止 / 重启服务
* 修改端口（支持重新配置端口跳跃）
* 修改密码
* 修改伪装形式
* 修改带宽限制
* 查看配置信息与分享链接

* 核心逻辑基于 [Misaka-blog](https://github.com/Misaka-blog) 的开源脚本。
* Hysteria 2 核心程序由 [apernet](https://github.com/apernet/hysteria) 开发。

