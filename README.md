# Winscan
一键Windows应急响应检测脚本
#### 实现功能：
---
说明：运行本脚本需要管理员权限。

信息收集相关：
+ 操作系统信息
+ 系统补丁情况(*)
+ 系统账户和用户组(*)
+ 域密码策略
+ 管理员组
+ 用户上次登录时间
+ 重要的注册表项
+ RDP保存的凭证
+ 是否开启远程桌面服务
+ 本机共享列表(*)
+ 系统启动信息(*)
+ 已安装的反病毒软件
+ 防火墙配置(*)
+ Defender检测到的活动和过去的恶意软件威胁
+ 防火墙日志和系统日志evtx收集
+ 已安装软件(*)
+ 计划任务(*)
+ 服务状态(*)
+ 自启动服务
+ 自启动目录
+ 注册表启动项(*)
+ 网络连接（ipc$ 命名管道连接）
+ 是否启用Windows剪切板历史记录
+ 用户登录初始化、管理员自动登录
+ Logon Scripts
+ 屏幕保护程序
+ AppInit_DLLs
+ COM劫持(*)
+ shim数据库是否被劫持
+ 进程注入
+ exe文件启动相关注册表
+ Lsa
+ 映像劫持
+ 接受最终用户许可协议的程序
+ 安全模式启动相关注册表
+ powershell命令记录(*)
+ IE浏览器记录
+ certutil下载记录
+ 最近访问的文件(*)
+ "我的电脑、此电脑、计算机"的任意文件夹地址栏内的历史记录
+ 【运行】的历史记录
+ 网络连接情况(*)
+ DNS缓存记录(*)
+ 进程(*)
+ 系统日志是否开启


调查取证相关：
+ SAM、SECURITY、SYSTEM(*)
+ Sysmon 日志(*)
+ SRUM (System Resource Usage Monitor)(*)
+ MUICache(*)
+ ShimCache(*)
+ Prefetch(*)
+ 系统日志(*)

![](https://s51.aconvert.com/convert/p3r68-cdx67/n55nj-e21c0.gif)

![](https://upload-images.jianshu.io/upload_images/21474770-ae15bc0ba4755ece.gif?imageMogr2/auto-orient/strip)
