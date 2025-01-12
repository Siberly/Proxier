# 应用
将代码下载到服务器上继续编译安装
-rwxr-xr-x 1 root root      4669 Jan 12 16:19 linux_proxy_server_install.sh

# 执行安装命令
chmod +x linux_proxy_server_install.sh&sh linux_proxy_server_install.sh

# 等待安装完成即可

# 重启服务
sudo systemctl daemon-reload
sudo systemctl enable siberly_proxy_server
sudo systemctl start siberly_proxy_server
sudo systemctl status siberly_proxy_server

# 查看日志
journalctl -u siberly-proxy-server -f

