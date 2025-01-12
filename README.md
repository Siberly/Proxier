# 应用
将代码下载到服务器上继续编译安装


# 重启服务
sudo systemctl daemon-reload
sudo systemctl enable proxy
sudo systemctl start proxy
sudo systemctl status proxy

# 查看日志
# 系统日志
journalctl -u siberly-proxy-server -f

