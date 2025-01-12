If you have any question,please send mail to siberlysily@outlook.com or siberlysily@gmail.com
You can git the source code from github society:https://wwww.github.com/Siberly
README_ZH="[Warning]免责声明：本代码仅供技术学习和研究使用。使用者在使用本代码时必须遵守相关法律法规，严禁用于任何违法违规用途。因使用本代码造成的任何损失或后果，均由使用者自行承担。"
README_EN="[Warning]Disclaimer:This code is intended for technical learning and research purposes only. Users must comply with all applicable laws and regulations when using this code. Any illegal or unauthorized use is strictly prohibited. The user assumes all risks and responsibilities for any losses or consequences arising from the use of this code."
version="Siberly Proxy Server v25.0.1"

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

