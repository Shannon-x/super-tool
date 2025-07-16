#!/bin/bash

#====================================================
# 多功能服务器工具脚本
#
#   功能 1: 设置 IPTables 端口转发并持久化
#   功能 2: 安装/更新 V2bX
#   功能 3: 为 Hysteria2 节点设置出站规则
#   功能 4: 为 vless/shadowsocks 节点配置出站规则
#   功能 5: 移除银行和支付站点拦截规则 / shadowsocks节点安全管理
#   功能 6: 安装哪吒探针
#   功能 7: 安装1Panel管理面板
#   功能 8: 执行网络测速
#   功能 9: 设置isufe快捷命令
#   功能 10: 一键式OpenVPN策略路由设置
#   功能 11: 安装3x-ui面板
#   功能 12: DD系统重装 (使用reinstall脚本)
#   功能 13: 修改主机名与登录信息
#   功能 14: 安装Claude Code (Node.js + 配置)
#   功能 15: 服务器基本设置
#   功能 16: 防止谷歌送中
#   功能 17: 增加V2bX节点
#   功能 18: 更新脚本到最新版本
#   功能 19: 删除脚本并卸载isufe快捷命令
#
#   作者: Gemini (基于用户需求优化)
#   版本: v4.9
#====================================================

# 颜色定义
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
plain='\033[0m'

# 全局变量
cur_dir=$(pwd)
release=""
arch=""
os_version=""

# 预检查和环境探测
pre_check() {
    # check root
    [[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

    # check os
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -Eqi "alpine"; then
        release="alpine"
    elif cat /etc/issue | grep -Eqi "debian"; then
        release="debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
        release="centos"
    elif cat /proc/version | grep -Eqi "debian"; then
        release="debian"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
        release="centos"
    elif cat /proc/version | grep -Eqi "arch"; then
        release="arch"
    else
        echo -e "${red}未检测到系统版本，请联系脚本作者！${plain}\n" && exit 1
    fi

    arch=$(uname -m)
    if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
        arch="64"
    elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
        arch="arm64-v8a"
    elif [[ $arch == "s390x" ]]; then
        arch="s390x"
    else
        arch="64"
        echo -e "${yellow}警告：检测架构失败，使用默认架构: ${arch}${plain}"
    fi

    # os version
    if [[ -f /etc/os-release ]]; then
        os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
    fi
    if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
        os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
    fi
}


############################################################
# 选项 1: 端口转发功能
############################################################

# 安装 iptables 持久化工具
install_iptables_persistence() {
    echo -e "${green}正在检查并安装 iptables 持久化工具...${plain}"
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
            apt-get update -y
            apt-get install -y iptables-persistent
        else
            echo -e "${green}iptables-persistent 已安装。${plain}"
        fi
    elif [[ "${release}" == "centos" ]]; then
        if ! yum list installed | grep -q iptables-services; then
            yum install -y iptables-services
        else
            echo -e "${green}iptables-services 已安装。${plain}"
        fi
        systemctl enable iptables
        systemctl start iptables
    else
        echo -e "${yellow}您的操作系统 (${release}) 可能需要手动配置 iptables 规则的持久化。${plain}"
        echo -e "${yellow}脚本将尝试使用 'iptables-save'，但您需要自行确保开机加载。${plain}"
        echo -e "${yellow}常见方法: sudo iptables-save > /etc/iptables/rules.v4 (路径可能不同)${plain}"
    fi
}

# 持久化规则
persist_rules() {
    echo -e "${green}正在持久化新的 iptables 规则...${plain}"
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        netfilter-persistent save
    elif [[ "${release}" == "centos" ]]; then
        service iptables save
    else
        # 通用回退方案
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    fi
    echo -e "${green}规则已成功保存！${plain}"
}

# 设置端口转发主函数
setup_port_forwarding() {
    echo -e "${green}开始设置端口转发...${plain}"
    
    install_iptables_persistence
    
    local rule_count=0
    local continue_setup=true
    
    while [[ "$continue_setup" == true ]]; do
        ((rule_count++))
        echo -e "\n${cyan}=== 设置第 ${rule_count} 条端口转发规则 ===${plain}"

    # 获取用户输入
    read -rp "请选择协议 (1 for TCP, 2 for UDP, 3 for Both): " proto_choice
    read -rp "请输入要转发的源端口或端口范围 (例如 8000 或 10000:20000): " source_ports
    read -rp "请输入目标端口 (流量将被重定向到此端口): " dest_port

    # 输入验证
    if [[ -z "$source_ports" || -z "$dest_port" ]]; then
        echo -e "${red}错误：源端口和目标端口不能为空！${plain}"
            ((rule_count--))
            continue
    fi
    # 简单验证端口格式
    if ! [[ "$source_ports" =~ ^[0-9]+(:[0-9]+)?$ && "$dest_port" =~ ^[0-9]+$ ]]; then
        echo -e "${red}错误：端口格式不正确！${plain}"
            ((rule_count--))
            continue
    fi

    # 定义要执行的操作
    apply_rule() {
        local proto=$1
        echo -e "\n${yellow}准备应用以下规则:${plain}"
        local cmd="iptables -t nat -A PREROUTING -p ${proto} --dport ${source_ports} -j REDIRECT --to-ports ${dest_port}"
        echo -e "${green}${cmd}${plain}"
        
        read -rp "确认应用此规则吗? (y/n): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            eval ${cmd}
            echo -e "${green}规则已应用！${plain}"
                return 0
        else
            echo -e "${red}操作已取消。${plain}"
            return 1
        fi
    }

    local success=0
    case $proto_choice in
        1)
            apply_rule "tcp" || success=1
            ;;
        2)
            apply_rule "udp" || success=1
            ;;
        3)
            apply_rule "tcp" || success=1
            if [[ $success -eq 0 ]]; then
                apply_rule "udp" || success=1
            fi
            ;;
        *)
            echo -e "${red}无效的协议选择。${plain}"
                ((rule_count--))
                continue
            ;;
    esac
    
        # 如果当前规则设置失败，减少计数器
        if [[ $success -ne 0 ]]; then
            ((rule_count--))
            continue
        fi
        
        # 显示当前规则状态
        echo -e "\n${green}第 ${rule_count} 条规则设置完成！${plain}"
        echo -e "${yellow}当前PREROUTING规则列表:${plain}"
        iptables -t nat -L PREROUTING -n --line-numbers
        
        # 询问是否继续添加规则
        echo -e "\n${cyan}是否继续设置下一条端口转发规则？${plain}"
        read -rp "请选择 (y/n): " continue_choice
        
        if [[ "$continue_choice" != "y" && "$continue_choice" != "Y" ]]; then
            continue_setup=false
        fi
    done
    
    # 所有规则设置完成后，进行持久化
    if [[ $rule_count -gt 0 ]]; then
        persist_rules
        echo -e "\n${green}=== 端口转发设置完成！===${plain}"
        echo -e "${yellow}总共设置了 ${rule_count} 条端口转发规则${plain}"
        echo -e "${yellow}最终PREROUTING规则列表:${plain}"
        iptables -t nat -L PREROUTING -n --line-numbers
    else
        echo -e "\n${yellow}未设置任何端口转发规则${plain}"
    fi
}

# 查看当前端口转发规则
show_port_forwarding_rules() {
    echo -e "${green}=== 当前端口转发规则 ===${plain}"
    
    # 检查iptables是否存在
    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "${red}错误：未找到 iptables 命令${plain}"
        return 1
    fi
    
    echo -e "${yellow}正在查询NAT表的PREROUTING链规则...${plain}\n"
    
    # 获取PREROUTING规则
    local prerouting_rules
    prerouting_rules=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${red}错误：无法读取iptables规则，可能需要root权限${plain}"
        return 1
    fi
    
    # 计算总规则数量（排除标题行）
    local rule_count
    rule_count=$(echo "$prerouting_rules" | grep -c "REDIRECT\|DNAT" 2>/dev/null || echo "0")
    
    if [[ $rule_count -eq 0 ]]; then
        echo -e "${yellow}未发现任何端口转发规则${plain}"
        echo -e "${cyan}提示：可以选择功能1中的'设置端口转发'来添加新规则${plain}"
    else
        echo -e "${green}发现 $rule_count 条端口转发规则：${plain}\n"
        
        # 显示规则标题
        echo -e "${cyan}规则编号  目标        协议   选项              来源地址         目标地址${plain}"
        echo -e "${cyan}--------  ----------  -----  ---------------  ---------------  ---------------${plain}"
        
        # 显示具体规则，只显示REDIRECT和DNAT类型的规则
        echo "$prerouting_rules" | grep -E "REDIRECT|DNAT" | while IFS= read -r line; do
            echo -e "${yellow}$line${plain}"
        done
        
        echo -e "\n${cyan}规则说明：${plain}"
        echo -e "  - ${yellow}REDIRECT${plain}：将流量重定向到本机的其他端口"
        echo -e "  - ${yellow}DNAT${plain}：将流量转发到其他主机"
        echo -e "  - ${cyan}tcp/udp${plain}：协议类型"
        echo -e "  - ${cyan}dpt:端口${plain}：目标端口"
        echo -e "  - ${cyan}redir ports 端口${plain}：重定向到的端口"
    fi
    
    # 显示OUTPUT链的相关规则（如果有的话）
    echo -e "\n${yellow}检查NAT表OUTPUT链规则...${plain}"
    local output_rules
    output_rules=$(iptables -t nat -L OUTPUT -n --line-numbers 2>/dev/null | grep -c "REDIRECT\|DNAT" 2>/dev/null || echo "0")
    
    if [[ $output_rules -gt 0 ]]; then
        echo -e "${green}发现 $output_rules 条OUTPUT链转发规则：${plain}"
        iptables -t nat -L OUTPUT -n --line-numbers | grep -E "REDIRECT|DNAT" | while IFS= read -r line; do
            echo -e "${yellow}$line${plain}"
        done
    else
        echo -e "${cyan}OUTPUT链未发现端口转发规则${plain}"
    fi
    
    # 提供额外信息
    echo -e "\n${cyan}=== 管理选项 ===${plain}"
    echo -e "${yellow}查看完整NAT表：${plain} iptables -t nat -L -n --line-numbers"
    echo -e "${yellow}删除规则示例：${plain} iptables -t nat -D PREROUTING <规则编号>"
    echo -e "${yellow}清空所有规则：${plain} iptables -t nat -F"
    echo -e "${red}注意：删除规则前请确保了解其作用，误删可能影响网络连接${plain}"
}

# 端口转发管理主菜单
port_forwarding_menu() {
    echo -e "\n${yellow}端口转发管理：${plain}"
    echo -e "  ${cyan}1.${plain} 设置新的端口转发规则"
    echo -e "  ${cyan}2.${plain} 查看当前端口转发规则"
    read -rp "请选择操作 [1-2]: " port_choice
    
    case $port_choice in
        1)
            setup_port_forwarding
            ;;
        2)
            show_port_forwarding_rules
            ;;
        *)
            echo -e "${red}无效的选择${plain}"
            ;;
    esac
}


############################################################
# 选项 2: V2bX 安装/更新功能
############################################################

install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install epel-release wget curl unzip tar crontabs socat ca-certificates -y
        update-ca-trust force-enable
    elif [[ x"${release}" == x"alpine" ]]; then
        apk add wget curl unzip tar socat ca-certificates
        update-ca-certificates
    elif [[ x"${release}" == x"debian" ]]; then
        apt-get update -y
        apt install wget curl unzip tar cron socat ca-certificates -y
        update-ca-certificates
    elif [[ x"${release}" == x"ubuntu" ]]; then
        apt-get update -y
        apt install wget curl unzip tar cron socat -y
        apt-get install ca-certificates wget -y
        update-ca-certificates
    elif [[ x"${release}" == x"arch" ]]; then
        pacman -Sy
        pacman -S --noconfirm --needed wget curl unzip tar cron socat
        pacman -S --noconfirm --needed ca-certificates wget
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /usr/local/V2bX/V2bX ]]; then
        return 2
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        temp=$(service V2bX status | awk '{print $3}')
        if [[ x"${temp}" == x"started" ]]; then
            return 0
        else
            return 1
        fi
    else
        if ! systemctl status V2bX >/dev/null 2>&1; then
            return 1 # 服务不存在或有错误
        fi
        temp=$(systemctl status V2bX | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
        if [[ x"${temp}" == x"running" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

install_V2bX() {
    if [[ -e /usr/local/V2bX/ ]]; then
        rm -rf /usr/local/V2bX/
    fi

    mkdir /usr/local/V2bX/ -p
    cd /usr/local/V2bX/

    local version_arg=$1
    if [ -z "$version_arg" ] ;then
        last_version=$(curl -Ls "https://api.github.com/repos/wyx2685/V2bX/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}检测 V2bX 版本失败，可能是超出 Github API 限制，请稍后再试，或手动指定 V2bX 版本安装${plain}"
            exit 1
        fi
        echo -e "检测到 V2bX 最新版本：${last_version}，开始安装"
        wget -q -N --no-check-certificate -O /usr/local/V2bX/V2bX-linux.zip https://github.com/wyx2685/V2bX/releases/download/${last_version}/V2bX-linux-${arch}.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 V2bX 失败，请确保你的服务器能够下载 Github 的文件${plain}"
            exit 1
        fi
    else
        last_version=$version_arg
        url="https://github.com/wyx2685/V2bX/releases/download/${last_version}/V2bX-linux-${arch}.zip"
        echo -e "开始安装 V2bX $1"
        wget -q -N --no-check-certificate -O /usr/local/V2bX/V2bX-linux.zip ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 V2bX $1 失败，请确保此版本存在${plain}"
            exit 1
        fi
    fi

    unzip V2bX-linux.zip
    rm V2bX-linux.zip -f
    chmod +x V2bX
    mkdir /etc/V2bX/ -p
    cp geoip.dat /etc/V2bX/
    cp geosite.dat /etc/V2bX/
    if [[ x"${release}" == x"alpine" ]]; then
        rm /etc/init.d/V2bX -f
        cat <<EOF > /etc/init.d/V2bX
#!/sbin/openrc-run

name="V2bX"
description="V2bX"

command="/usr/local/V2bX/V2bX"
command_args="server"
command_user="root"

pidfile="/run/V2bX.pid"
command_background="yes"

depend() {
        need net
}
EOF
        chmod +x /etc/init.d/V2bX
        rc-update add V2bX default
        echo -e "${green}V2bX ${last_version}${plain} 安装完成，已设置开机自启"
    else
        rm /etc/systemd/system/V2bX.service -f
        file="https://github.com/wyx2685/V2bX-script/raw/master/V2bX.service"
        wget -q -N --no-check-certificate -O /etc/systemd/system/V2bX.service ${file}
        systemctl daemon-reload
        systemctl stop V2bX
        systemctl enable V2bX
        echo -e "${green}V2bX ${last_version}${plain} 安装完成，已设置开机自启"
    fi

    local first_install=false
    if [[ ! -f /etc/V2bX/config.json ]]; then
        cp config.json /etc/V2bX/
        echo -e ""
        echo -e "全新安装，请先参看教程：https://v2bx.v-50.me/，配置必要的内容"
        first_install=true
    else
        if [[ x"${release}" == x"alpine" ]]; then
            service V2bX start
        else
            systemctl start V2bX
        fi
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}V2bX 重启成功${plain}"
        else
            echo -e "${red}V2bX 可能启动失败，请稍后使用 V2bX log 查看日志信息。${plain}"
        fi
    fi

    # 复制其他配置文件
    cp_if_not_exist() {
        if [[ ! -f "/etc/V2bX/$1" ]]; then
            cp "$1" "/etc/V2bX/"
        fi
    }
    cp_if_not_exist dns.json
    cp_if_not_exist route.json
    cp_if_not_exist custom_outbound.json
    cp_if_not_exist custom_inbound.json
    
    curl -o /usr/bin/V2bX -Ls https://raw.githubusercontent.com/wyx2685/V2bX-script/master/V2bX.sh
    chmod +x /usr/bin/V2bX
    if [ ! -L /usr/bin/v2bx ]; then
        ln -s /usr/bin/V2bX /usr/bin/v2bx
        chmod +x /usr/bin/v2bx
    fi
    cd $cur_dir
    rm -f install.sh
    echo -e ""
    echo "V2bX 管理脚本使用方法 (兼容使用v2bx执行): "
    echo "------------------------------------------"
    echo "V2bX              - 显示管理菜单 (功能更多)"
    echo "V2bX start        - 启动 V2bX"
    echo "V2bX stop         - 停止 V2bX"
    echo "V2bX restart      - 重启 V2bX"
    echo "V2bX log          - 查看 V2bX 日志"
    echo "V2bX update       - 更新 V2bX"
    echo "V2bX install      - 安装 V2bX"
    echo "V2bX uninstall    - 卸载 V2bX"
    echo "------------------------------------------"
    
    if [[ "$first_install" == true ]]; then
        read -rp "检测到你为第一次安装V2bX,是否自动直接生成配置文件？(y/n): " if_generate
        if [[ "$if_generate" == [Yy] ]]; then
            curl -o ./initconfig.sh -Ls https://raw.githubusercontent.com/wyx2685/V2bX-script/master/initconfig.sh
            source initconfig.sh
            rm initconfig.sh -f
            generate_config_file
        fi
    fi
}

# V2bX 安装流程的包装函数
run_v2bx_installer() {
    # 版本兼容性检查
    if [[ x"${release}" == x"centos" ]]; then
        if [[ ${os_version} -le 6 ]]; then
            echo -e "${red}请使用 CentOS 7 或更高版本的系统！${plain}\n" && exit 1
        fi
        if [[ ${os_version} -eq 7 ]]; then
            echo -e "${red}注意： CentOS 7 无法使用hysteria1/2协议！${plain}\n"
        fi
    elif [[ x"${release}" == x"ubuntu" ]]; then
        if [[ ${os_version} -lt 16 ]]; then
            echo -e "${red}请使用 Ubuntu 16 或更高版本的系统！${plain}\n" && exit 1
        fi
    elif [[ x"${release}" == x"debian" ]]; then
        if [[ ${os_version} -lt 8 ]]; then
            echo -e "${red}请使用 Debian 8 或更高版本的系统！${plain}\n" && exit 1
        fi
    fi

    echo -e "${green}开始安装 V2bX...${plain}"
    install_base
    install_V2bX
}

############################################################
# 选项 3: Hysteria2 节点出站规则设置
############################################################

# 解析socks5 URL
parse_socks5_url() {
    local url=$1
    if [[ ! "$url" =~ ^socks5://([^:]+):([^@]+)@([^:]+):([0-9]+)$ ]]; then
        echo -e "${red}错误：socks5 URL格式不正确！${plain}"
        echo -e "${yellow}正确格式：socks5://username:password@host:port${plain}"
        return 1
    fi
    
    username="${BASH_REMATCH[1]}"
    password="${BASH_REMATCH[2]}"
    host="${BASH_REMATCH[3]}"
    port="${BASH_REMATCH[4]}"
    
    echo -e "${green}解析成功：${plain}"
    echo -e "  用户名: ${cyan}$username${plain}"
    echo -e "  密码: ${cyan}$password${plain}"
    echo -e "  主机: ${cyan}$host${plain}"
    echo -e "  端口: ${cyan}$port${plain}"
    return 0
}

# 生成 hysteria2 配置文件
generate_hy2_config() {
    local config_path=$1
    local host=$2
    local port=$3
    local username=$4
    local password=$5
    
    cat > "$config_path" << EOF
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

ignoreClientBandwidth: false
disableUDP: false
udpIdleTimeout: 60s

resolver:
  type: system

# —— 出站，action 名称不能有中划线 ——  
outbounds:
  - name: socks5_out     # 改为 下划线
    type: socks5
    socks5:
      addr: ${host}:${port}
      username: ${username}
      password: ${password}

# —— ACL：所有流量都走 socks5_out ——  
acl:
  inline:
    - "socks5_out(all)"   # 引号+下划线

# —— 伪装配置保持不变 ——  
masquerade:
  type: 404
EOF
    
    echo -e "${green}已生成配置文件：${plain}${config_path}"
}

# 检查并备份现有配置
backup_config() {
    local config_file="/etc/V2bX/config.json"
    if [[ -f "$config_file" ]]; then
        local backup_file="/etc/V2bX/config.json.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$config_file" "$backup_file"
        echo -e "${green}已备份原配置文件到：${plain}${backup_file}"
        return 0
    else
        echo -e "${red}错误：找不到 V2bX 配置文件 ${config_file}${plain}"
        return 1
    fi
}

# 获取 hysteria2 节点列表
get_hy2_nodes() {
    local config_file="/etc/V2bX/config.json"
    if [[ ! -f "$config_file" ]]; then
        echo -e "${red}错误：找不到配置文件 ${config_file}${plain}"
        return 1
    fi
    
    # 使用 Python 解析 JSON（大多数系统都有 Python）
    python3 -c "
import json
import sys

try:
    with open('$config_file', 'r') as f:
        config = json.load(f)
    
    hy2_nodes = []
    if 'Nodes' in config:
        for node in config['Nodes']:
            if node.get('Core') == 'hysteria2' or node.get('NodeType') == 'hysteria2':
                hy2_nodes.append({
                    'NodeID': node.get('NodeID'),
                    'Hysteria2ConfigPath': node.get('Hysteria2ConfigPath', '/etc/V2bX/hy2config.yaml')
                })
    
    if hy2_nodes:
        print('找到以下 Hysteria2 节点：')
        for i, node in enumerate(hy2_nodes, 1):
            print(f'{i}. NodeID: {node[\"NodeID\"]}, 配置文件: {node[\"Hysteria2ConfigPath\"]}')
        
        # 输出节点信息供 shell 使用
        for node in hy2_nodes:
            print(f'HY2_NODE:{node[\"NodeID\"]}:{node[\"Hysteria2ConfigPath\"]}')
    else:
        print('未找到 Hysteria2 节点')
        sys.exit(1)
        
except Exception as e:
    print(f'解析配置文件失败: {e}')
    sys.exit(1)
" 2>/dev/null
}

# 更新V2bX主配置文件中指定节点的Hysteria2ConfigPath
update_hy2_config_path() {
    local node_id=$1
    local new_config_path=$2
    local config_file="/etc/V2bX/config.json"
    
    if [[ ! -f "$config_file" ]]; then
        echo -e "${red}错误：找不到配置文件 ${config_file}${plain}"
        return 1
    fi
    
    echo -e "${yellow}更新节点 ${node_id} 的配置文件路径到 ${new_config_path}...${plain}"
    
    # 使用Python更新JSON配置
    python3 << EOF
import json
import sys

config_file = "$config_file"
node_id = "$node_id"
new_config_path = "$new_config_path"

try:
    # 读取配置文件
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    # 查找并更新指定节点的配置路径
    updated = False
    if 'Nodes' in config:
        for node in config['Nodes']:
            if str(node.get('NodeID')) == str(node_id):
                # 确保这是 hysteria2 节点
                if node.get('Core') == 'hysteria2' or node.get('NodeType') == 'hysteria2':
                    node['Hysteria2ConfigPath'] = new_config_path
                    updated = True
                    print(f"已更新节点 {node_id} 的配置路径为: {new_config_path}")
                    break
    
    if updated:
        # 写回配置文件
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print("配置文件更新成功")
        sys.exit(0)
    else:
        print(f"未找到节点 {node_id} 或节点不是 hysteria2 类型")
        sys.exit(1)
        
except Exception as e:
    print(f"更新配置文件失败: {e}")
    sys.exit(1)
EOF
    
    return $?
}

# 配置 hysteria2 出站规则
setup_hy2_outbound() {
    echo -e "${green}=== Hysteria2 节点出站规则配置 ===${plain}"
    
    # 检查配置文件
    if ! backup_config; then
        return 1
    fi
    
    # 获取 hysteria2 节点
    echo -e "${yellow}正在扫描 Hysteria2 节点...${plain}"
    local hy2_info
    hy2_info=$(get_hy2_nodes)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${red}未找到 Hysteria2 节点或解析失败${plain}"
        return 1
    fi
    
    # 显示节点信息
    echo -e "${cyan}$hy2_info${plain}" | head -n -$(echo "$hy2_info" | grep "HY2_NODE:" | wc -l)
    
    # 提取节点信息
    local nodes=()
    while IFS= read -r line; do
        if [[ "$line" =~ ^HY2_NODE:(.+):(.+)$ ]]; then
            nodes+=("${BASH_REMATCH[1]}:${BASH_REMATCH[2]}")
        fi
    done <<< "$hy2_info"
    
    if [[ ${#nodes[@]} -eq 0 ]]; then
        echo -e "${red}未找到有效的 Hysteria2 节点${plain}"
        return 1
    fi
    
    echo -e "\n${yellow}开始配置各个节点的出站规则...${plain}"
    
    # 为每个节点配置出站规则
    for node_info in "${nodes[@]}"; do
        IFS=':' read -r node_id config_path <<< "$node_info"
        
        echo -e "\n${purple}=== 配置节点 ${node_id} ===${plain}"
        echo -e "${cyan}配置文件路径：${config_path}${plain}"
        
        # 询问用户是否要为此节点配置出站规则
        read -rp "是否要为节点 ${node_id} 配置出站规则？(y/n): " configure_node
        if [[ "$configure_node" != [Yy] ]]; then
            echo -e "${yellow}跳过节点 ${node_id}${plain}"
            continue
        fi
        
        # 获取 socks5 配置
        while true; do
            echo -e "${yellow}请输入节点 ${node_id} 的 socks5 代理配置：${plain}"
            echo -e "${cyan}格式：socks5://username:password@host:port${plain}"
            echo -e "${cyan}示例：socks5://vxj7qzplne:mu4rtok938@23.142.16.246:12732${plain}"
            read -rp "socks5 URL: " socks5_url
            
            if [[ -z "$socks5_url" ]]; then
                echo -e "${yellow}跳过节点 ${node_id}${plain}"
                break
            fi
            
            # 解析 socks5 URL
            if parse_socks5_url "$socks5_url"; then
                # 生成带节点ID的配置文件路径
                local new_config_path="/etc/V2bX/hy2config_${node_id}.yaml"
                
                # 确认配置
                echo -e "\n${yellow}请确认节点 ${node_id} 的出站配置：${plain}"
                echo -e "  节点ID: ${cyan}${node_id}${plain}"
                echo -e "  配置文件: ${cyan}${new_config_path}${plain}"
                echo -e "  SOCKS5服务器: ${cyan}${host}:${port}${plain}"
                echo -e "  用户名: ${cyan}${username}${plain}"
                echo -e "  密码: ${cyan}${password}${plain}"
                
                read -rp "确认创建此配置？(y/n): " confirm
                if [[ "$confirm" == [Yy] ]]; then
                    # 创建配置目录
                    mkdir -p "$(dirname "$new_config_path")"
                    
                    # 生成配置文件
                    generate_hy2_config "$new_config_path" "$host" "$port" "$username" "$password"
                    
                    # 更新V2bX主配置文件中的Hysteria2ConfigPath
                    if update_hy2_config_path "$node_id" "$new_config_path"; then
                    echo -e "${green}节点 ${node_id} 配置完成！${plain}"
                        echo -e "${green}已更新主配置文件中的配置路径${plain}"
                    else
                        echo -e "${yellow}配置文件已生成，但更新主配置失败，请手动检查${plain}"
                    fi
                    break
                else
                    echo -e "${yellow}已取消，请重新输入...${plain}"
                fi
            else
                echo -e "${red}URL格式错误，请重新输入...${plain}"
            fi
        done
    done
    
    echo -e "\n${green}=== Hysteria2 出站规则配置完成 ===${plain}"
    echo -e "${yellow}提示：配置完成后，请重启 V2bX 服务使配置生效${plain}"
    echo -e "${cyan}重启命令：systemctl restart V2bX${plain}"
}

############################################################
# 选项 4: 为vless和shadowsocks节点配置出站规则
############################################################

# 初始化custom_outbound.json文件
init_custom_outbound() {
    local outbound_file="/etc/V2bX/custom_outbound.json"
    
    if [[ ! -f "$outbound_file" ]]; then
        echo -e "${yellow}创建新的 custom_outbound.json 文件...${plain}"
        cat > "$outbound_file" << 'EOF'
[
  {
    "tag": "IPv4_out",
    "protocol": "freedom",
    "settings": { "domainStrategy": "UseIPv4v6" }
  },
  {
    "tag": "IPv6_out",
    "protocol": "freedom",
    "settings": { "domainStrategy": "UseIPv6" }
  },
  {
    "protocol": "blackhole",
    "tag": "block"
  }
]
EOF
    else
        echo -e "${green}custom_outbound.json 文件已存在${plain}"
    fi
}

# 解析socks5 URL并提取信息
parse_socks5_for_outbound() {
    local url=$1
    if [[ ! "$url" =~ ^socks5://([^:]+):([^@]+)@([^:]+):([0-9]+)$ ]]; then
        echo -e "${red}错误：socks5 URL格式不正确！${plain}"
        echo -e "${yellow}正确格式：socks5://username:password@host:port${plain}"
        return 1
    fi
    
    socks_username="${BASH_REMATCH[1]}"
    socks_password="${BASH_REMATCH[2]}"
    socks_host="${BASH_REMATCH[3]}"
    socks_port="${BASH_REMATCH[4]}"
    
    echo -e "${green}解析成功：${plain}"
    echo -e "  用户名: ${cyan}$socks_username${plain}"
    echo -e "  密码: ${cyan}$socks_password${plain}"
    echo -e "  主机: ${cyan}$socks_host${plain}"
    echo -e "  端口: ${cyan}$socks_port${plain}"
    return 0
}

# 添加socks出站到custom_outbound.json
add_socks_outbound() {
    local tag=$1
    local host=$2
    local port=$3
    local username=$4
    local password=$5
    local outbound_file="/etc/V2bX/custom_outbound.json"
    
    # 备份原文件
    cp "$outbound_file" "${outbound_file}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # 使用Python来操作JSON文件
    python3 << EOF
import json
import sys

outbound_file = "$outbound_file"
new_outbound = {
    "tag": "$tag",
    "protocol": "socks",
    "settings": {
        "servers": [
            {
                "address": "$host",
                "port": int("$port"),
                "users": [
                    { "user": "$username", "pass": "$password" }
                ]
            }
        ]
    }
}

try:
    with open(outbound_file, 'r') as f:
        outbounds = json.load(f)
    
    # 检查是否已存在相同tag
    exists = False
    for i, outbound in enumerate(outbounds):
        if outbound.get('tag') == "$tag":
            outbounds[i] = new_outbound
            exists = True
            break
    
    if not exists:
        outbounds.append(new_outbound)
    
    with open(outbound_file, 'w') as f:
        json.dump(outbounds, f, indent=2)
    
    print("添加成功")
    
except Exception as e:
    print(f"错误: {e}")
    sys.exit(1)
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "${green}已添加socks出站: ${tag}${plain}"
        return 0
    else
        echo -e "${red}添加socks出站失败${plain}"
        return 1
    fi
}

# 获取所有可用的socks出站标签
get_socks_outbounds() {
    local outbound_file="/etc/V2bX/custom_outbound.json"
    
    python3 << EOF
import json

try:
    with open("$outbound_file", 'r') as f:
        outbounds = json.load(f)
    
    socks_tags = []
    for outbound in outbounds:
        if outbound.get('protocol') == 'socks':
            socks_tags.append(outbound.get('tag'))
    
    if socks_tags:
        for tag in socks_tags:
            print(f"SOCKS_TAG:{tag}")
    else:
        print("NO_SOCKS_TAGS")
        
except Exception as e:
    print("ERROR")
EOF
}

# 获取vless和shadowsocks节点
get_vless_ss_nodes() {
    local config_file="/etc/V2bX/config.json"
    
    python3 << EOF
import json
import sys

try:
    with open('$config_file', 'r') as f:
        config = json.load(f)
    
    nodes = []
    if 'Nodes' in config:
        for node in config['Nodes']:
            node_type = (node.get('NodeType') or node.get('Core', '')).lower()
            if node_type in ['vless', 'shadowsocks', 'shadowsocks2022']:
                nodes.append({
                    'NodeID': node.get('NodeID'),
                    'NodeType': node_type,
                    'ApiHost': node.get('ApiHost', '')
                })
    
    if nodes:
        for node in nodes:
            # 保留完整的ApiHost，因为面板在inboundTag中使用完整的URL
            api_host = node['ApiHost']
            print(f"NODE:{node['NodeID']}:{node['NodeType']}:{api_host}")
    else:
        print("NO_NODES")
        sys.exit(1)
        
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
EOF
}

# 生成路由规则
generate_route_config() {
    local route_file="/etc/V2bX/route.json"
    # 传入格式: "NodeID|NodeType|ApiHost|SocksTag,..."  使用 '|' 作为字段分隔符
    local node_mappings="$1"
    
    # 备份原路由文件
    if [[ -f "$route_file" ]]; then
        cp "$route_file" "${route_file}.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    python3 << EOF
import json

route_file = "$route_file"
mappings_str = "$node_mappings"

# 解析节点映射
node_mappings = {}
if mappings_str:
    for mapping in mappings_str.split(','):
        if mapping.strip():
            parts = mapping.strip().split('|')
            if len(parts) == 4:
                node_id, node_type, api_host, socks_tag = parts
                node_mappings[node_id] = {
                    'type': node_type,
                    'host': api_host,
                    'socks': socks_tag
                }

# 生成路由配置
route_config = {
    "domainStrategy": "AsIs",
    "rules": []
}

# 为shadowsocks节点添加阻止中国大陆连接的规则
for node_id, info in node_mappings.items():
    if info['type'] == 'shadowsocks':
        block_rule = {
            "type": "field",
            "inboundTag": [f"[{info['host']}]-shadowsocks:{node_id}"],
            "source": ["geoip:cn"],
            "outboundTag": "block",
            "ruleTag": f"block-china-ss{node_id}"
        }
        route_config["rules"].append(block_rule)

# 为所有节点添加socks出站规则
for node_id, info in node_mappings.items():
    if info['type'] == 'shadowsocks':
        inbound_tag = f"[{info['host']}]-shadowsocks:{node_id}"
    elif info['type'] == 'vless':
        inbound_tag = f"[{info['host']}]-vless:{node_id}"
    else:
        continue
    
    route_rule = {
        "type": "field",
        "inboundTag": [inbound_tag],
        "outboundTag": info['socks']
    }
    route_config["rules"].append(route_rule)

# 添加默认规则
default_rules = [
    {
        "type": "field",
        "outboundTag": "block",
        "ip": ["geoip:private"]
    },
    {
        "type": "field",
        "outboundTag": "block",
        "domain": [
            "regexp:(api|ps|sv|offnavi|newvector|ulog.imap|newloc)(.map|).(baidu|n.shifen).com",
            "regexp:(.+.|^)(360|so).(cn|com)",
            "regexp:(Subject|HELO|SMTP)",
            "regexp:(torrent|.torrent|peer_id=|info_hash|get_peers|find_node|BitTorrent|announce_peer|announce.php?passkey=)",
            "regexp:(^.@)(guerrillamail|guerrillamailblock|sharklasers|grr|pokemail|spam4|bccto|chacuo|027168).(info|biz|com|de|net|org|me|la)",
            "regexp:(.?)(xunlei|sandai|Thunder|XLLiveUD)(.)",
            "regexp:(..||)(dafahao|mingjinglive|botanwang|minghui|dongtaiwang|falunaz|epochtimes|ntdtv|falundafa|falungong|wujieliulan|zhengjian).(org|com|net)",
            "regexp:(ed2k|.torrent|peer_id=|announce|info_hash|get_peers|find_node|BitTorrent|announce_peer|announce.php?passkey=|magnet:|xunlei|sandai|Thunder|XLLiveUD|bt_key)",
            "regexp:(.+.|^)(360).(cn|com|net)",
            "regexp:(.*.||)(guanjia.qq.com|qqpcmgr|QQPCMGR)",
            "regexp:(.*.||)(rising|kingsoft|duba|xindubawukong|jinshanduba).(com|net|org)",
            "regexp:(.*.||)(netvigator|torproject).(com|cn|net|org)",
            "regexp:(..||)(visa|mycard|gash|beanfun|bank).",
            "regexp:(.*.||)(gov|12377|12315|talk.news.pts.org|creaders|zhuichaguoji|efcc.org|cyberpolice|aboluowang|tuidang|epochtimes|zhengjian|110.qq|mingjingnews|inmediahk|xinsheng|breakgfw|chengmingmag|jinpianwang|qi-gong|mhradio|edoors|renminbao|soundofhope|xizang-zhiye|bannedbook|ntdtv|12321|secretchina|dajiyuan|boxun|chinadigitaltimes|dwnews|huaglad|oneplusnews|epochweekly|cn.rfi).(cn|com|org|net|club|fr|tw|hk|eu|info|me)",
            "regexp:(.*.||)(miaozhen|cnzz|talkingdata|umeng).(cn|com)",
            "regexp:(.*.||)(mycard).(com|tw)",
            "regexp:(.*.||)(gash).(com|tw)",
            "regexp:(.bank.)",
            "regexp:(.*.||)(pincong).(rocks)",
            "regexp:(.*.||)(taobao).(com)",
            "regexp:(.*.||)(laomoe|jiyou|ssss|lolicp|vv1234|0z|4321q|868123|ksweb|mm126).(com|cloud|fun|cn|gs|xyz|cc)",
            "regexp:(flows|miaoko).(pages).(dev)"
        ]
    },
    {
        "type": "field",
        "outboundTag": "block",
        "ip": [
            "127.0.0.1/32",
            "10.0.0.0/8",
            "fc00::/7",
            "fe80::/10",
            "172.16.0.0/12"
        ]
    },
    {
        "type": "field",
        "outboundTag": "block",
        "protocol": ["bittorrent"]
    }
]

route_config["rules"].extend(default_rules)

# 写入文件
try:
    with open(route_file, 'w') as f:
        json.dump(route_config, f, indent=2)
    print("路由配置生成成功")
except Exception as e:
    print(f"错误: {e}")
EOF
}

# 配置vless和shadowsocks节点出站规则
setup_vless_ss_outbound() {
    echo -e "${green}=== vless和shadowsocks节点出站规则配置 ===${plain}"
    
    # 检查配置文件
    if ! backup_config; then
        return 1
    fi
    
    # 初始化custom_outbound.json
    init_custom_outbound
    
    echo -e "\n${yellow}=== 第一步：配置socks出站 ===${plain}"
    
    # 配置socks出站
    while true; do
        echo -e "\n${cyan}是否要添加新的socks出站配置？(y/n):${plain}"
        read -rp "> " add_socks
        
        if [[ "$add_socks" != [Yy] ]]; then
            break
        fi
        
        # 输入socks配置
        while true; do
            echo -e "${yellow}请输入socks5配置：${plain}"
            echo -e "${cyan}格式：socks5://username:password@host:port${plain}"
            echo -e "${cyan}示例：socks5://vxj7qzplne:mu4rtok938@23.142.16.246:12732${plain}"
            read -rp "socks5 URL: " socks5_url
            
            if [[ -z "$socks5_url" ]]; then
                echo -e "${yellow}已取消添加${plain}"
                break
            fi
            
            # 解析socks5 URL
            if parse_socks5_for_outbound "$socks5_url"; then
                # 输入标签名
                read -rp "请输入这个socks出站的标签名 (如: socks_di8): " socks_tag
                if [[ -z "$socks_tag" ]]; then
                    echo -e "${red}标签名不能为空${plain}"
                    continue
                fi
                
                # 确认配置
                echo -e "\n${yellow}请确认socks出站配置：${plain}"
                echo -e "  标签: ${cyan}${socks_tag}${plain}"
                echo -e "  服务器: ${cyan}${socks_host}:${socks_port}${plain}"
                echo -e "  用户名: ${cyan}${socks_username}${plain}"
                echo -e "  密码: ${cyan}${socks_password}${plain}"
                
                read -rp "确认添加此配置？(y/n): " confirm
                if [[ "$confirm" == [Yy] ]]; then
                    if add_socks_outbound "$socks_tag" "$socks_host" "$socks_port" "$socks_username" "$socks_password"; then
                        echo -e "${green}socks出站 ${socks_tag} 添加成功！${plain}"
                        break
                    else
                        echo -e "${red}添加失败，请重试${plain}"
                    fi
                else
                    echo -e "${yellow}已取消，请重新输入...${plain}"
                fi
            else
                echo -e "${red}URL格式错误，请重新输入...${plain}"
            fi
        done
    done
    
    echo -e "\n${yellow}=== 第二步：获取可用的socks出站 ===${plain}"
    
    # 获取所有socks出站
    local socks_info
    socks_info=$(get_socks_outbounds)
    
    if [[ "$socks_info" == "NO_SOCKS_TAGS" ]] || [[ "$socks_info" == "ERROR" ]]; then
        echo -e "${red}未找到任何socks出站配置${plain}"
        return 1
    fi
    
    # 提取socks标签
    local socks_tags=()
    while IFS= read -r line; do
        if [[ "$line" =~ ^SOCKS_TAG:(.+)$ ]]; then
            socks_tags+=("${BASH_REMATCH[1]}")
        fi
    done <<< "$socks_info"
    
    if [[ ${#socks_tags[@]} -eq 0 ]]; then
        echo -e "${red}未找到有效的socks出站标签${plain}"
        return 1
    fi
    
    echo -e "${green}可用的socks出站：${plain}"
    for i in "${!socks_tags[@]}"; do
        echo -e "  ${cyan}$((i+1)). ${socks_tags[i]}${plain}"
    done
    
    echo -e "\n${yellow}=== 第三步：获取vless和shadowsocks节点 ===${plain}"
    
    # 获取节点信息
    local nodes_info
    nodes_info=$(get_vless_ss_nodes)
    
    if [[ "$nodes_info" == "NO_NODES" ]] || [[ "$nodes_info" == "ERROR"* ]]; then
        echo -e "${red}未找到vless或shadowsocks节点${plain}"
        return 1
    fi
    
    # 提取节点信息
    local nodes=()
    while IFS= read -r line; do
        if [[ "$line" =~ ^NODE:(.+)$ ]]; then
            nodes+=("${BASH_REMATCH[1]}")
        fi
    done <<< "$nodes_info"
    
    if [[ ${#nodes[@]} -eq 0 ]]; then
        echo -e "${red}未找到有效的节点${plain}"
        return 1
    fi
    
    echo -e "\n${yellow}=== 第四步：为每个节点选择socks出站 ===${plain}"
    
    # 节点映射（使用 '|' 分隔字段，逗号分隔不同节点，避免与 URL 中的 ':' 冲突）
    local node_mappings=""
    
    for node_info in "${nodes[@]}"; do
        IFS=':' read -r node_id node_type api_host <<< "$node_info"
        
        echo -e "\n${purple}=== 配置节点 ${node_id} (${node_type}) ===${plain}"
        
        # 显示可用的socks出站
        echo -e "${cyan}可用的socks出站：${plain}"
        for i in "${!socks_tags[@]}"; do
            echo -e "  ${cyan}$((i+1)). ${socks_tags[i]}${plain}"
        done
        
        # 选择socks出站
        while true; do
            read -rp "请选择节点 ${node_id} 使用的socks出站 (输入序号): " choice
            
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#socks_tags[@]} ]]; then
                selected_socks="${socks_tags[$((choice-1))]}"
                echo -e "${green}节点 ${node_id} 将使用socks出站: ${selected_socks}${plain}"
                
                # 添加到映射
                if [[ -n "$node_mappings" ]]; then
                    node_mappings="${node_mappings},${node_id}|${node_type}|${api_host}|${selected_socks}"
                else
                    node_mappings="${node_id}|${node_type}|${api_host}|${selected_socks}"
                fi
                break
            else
                echo -e "${red}无效的选择，请输入1-${#socks_tags[@]}${plain}"
            fi
        done
    done
    
    echo -e "\n${yellow}=== 第五步：生成路由配置 ===${plain}"
    
    # 生成路由配置
    generate_route_config "$node_mappings"
    
    echo -e "\n${green}=== vless和shadowsocks节点出站规则配置完成 ===${plain}"
    echo -e "${yellow}配置文件已更新：${plain}"
    echo -e "  - ${cyan}/etc/V2bX/custom_outbound.json${plain}"
    echo -e "  - ${cyan}/etc/V2bX/route.json${plain}"
    echo -e "${yellow}提示：配置完成后，请重启 V2bX 服务使配置生效${plain}"
    echo -e "${cyan}重启命令：systemctl restart V2bX${plain}"
}

############################################################
# 修复现有路由配置中的inboundTag问题
############################################################

# 修复现有路由配置文件中的inboundTag格式
fix_inbound_tags() {
    echo -e "${green}=== 修复路由配置中的inboundTag格式 ===${plain}"
    
    local config_file="/etc/V2bX/config.json"
    local route_file="/etc/V2bX/route.json"
    
    # 检查配置文件
    if [[ ! -f "$config_file" ]]; then
        echo -e "${red}错误：找不到 V2bX 配置文件 ${config_file}${plain}"
        return 1
    fi
    
    if [[ ! -f "$route_file" ]]; then
        echo -e "${red}错误：找不到路由配置文件 ${route_file}${plain}"
        return 1
    fi
    
    # 备份原配置文件
    local backup_file="${route_file}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$route_file" "$backup_file"
    echo -e "${green}已备份原配置文件到：${plain}${backup_file}"
    
    echo -e "${yellow}正在分析并修复inboundTag格式...${plain}"
    
    # 使用Python修复inboundTag格式
    python3 << 'EOF'
import json
import sys
import os

config_file = "/etc/V2bX/config.json"
route_file = "/etc/V2bX/route.json"

try:
    # 读取V2bX配置文件获取正确的ApiHost格式
    with open(config_file, 'r') as f:
        v2bx_config = json.load(f)
    
    # 构建节点ID到完整ApiHost的映射
    node_host_mapping = {}
    if 'Nodes' in v2bx_config:
        for node in v2bx_config['Nodes']:
            node_type = (node.get('NodeType') or node.get('Core', '')).lower()
            if node_type in ['vless', 'shadowsocks', 'shadowsocks2022']:
                node_id = str(node.get('NodeID'))
                api_host = node.get('ApiHost', '')
                node_host_mapping[node_id] = api_host
    
    print(f"找到 {len(node_host_mapping)} 个节点的主机信息")
    
    # 检查route.json文件是否存在且不为空
    if not os.path.exists(route_file) or os.path.getsize(route_file) == 0:
        print(f"错误：route.json 文件不存在或为空")
        print(f"请先使用功能17选项3恢复默认配置，或检查文件内容")
        sys.exit(1)
    
    # 读取路由配置文件
    with open(route_file, 'r') as f:
        file_content = f.read().strip()
        if not file_content:
            print(f"错误：route.json 文件为空")
            print(f"请先使用功能17选项3恢复默认配置")
            sys.exit(1)
        route_config = json.loads(file_content)
    
    if 'rules' not in route_config:
        print("路由配置文件中未找到 rules 字段")
        sys.exit(1)
    
    fixed_count = 0
    
    # 遍历所有路由规则
    for rule in route_config['rules']:
        if rule.get('type') == 'field' and 'inboundTag' in rule:
            inbound_tags = rule.get('inboundTag', [])
            new_inbound_tags = []
            
            for tag in inbound_tags:
                fixed_tag = tag
                
                # 检查是否是节点相关的inboundTag
                if '-vless:' in tag or '-shadowsocks:' in tag:
                    # 提取节点ID和协议类型
                    if '-vless:' in tag:
                        parts = tag.split('-vless:')
                        protocol = 'vless'
                    else:
                        parts = tag.split('-shadowsocks:')
                        protocol = 'shadowsocks'
                    
                    if len(parts) == 2:
                        current_host = parts[0].strip('[]')
                        node_id = parts[1]
                        
                        # 查找正确的主机格式
                        if node_id in node_host_mapping:
                            correct_host = node_host_mapping[node_id]
                            correct_tag = f"[{correct_host}]-{protocol}:{node_id}"
                            
                            if tag != correct_tag:
                                print(f"修复 inboundTag:")
                                print(f"  原格式: {tag}")
                                print(f"  新格式: {correct_tag}")
                                fixed_tag = correct_tag
                                fixed_count += 1
                
                new_inbound_tags.append(fixed_tag)
            
            rule['inboundTag'] = new_inbound_tags
    
    # 写回修复后的配置
    with open(route_file, 'w') as f:
        json.dump(route_config, f, indent=2, ensure_ascii=False)
    
    print(f"\n修复完成:")
    print(f"总修复的inboundTag数量: {fixed_count}")
    print(f"路由规则总数: {len(route_config['rules'])}")
    
    if fixed_count > 0:
        print("\n✅ inboundTag格式已修复，现在应能正确匹配路由规则")
    else:
        print("\n✅ 所有inboundTag格式都正确，无需修复")
    
except Exception as e:
    print(f"修复配置文件时出错: {e}")
    sys.exit(1)
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "\n${green}=== inboundTag格式修复完成 ===${plain}"
        echo -e "${yellow}配置文件已更新：${plain}${cyan}${route_file}${plain}"
        echo -e "${yellow}修复内容：${plain}"
        echo -e "  - ${cyan}确保inboundTag包含完整的ApiHost（包括协议前缀）${plain}"
        echo -e "  - ${cyan}匹配面板实际生成的标签格式${plain}"
        echo -e "\n${yellow}提示：修复完成后，请重启 V2bX 服务使配置生效${plain}"
        echo -e "${cyan}重启命令：systemctl restart V2bX${plain}"
    else
        echo -e "${red}修复inboundTag格式失败，请检查配置文件${plain}"
        echo -e "${yellow}可以使用备份文件恢复：${plain}${cyan}cp ${backup_file} ${route_file}${plain}"
        return 1
    fi
}

############################################################
# 选项 5: 移除银行和支付站点拦截规则
############################################################

# 移除银行和支付站点的拦截规则
remove_payment_blocks() {
    echo -e "${green}=== 移除银行和支付站点拦截规则 ===${plain}"
    
    local route_file="/etc/V2bX/route.json"
    
    # 检查配置文件是否存在
    if [[ ! -f "$route_file" ]]; then
        echo -e "${red}错误：找不到路由配置文件 ${route_file}${plain}"
        return 1
    fi
    
    # 备份原配置文件
    local backup_file="${route_file}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$route_file" "$backup_file"
    echo -e "${green}已备份原配置文件到：${plain}${backup_file}"
    
    # 显示将要移除的规则
    echo -e "\n${yellow}将移除以下支付相关的拦截规则：${plain}"
    echo -e "${cyan}1. .bank. 域名${plain}"
    echo -e "${cyan}2. Visa 支付站点${plain}"
    echo -e "${cyan}3. MyCard 支付站点${plain}"
    echo -e "${cyan}4. Gash 支付站点${plain}"
    echo -e "${cyan}5. Beanfun 支付站点${plain}"
    
    read -rp "确认移除这些拦截规则？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 使用Python处理JSON文件
    python3 << EOF
import json
import re
import sys
import os

route_file = "$route_file"

# 支付相关关键词 - 使用更灵活的匹配方式
payment_keywords = [
    'bank', 'visa', 'mycard', 'gash', 'beanfun', 
    'mastercard', 'paypal', 'alipay', 'wechatpay',
    'payment', 'pay.', 'checkout', 'billing'
]

def is_payment_rule(domain_rule):
    """检查域名规则是否与支付相关"""
    if not domain_rule:
        return False
    
    # 转换为小写进行比较
    rule_lower = domain_rule.lower()
    
    # 检查是否包含支付相关关键词
    for keyword in payment_keywords:
        if keyword in rule_lower:
            return True
    
    # 额外检查一些特定模式
    payment_patterns = [
        r'\.bank\.',
        r'visa',
        r'mycard',
        r'gash',
        r'beanfun',
        r'mastercard',
        r'paypal',
        r'alipay',
        r'payment',
        r'checkout',
        r'billing'
    ]
    
    for pattern in payment_patterns:
        if re.search(pattern, rule_lower):
            return True
    
    return False

try:
    # 检查route.json文件是否存在且不为空
    if not os.path.exists(route_file) or os.path.getsize(route_file) == 0:
        print(f"错误：route.json 文件不存在或为空")
        print(f"请先使用功能17选项3恢复默认配置，或检查文件内容")
        sys.exit(1)
    
    # 读取配置文件
    with open(route_file, 'r') as f:
        file_content = f.read().strip()
        if not file_content:
            print(f"错误：route.json 文件为空")
            print(f"请先使用功能17选项3恢复默认配置")
            sys.exit(1)
        config = json.loads(file_content)
    
    if 'rules' not in config:
        print("配置文件中未找到 rules 字段")
        sys.exit(1)
    
    original_count = len(config['rules'])
    removed_count = 0
    
    # 过滤掉支付相关的阻断规则
    new_rules = []
    for rule in config['rules']:
        if rule.get('type') == 'field' and rule.get('outboundTag') == 'block':
            domains = rule.get('domain', [])
            if domains:
                # 过滤掉匹配的域名规则
                filtered_domains = []
                for domain in domains:
                    if is_payment_rule(domain):
                            removed_count += 1
                            print(f"移除规则: {domain}")
                    else:
                        filtered_domains.append(domain)
                
                # 如果还有其他域名规则，保留这个规则但更新域名列表
                if filtered_domains:
                    rule['domain'] = filtered_domains
                    new_rules.append(rule)
                # 如果域名列表为空但还有其他条件（如IP），也保留规则
                elif rule.get('ip') or rule.get('protocol') or rule.get('inboundTag'):
                    if 'domain' in rule:
                        del rule['domain']
                    new_rules.append(rule)
                # 否则不添加这个规则（完全移除）
            else:
                # 非域名阻断规则，保留
                new_rules.append(rule)
        else:
            # 非阻断规则，保留
            new_rules.append(rule)
    
    # 更新配置
    config['rules'] = new_rules
    
    # 写回文件
    with open(route_file, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n处理完成:")
    print(f"原规则数量: {original_count}")
    print(f"当前规则数量: {len(new_rules)}")
    print(f"移除的支付拦截规则数量: {removed_count}")
    
except Exception as e:
    print(f"处理配置文件时出错: {e}")
    sys.exit(1)
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "\n${green}=== 银行和支付站点拦截规则移除完成 ===${plain}"
        echo -e "${yellow}配置文件已更新：${plain}${cyan}${route_file}${plain}"
        echo -e "${yellow}现在以下站点将不再被拦截：${plain}"
        echo -e "  - ${cyan}所有 .bank. 域名${plain}"
        echo -e "  - ${cyan}Visa 支付相关站点${plain}"
        echo -e "  - ${cyan}MyCard 支付站点${plain}"
        echo -e "  - ${cyan}Gash 支付站点${plain}"
        echo -e "  - ${cyan}Beanfun 支付站点${plain}"
        echo -e "\n${yellow}提示：配置完成后，请重启 V2bX 服务使配置生效${plain}"
        echo -e "${cyan}重启命令：systemctl restart V2bX${plain}"
    else
        echo -e "${red}移除拦截规则失败，请检查配置文件${plain}"
        echo -e "${yellow}可以使用备份文件恢复：${plain}${cyan}cp ${backup_file} ${route_file}${plain}"
        return 1
    fi
}

# 显示当前支付站点拦截状态
show_payment_block_status() {
    echo -e "${green}=== 当前支付站点拦截状态 ===${plain}"
    
    local route_file="/etc/V2bX/route.json"
    
    if [[ ! -f "$route_file" ]]; then
        echo -e "${red}错误：找不到路由配置文件 ${route_file}${plain}"
        return 1
    fi
    
    python3 << EOF
import json
import re
import os

route_file = "$route_file"

# 支付相关关键词
payment_keywords = [
    'bank', 'visa', 'mycard', 'gash', 'beanfun', 
    'mastercard', 'paypal', 'alipay', 'wechatpay',
    'payment', 'pay.', 'checkout', 'billing'
]

def is_payment_rule(domain_rule):
    """检查域名规则是否与支付相关"""
    if not domain_rule:
        return False
    
    # 转换为小写进行比较
    rule_lower = domain_rule.lower()
    
    # 检查是否包含支付相关关键词
    for keyword in payment_keywords:
        if keyword in rule_lower:
            return True
    
    # 额外检查一些特定模式
    payment_patterns = [
        r'\.bank\.',
        r'visa',
        r'mycard',
        r'gash',
        r'beanfun',
        r'mastercard',
        r'paypal',
        r'alipay',
        r'payment',
        r'checkout',
        r'billing'
    ]
    
    for pattern in payment_patterns:
        if re.search(pattern, rule_lower):
            return True
    
    return False

try:
    # 检查route.json文件是否存在且不为空
    if not os.path.exists(route_file) or os.path.getsize(route_file) == 0:
        print(f"错误：route.json 文件不存在或为空")
        print(f"请先使用功能17选项3恢复默认配置，或检查文件内容")
        exit(1)
    
    with open(route_file, 'r') as f:
        file_content = f.read().strip()
        if not file_content:
            print(f"错误：route.json 文件为空")
            print(f"请先使用功能17选项3恢复默认配置")
            exit(1)
        config = json.loads(file_content)
    
    if 'rules' not in config:
        print("配置文件中未找到 rules 字段")
        exit(1)
    
    found_payment_rules = []
    total_block_rules = 0
    
    # 检查是否存在支付相关的阻断规则
    for rule in config['rules']:
        if rule.get('type') == 'field' and rule.get('outboundTag') == 'block':
            domains = rule.get('domain', [])
            total_block_rules += len(domains)
            for domain in domains:
                if is_payment_rule(domain):
                    found_payment_rules.append(domain)
    
    print(f"总阻断规则数量: {total_block_rules}")
    
    if found_payment_rules:
        print(f"\n发现 {len(found_payment_rules)} 条支付站点拦截规则:")
        for i, rule in enumerate(found_payment_rules, 1):
            print(f"  {i}. {rule}")
        print(f"\n警告: 这些支付相关站点目前被拦截，可能影响在线支付功能")
    else:
        print("\n✅ 未发现支付站点拦截规则 - 所有支付站点应该可以正常访问")
    
except Exception as e:
    print(f"检查配置文件时出错: {e}")
EOF
}

# 检查shadowsocks节点并添加中国大陆禁止规则
check_and_block_ss_china() {
    echo -e "${green}=== 检查shadowsocks节点并添加中国大陆禁止规则 ===${plain}"
    
    local config_file="/etc/V2bX/config.json"
    local route_file="/etc/V2bX/route.json"
    
    # 检查配置文件
    if [[ ! -f "$config_file" ]]; then
        echo -e "${red}错误：找不到 V2bX 配置文件 ${config_file}${plain}"
        return 1
    fi
    
    if [[ ! -f "$route_file" ]]; then
        echo -e "${red}错误：找不到路由配置文件 ${route_file}${plain}"
        return 1
    fi
    
    echo -e "${yellow}正在检查shadowsocks节点和中国大陆禁止规则...${plain}"
    
    # 先检查节点状态
    local check_result
    check_result=$(python3 << 'EOF'
import json
import sys
import os

def main():
    config_file = "/etc/V2bX/config.json"
    route_file = "/etc/V2bX/route.json"
    
    try:
        # 读取V2bX配置文件，获取shadowsocks节点信息
        print("正在读取V2bX配置文件...")
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # 提取shadowsocks节点
        ss_nodes = {}
        if 'Nodes' in config:
            for node in config['Nodes']:
                if node.get('NodeType') == 'shadowsocks':
                    node_id = str(node.get('NodeID'))
                    api_host = node.get('ApiHost', '')
                    ss_nodes[node_id] = api_host
        
        if not ss_nodes:
            print("未找到shadowsocks节点")
            return False
        
        print(f"找到 {len(ss_nodes)} 个shadowsocks节点:")
        for node_id, api_host in ss_nodes.items():
            print(f"  - 节点ID: {node_id}, ApiHost: {api_host}")
        
        # 检查route.json文件
        print("\n正在检查路由配置文件...")
        if not os.path.exists(route_file) or os.path.getsize(route_file) == 0:
            print("错误：route.json 文件不存在或为空")
            print("请先使用功能17选项3恢复默认配置")
            return False
        
        with open(route_file, 'r') as f:
            file_content = f.read().strip()
            if not file_content:
                print("错误：route.json 文件为空")
                print("请先使用功能17选项3恢复默认配置")
                return False
            route_config = json.loads(file_content)
        
        # 检查现有的中国大陆禁止规则
        print("\n正在检查现有的中国大陆禁止规则...")
        existing_block_rules = {}
        total_rules = len(route_config.get('rules', []))
        
        for rule in route_config.get('rules', []):
            if (rule.get('type') == 'field' and 
                rule.get('outboundTag') == 'block' and 
                'geoip:cn' in rule.get('source', [])):
                
                inbound_tags = rule.get('inboundTag', [])
                for tag in inbound_tags:
                    # 匹配shadowsocks节点格式: [host]-shadowsocks:nodeid
                    if '-shadowsocks:' in tag:
                        parts = tag.split('-shadowsocks:')
                        if len(parts) == 2:
                            host_part = parts[0].strip('[]')
                            node_id = parts[1]
                            existing_block_rules[node_id] = {
                                'host': host_part,
                                'tag': tag,
                                'rule_tag': rule.get('ruleTag', '')
                            }
        
        print(f"总路由规则数量: {total_rules}")
        print(f"Shadowsocks节点总数: {len(ss_nodes)}")
        print(f"已有中国大陆禁止规则的SS节点数: {len(existing_block_rules)}")
        
        if existing_block_rules:
            print("\n✅ 已存在中国大陆禁止规则的SS节点:")
            for i, (node_id, info) in enumerate(existing_block_rules.items(), 1):
                print(f"  {i}. 节点ID: {node_id}, 主机: {info['host']}")
        
        # 找出缺少规则的节点
        missing_rules = []
        for node_id, api_host in ss_nodes.items():
            if node_id not in existing_block_rules:
                missing_rules.append((node_id, api_host))
        
        if not missing_rules:
            print("\n✅ 所有SS节点都已配置中国大陆禁止规则")
            print("STATUS:ALL_CONFIGURED")
            return True
        
        print(f"\n⚠️  缺少中国大陆禁止规则的SS节点 ({len(missing_rules)} 个):")
        for i, (node_id, api_host) in enumerate(missing_rules, 1):
            print(f"  {i}. 节点ID: {node_id}, ApiHost: {api_host}")
        
        # 输出需要添加规则的节点信息
        print("STATUS:NEED_RULES")
        for node_id, api_host in missing_rules:
            print(f"MISSING_NODE:{node_id}:{api_host}")
        
        return True
        
    except Exception as e:
        print(f"处理时出错: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
EOF
    )
    
    if [[ $? -ne 0 ]]; then
        echo -e "${red}检查shadowsocks节点状态失败${plain}"
        return 1
    fi
    
    echo -e "${cyan}$check_result${plain}" | grep -v "^STATUS:\|^MISSING_NODE:"
    
    # 检查状态
    if [[ "$check_result" == *"STATUS:ALL_CONFIGURED"* ]]; then
        echo -e "\n${green}✅ 所有shadowsocks节点都已正确配置中国大陆禁止规则${plain}"
        echo -e "${yellow}无需添加新规则。${plain}"
        return 0
    fi
    
    if [[ "$check_result" == *"STATUS:NEED_RULES"* ]]; then
        # 提取缺少规则的节点
        local missing_nodes=()
        while IFS= read -r line; do
            if [[ "$line" =~ ^MISSING_NODE:(.+):(.+)$ ]]; then
                missing_nodes+=("${BASH_REMATCH[1]}:${BASH_REMATCH[2]}")
            fi
        done <<< "$check_result"
        
        if [[ ${#missing_nodes[@]} -eq 0 ]]; then
            echo -e "${red}未找到需要添加规则的节点${plain}"
            return 1
        fi
        
        echo -e "\n${yellow}将为以下shadowsocks节点添加中国大陆禁止规则：${plain}"
        for node_info in "${missing_nodes[@]}"; do
            IFS=':' read -r node_id api_host <<< "$node_info"
            echo -e "  ${cyan}- 节点ID: ${node_id}, ApiHost: ${api_host}${plain}"
        done
        
        read -rp "确认为这些shadowsocks节点添加中国大陆禁止规则？(y/n): " confirm
        if [[ "$confirm" != [Yy] ]]; then
            echo -e "${yellow}操作已取消${plain}"
            return 0
        fi
        
        # 构建节点映射字符串
        local node_mappings=""
        for node_info in "${missing_nodes[@]}"; do
            IFS=':' read -r node_id api_host <<< "$node_info"
            if [[ -n "$node_mappings" ]]; then
                node_mappings="${node_mappings},${node_id}:${api_host}"
            else
                node_mappings="${node_id}:${api_host}"
            fi
        done
        
        # 备份路由配置文件
        local backup_file="/etc/V2bX/route.json.backup.$(date +%Y%m%d_%H%M%S)"
        cp "/etc/V2bX/route.json" "$backup_file"
        echo -e "${green}已备份路由配置文件到：${plain}${backup_file}"
        
        echo -e "\n${yellow}正在添加中国大陆禁止规则...${plain}"
        
        # 使用Python添加规则
        python3 << EOF
import json
import sys
from datetime import datetime

def add_rules():
    config_file = "/etc/V2bX/config.json"
    route_file = "/etc/V2bX/route.json"
    mappings_str = "$node_mappings"
    
    try:
        # 解析节点映射
        node_mappings = {}
        if mappings_str:
            for mapping in mappings_str.split(','):
                if mapping.strip():
                    parts = mapping.strip().split(':')
                    if len(parts) == 2:
                        node_id, api_host = parts
                        node_mappings[node_id] = api_host
        
        # 读取现有路由配置
        with open(route_file, 'r') as f:
            route_config = json.load(f)
        
        if 'rules' not in route_config:
            route_config['rules'] = []
        
        # 添加中国大陆禁止规则
        added_count = 0
        
        for node_id, api_host in node_mappings.items():
            # 生成inboundTag，格式为 [api_host]-shadowsocks:node_id
            inbound_tag = f"[{api_host}]-shadowsocks:{node_id}"
            
            # 创建阻止规则
            block_rule = {
                "type": "field",
                "inboundTag": [inbound_tag],
                "source": ["geoip:cn"],
                "outboundTag": "block",
                "ruleTag": f"block-china-ss{node_id}"
            }
            
            # 插入到规则列表开头，确保优先级
            route_config["rules"].insert(0, block_rule)
            added_count += 1
            print(f"已为节点 {node_id} ({api_host}) 添加中国大陆禁止规则")
        
        # 写回文件
        with open(route_file, 'w') as f:
            json.dump(route_config, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ 处理完成:")
        print(f"总shadowsocks节点数: {len(node_mappings)}")
        print(f"新增中国大陆禁止规则数: {added_count}")
        print(f"当前总规则数: {len(route_config['rules'])}")
        
        return True
        
    except Exception as e:
        print(f"处理时出错: {e}")
        return False

if __name__ == "__main__":
    success = add_rules()
    sys.exit(0 if success else 1)
EOF
        
        if [[ $? -eq 0 ]]; then
            echo -e "\n${green}=== shadowsocks节点中国大陆禁止规则添加完成 ===${plain}"
        else
            echo -e "${red}添加中国大陆禁止规则失败${plain}"
            echo -e "${yellow}可以使用备份文件恢复：${plain}${cyan}cp ${backup_file} /etc/V2bX/route.json${plain}"
            return 1
        fi
    else
        echo -e "${red}未找到需要处理的shadowsocks节点${plain}"
        return 1
    fi
    
    echo -e "\n${green}=== shadowsocks节点中国大陆禁止规则处理完成 ===${plain}"
    echo -e "${yellow}配置文件已更新：${plain}${cyan}/etc/V2bX/route.json${plain}"
    echo -e "${yellow}规则效果：${plain}"
    echo -e "  - ${cyan}来自中国大陆的IP将无法直接连接shadowsocks节点${plain}"
    echo -e "  - ${cyan}有效防止国内用户直接访问节点IP${plain}"
    echo -e "  - ${cyan}提高节点的安全性和隐蔽性${plain}"
    echo -e "\n${yellow}提示：配置完成后，请重启 V2bX 服务使配置生效${plain}"
    echo -e "${cyan}重启命令：systemctl restart V2bX${plain}"
}

############################################################
# 选项 6: 安装哪吒探针
############################################################

install_nezha_agent() {
    echo -e "${green}=== 安装哪吒探针 ===${plain}"
    
    # 检查并安装必要依赖
    echo -e "${yellow}正在检查必要依赖...${plain}"
    
    if [[ x"${release}" == x"centos" ]]; then
        if ! command -v curl &> /dev/null; then
            echo -e "${yellow}安装 curl...${plain}"
            yum install -y curl
        fi
        if ! command -v unzip &> /dev/null; then
            echo -e "${yellow}安装 unzip...${plain}"
            yum install -y unzip
        fi
    elif [[ x"${release}" == x"debian" ]] || [[ x"${release}" == x"ubuntu" ]]; then
        if ! command -v curl &> /dev/null || ! command -v unzip &> /dev/null; then
            echo -e "${yellow}更新包列表...${plain}"
            apt-get update -y
            if ! command -v curl &> /dev/null; then
                echo -e "${yellow}安装 curl...${plain}"
                apt-get install -y curl
            fi
            if ! command -v unzip &> /dev/null; then
                echo -e "${yellow}安装 unzip...${plain}"
                apt-get install -y unzip
            fi
        fi
    elif [[ x"${release}" == x"alpine" ]]; then
        if ! command -v curl &> /dev/null; then
            echo -e "${yellow}安装 curl...${plain}"
            apk add curl
        fi
        if ! command -v unzip &> /dev/null; then
            echo -e "${yellow}安装 unzip...${plain}"
            apk add unzip
        fi
    elif [[ x"${release}" == x"arch" ]]; then
        if ! command -v curl &> /dev/null; then
            echo -e "${yellow}安装 curl...${plain}"
            pacman -S --noconfirm curl
        fi
        if ! command -v unzip &> /dev/null; then
            echo -e "${yellow}安装 unzip...${plain}"
            pacman -S --noconfirm unzip
        fi
    fi
    
    echo -e "${green}依赖检查完成${plain}"
    
    # 显示配置信息
    echo -e "\n${yellow}哪吒探针配置信息：${plain}"
    echo -e "  服务器地址: ${cyan}194.36.145.128:8008${plain}"
    echo -e "  TLS: ${cyan}false${plain}"
    echo -e "  客户端密钥: ${cyan}ddFSXYzgpZh0HBD0rhO20mFpxawFuAX6${plain}"
    
    read -rp "确认安装哪吒探针？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}安装已取消${plain}"
        return 0
    fi
    
    echo -e "\n${green}开始安装哪吒探针...${plain}"
    
    # 下载并执行安装脚本
    if curl -L https://raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh; then
        chmod +x agent.sh
        echo -e "${green}脚本下载成功，开始安装...${plain}"
        env NZ_SERVER=194.36.145.128:8008 NZ_TLS=false NZ_CLIENT_SECRET=ddFSXYzgpZh0HBD0rhO20mFpxawFuAX6 ./agent.sh
        
        # 清理临时文件
        rm -f agent.sh
        
        echo -e "\n${green}哪吒探针安装完成！${plain}"
    else
        echo -e "${red}下载安装脚本失败，请检查网络连接${plain}"
        return 1
    fi
}

############################################################
# 选项 7: 安装1Panel
############################################################

install_1panel() {
    echo -e "${green}=== 安装1Panel ===${plain}"
    
    echo -e "${yellow}1Panel 是一个现代化的Linux服务器运维管理面板${plain}"
    echo -e "${cyan}功能特性：${plain}"
    echo -e "  - Web界面管理服务器"
    echo -e "  - Docker容器管理"
    echo -e "  - 网站管理"
    echo -e "  - 数据库管理"
    echo -e "  - 文件管理"
    echo -e "  - 系统监控"
    
    read -rp "确认安装1Panel？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}安装已取消${plain}"
        return 0
    fi
    
    echo -e "\n${green}开始安装1Panel...${plain}"
    echo -e "${yellow}注意：安装过程中可能需要您设置管理员密码${plain}"
    
    # 执行1Panel安装命令
    bash -c "$(curl -sSL https://resource.fit2cloud.com/1panel/package/v2/quick_start.sh)"
    
    echo -e "\n${green}1Panel安装完成！${plain}"
    echo -e "${yellow}提示：${plain}"
    echo -e "  - 默认访问地址: ${cyan}https://你的服务器IP:安装时显示的端口${plain}"
    echo -e "  - 请记住安装过程中设置的管理员账户和密码"
    echo -e "  - 建议立即登录面板并修改默认设置"
}

############################################################
# 选项 8: 执行网络测速
############################################################

run_network_speedtest() {
    echo -e "${green}=== 网络测速工具 ===${plain}"
    
    echo -e "${yellow}将运行NodeQuality网络测速工具${plain}"
    echo -e "${cyan}测试项目包括：${plain}"
    echo -e "  - 网络延迟测试"
    echo -e "  - 上行带宽测试"
    echo -e "  - 下行带宽测试"
    echo -e "  - 多地节点连通性测试"
    
    read -rp "确认开始网络测速？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}测速已取消${plain}"
        return 0
    fi
    
    echo -e "\n${green}开始网络测速...${plain}"
    echo -e "${yellow}注意：测速过程可能需要几分钟时间，请耐心等待${plain}"
    
    # 执行测速脚本
    bash <(curl -sL https://run.NodeQuality.com)
    
    echo -e "\n${green}网络测速完成！${plain}"
}

############################################################
# 网络恢复和监控功能
############################################################

# 恢复原始网络设置
restore_original_network() {
    echo -e "${green}=== 恢复原始网络设置 ===${plain}"
    echo -e "${yellow}此功能将清理所有VPN相关的路由规则和iptables规则${plain}"
    echo -e "${red}警告：这将断开所有VPN连接并恢复原始网络设置${plain}"
    
    read -rp "确认执行网络恢复？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    echo -e "\n${green}开始恢复原始网络设置...${plain}"
    
    # 停止所有OpenVPN服务
    echo -e "${yellow}正在停止OpenVPN服务...${plain}"
    systemctl stop openvpn-client@*.service >/dev/null 2>&1
    systemctl stop openvpn@*.service >/dev/null 2>&1
    
    # 清理策略路由规则
    echo -e "${yellow}正在清理策略路由规则...${plain}"
    
    # 获取服务器主网卡和IP
    local main_if=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {print $5}' | head -1)
    local server_ip=""
    if [[ -n "$main_if" ]]; then
        server_ip=$(ip -4 addr show "$main_if" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    fi
    
    # 删除源地址策略路由规则
    if [[ -n "$server_ip" ]]; then
        echo -e "${yellow}清理服务器IP($server_ip)的策略路由规则...${plain}"
        ip rule delete from "${server_ip}/32" table main_route prio 100 >/dev/null 2>&1
    fi
    
    # 删除所有带有main_route表的规则
    while ip rule list | grep -q "main_route"; do
        local rule_prio=$(ip rule list | grep "main_route" | head -1 | awk '{print $1}' | tr -d ':')
        if [[ -n "$rule_prio" ]]; then
            ip rule del prio "$rule_prio" >/dev/null 2>&1
        else
            break
        fi
    done
    
    # 清空main_route路由表
    ip route flush table main_route >/dev/null 2>&1
    
    # 恢复内核参数
    echo -e "${yellow}正在恢复内核参数...${plain}"
    sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1
    
    # 检测主网卡并恢复其rp_filter
    local main_if=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {print $5}' | head -1)
    if [[ -n "$main_if" ]]; then
        sysctl -w net.ipv4.conf.${main_if}.rp_filter=1 >/dev/null 2>&1
    fi
    
    # 刷新路由缓存
    ip route flush cache >/dev/null 2>&1
    
    echo -e "${green}网络设置恢复完成！${plain}"
    echo -e "${yellow}正在验证网络连通性...${plain}"
    
    # 验证网络连通性
    local current_ip
    current_ip=$(timeout 10 curl -s ip.sb 2>/dev/null)
    if [[ -n "$current_ip" ]]; then
        echo -e "${green}✓ 网络连通性正常${plain}"
        echo -e "${green}✓ 当前外网IP: $current_ip${plain}"
    else
        echo -e "${yellow}正在尝试备用检测方法...${plain}"
        current_ip=$(timeout 10 curl -s ifconfig.me 2>/dev/null)
        if [[ -n "$current_ip" ]]; then
            echo -e "${green}✓ 网络连通性正常${plain}"
            echo -e "${green}✓ 当前外网IP: $current_ip${plain}"
        else
            echo -e "${red}! 无法获取外网IP，请手动检查网络连接${plain}"
        fi
    fi
    
    echo -e "\n${green}原始网络设置已恢复！${plain}"
    echo -e "${cyan}说明：${plain}"
    echo -e "• 所有VPN连接已断开"
    echo -e "• 策略路由规则已清理"
    echo -e "• 网络设置已恢复到初始状态"
    echo -e "• SSH连接应该保持正常"
}

# 创建网络监控脚本
create_network_monitor() {
    local monitor_script="/usr/local/bin/openvpn-monitor.sh"
    
    echo -e "${yellow}正在创建网络监控脚本...${plain}"
    
    cat << 'EOF' > "$monitor_script"
#!/bin/bash

# OpenVPN网络监控和自动恢复脚本
# 当VPN断线时自动恢复原始网络设置

# 配置参数
CHECK_INTERVAL=30  # 检查间隔（秒）
RETRY_COUNT=3      # 重试次数
LOG_FILE="/var/log/openvpn-monitor.log"
TABLE_ID="main_route"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 日志函数
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# 检查网络连通性
check_network() {
    local test_urls=("8.8.8.8" "1.1.1.1" "114.114.114.114")
    local success=0
    
    for url in "${test_urls[@]}"; do
        if ping -c 1 -W 3 "$url" >/dev/null 2>&1; then
            success=1
            break
        fi
    done
    
    return $((1 - success))
}

# 检查OpenVPN服务状态
check_openvpn_service() {
    local services=$(systemctl list-units --type=service --state=active | grep -E "openvpn|openvpn-client" | awk '{print $1}')
    
    if [[ -z "$services" ]]; then
        return 1  # 没有活动的OpenVPN服务
    fi
    
    for service in $services; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            return 0  # 至少有一个服务是活动的
        fi
    done
    
    return 1  # 所有服务都不活动
}

# 恢复原始网络设置
restore_network() {
    log_message "INFO" "开始恢复原始网络设置..."
    
    # 停止OpenVPN服务
    systemctl stop openvpn-client@*.service >/dev/null 2>&1
    systemctl stop openvpn@*.service >/dev/null 2>&1
    
    # 获取主网卡和服务器IP
    local main_if=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {print $5}' | head -1)
    local server_ip=""
    if [[ -n "$main_if" ]]; then
        server_ip=$(ip -4 addr show "$main_if" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    fi
    
    # 删除源地址策略路由规则
    if [[ -n "$server_ip" ]]; then
        log_message "INFO" "清理服务器IP($server_ip)的策略路由规则"
        ip rule delete from "${server_ip}/32" table "$TABLE_ID" prio 100 >/dev/null 2>&1
    fi
    
    # 清理所有main_route相关的策略路由规则
    while ip rule list | grep -q "$TABLE_ID"; do
        local rule_prio=$(ip rule list | grep "$TABLE_ID" | head -1 | awk '{print $1}' | tr -d ':')
        if [[ -n "$rule_prio" ]]; then
            ip rule del prio "$rule_prio" >/dev/null 2>&1
        else
            break
        fi
    done
    
    # 清空路由表
    ip route flush table "$TABLE_ID" >/dev/null 2>&1
    
    # 恢复内核参数
    sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1
    
    # 检测主网卡并恢复其rp_filter
    if [[ -n "$main_if" ]]; then
        sysctl -w net.ipv4.conf.${main_if}.rp_filter=1 >/dev/null 2>&1
    fi
    
    # 刷新路由缓存
    ip route flush cache >/dev/null 2>&1
    
    log_message "INFO" "网络设置恢复完成"
}

# 主监控循环
main_monitor() {
    log_message "INFO" "OpenVPN网络监控服务启动"
    
    while true; do
        # 检查OpenVPN服务是否运行
        if check_openvpn_service; then
            # OpenVPN服务正在运行，检查网络连通性
            local retry=0
            local network_ok=0
            
            while [[ $retry -lt $RETRY_COUNT ]]; do
                if check_network; then
                    network_ok=1
                    break
                fi
                retry=$((retry + 1))
                sleep 5
            done
            
            if [[ $network_ok -eq 0 ]]; then
                log_message "ERROR" "网络连通性检查失败，执行自动恢复"
                restore_network
                
                # 验证恢复后的网络连通性
                sleep 10
                if check_network; then
                    log_message "INFO" "网络恢复成功"
                else
                    log_message "ERROR" "网络恢复失败，请手动检查"
                fi
            fi
        fi
        
        sleep "$CHECK_INTERVAL"
    done
}

# 检查是否以root权限运行
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}错误：此脚本必须以root权限运行${NC}"
    exit 1
fi

# 创建日志文件
touch "$LOG_FILE"

# 启动监控
main_monitor
EOF
    
    chmod +x "$monitor_script"
    echo -e "${green}网络监控脚本已创建：$monitor_script${plain}"
    
    # 创建systemd服务文件
    local service_file="/etc/systemd/system/openvpn-monitor.service"
    
    cat << EOF > "$service_file"
[Unit]
Description=OpenVPN Network Monitor
After=network.target

[Service]
Type=simple
ExecStart=$monitor_script
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    echo -e "${green}监控服务已创建：openvpn-monitor.service${plain}"
    echo -e "${yellow}使用以下命令管理监控服务：${plain}"
    echo -e "• 启动监控：${cyan}systemctl start openvpn-monitor${plain}"
    echo -e "• 停止监控：${cyan}systemctl stop openvpn-monitor${plain}"
    echo -e "• 开机自启：${cyan}systemctl enable openvpn-monitor${plain}"
    echo -e "• 查看日志：${cyan}tail -f /var/log/openvpn-monitor.log${plain}"
}

# 查看OpenVPN连接状态和日志
view_openvpn_status() {
    echo -e "${green}=== OpenVPN 连接状态和日志查看 ===${plain}"
    
    # 检查是否有运行中的OpenVPN服务
    local openvpn_services=($(systemctl list-units --type=service --state=active | grep -E "openvpn|openvpn-client" | awk '{print $1}' | head -10))
    
    if [[ ${#openvpn_services[@]} -eq 0 ]]; then
        echo -e "${yellow}未发现运行中的OpenVPN服务${plain}"
        
        # 查找所有OpenVPN配置
        local all_services=($(systemctl list-unit-files | grep -E "openvpn.*\.service" | awk '{print $1}' | head -10))
        
        if [[ ${#all_services[@]} -eq 0 ]]; then
            echo -e "${red}系统中没有找到任何OpenVPN服务配置${plain}"
            return 1
        else
            echo -e "\n${cyan}找到以下OpenVPN服务（未运行）：${plain}"
            for i in "${!all_services[@]}"; do
                local service_name="${all_services[i]}"
                local status=$(systemctl is-active "$service_name" 2>/dev/null)
                echo -e "  ${yellow}$((i+1)).${plain} $service_name (状态: ${red}$status${plain})"
            done
            
            echo -e "\n${yellow}您可以选择查看这些服务的状态和日志：${plain}"
            read -rp "请选择服务编号 [1-${#all_services[@]}] 或按回车返回: " choice
            
            if [[ -n "$choice" ]] && [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#all_services[@]}" ]]; then
                local selected_service="${all_services[$((choice-1))]}"
                show_service_details "$selected_service"
            fi
        fi
        return 0
    fi
    
    echo -e "${green}发现 ${#openvpn_services[@]} 个运行中的OpenVPN服务：${plain}"
    
    # 显示运行中的服务列表
    for i in "${!openvpn_services[@]}"; do
        local service_name="${openvpn_services[i]}"
        local status=$(systemctl is-active "$service_name" 2>/dev/null)
        local uptime=$(systemctl show "$service_name" --property=ActiveEnterTimestamp --value 2>/dev/null | cut -d' ' -f2-3)
        echo -e "  ${green}$((i+1)).${plain} $service_name (状态: ${green}$status${plain}, 启动: $uptime)"
    done
    
    # 如果只有一个服务，直接显示详情
    if [[ ${#openvpn_services[@]} -eq 1 ]]; then
        echo -e "\n${yellow}自动显示唯一服务的详细信息：${plain}"
        show_service_details "${openvpn_services[0]}"
    else
        # 让用户选择要查看的服务
        echo -e "\n${yellow}请选择要查看详细信息的服务：${plain}"
        read -rp "请选择服务编号 [1-${#openvpn_services[@]}]: " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#openvpn_services[@]}" ]]; then
            local selected_service="${openvpn_services[$((choice-1))]}"
            show_service_details "$selected_service"
        else
            echo -e "${red}无效选择${plain}"
            return 1
        fi
    fi
}

# 显示OpenVPN服务详细信息
show_service_details() {
    local service_name="$1"
    
    echo -e "\n${green}================= 服务详细信息 =================${plain}"
    echo -e "${cyan}服务名称：${plain}$service_name"
    
    # 显示服务状态
    echo -e "\n${yellow}1. 服务状态：${plain}"
    systemctl status "$service_name" --no-pager -l
    
    # 显示网络连接信息
    echo -e "\n${yellow}2. 网络连接状态：${plain}"
    
    # 检查tun接口
    local tun_interfaces=$(ip link show | grep -E "tun[0-9]+" | awk -F': ' '{print $2}' | cut -d'@' -f1)
    if [[ -n "$tun_interfaces" ]]; then
        echo -e "${green}检测到VPN网络接口：${plain}"
        for tun_if in $tun_interfaces; do
            local tun_ip=$(ip addr show "$tun_if" 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
            echo -e "  • $tun_if: ${cyan}${tun_ip:-未分配IP}${plain}"
        done
    else
        echo -e "${red}未检测到VPN网络接口${plain}"
    fi
    
    # 检查外网IP
    echo -e "\n${yellow}3. 外网IP检测：${plain}"
    local current_ip
    echo -e "${cyan}正在检测当前外网IP...${plain}"
    current_ip=$(timeout 5 curl -s ip.sb 2>/dev/null)
    if [[ -n "$current_ip" ]]; then
        echo -e "${green}当前外网IP: $current_ip${plain}"
    else
        echo -e "${yellow}尝试备用检测...${plain}"
        current_ip=$(timeout 5 curl -s ifconfig.me 2>/dev/null)
        if [[ -n "$current_ip" ]]; then
            echo -e "${green}当前外网IP: $current_ip${plain}"
        else
            echo -e "${red}无法检测外网IP${plain}"
        fi
    fi
    
    # 检查策略路由状态
    echo -e "\n${yellow}4. 策略路由状态：${plain}"
    local route_rules=$(ip rule list | grep "main_route")
    if [[ -n "$route_rules" ]]; then
        echo -e "${green}策略路由规则已配置：${plain}"
        echo "$route_rules" | while read -r rule; do
            echo -e "  • $rule"
        done
        
        echo -e "\n${cyan}保留路由表内容：${plain}"
        ip route show table main_route 2>/dev/null | while read -r route; do
            echo -e "  • $route"
        done
    else
        echo -e "${yellow}未检测到策略路由规则${plain}"
    fi
    
    # 显示最近日志
    echo -e "\n${yellow}5. 最近50行日志：${plain}"
    echo -e "${cyan}==================== 日志开始 ====================${plain}"
    journalctl -u "$service_name" -n 50 --no-pager -o cat
    echo -e "${cyan}==================== 日志结束 ====================${plain}"
    
    # 提供操作选项
    echo -e "\n${yellow}可用操作：${plain}"
    echo -e "  ${cyan}1.${plain} 实时查看日志"
    echo -e "  ${cyan}2.${plain} 重启服务"
    echo -e "  ${cyan}3.${plain} 停止服务"
    echo -e "  ${cyan}4.${plain} 查看配置文件"
    echo -e "  ${cyan}5.${plain} 返回"
    
    read -rp "请选择操作 [1-5]: " action_choice
    
    case $action_choice in
        1)
            echo -e "${green}实时日志监控（按Ctrl+C退出）：${plain}"
            journalctl -u "$service_name" -f
            ;;
        2)
            echo -e "${yellow}正在重启服务...${plain}"
            if systemctl restart "$service_name"; then
                echo -e "${green}服务重启成功${plain}"
                sleep 2
                systemctl status "$service_name" --no-pager -l
            else
                echo -e "${red}服务重启失败${plain}"
            fi
            ;;
        3)
            read -rp "确认停止 $service_name 服务？(y/n): " confirm_stop
            if [[ "$confirm_stop" == [Yy] ]]; then
                echo -e "${yellow}正在停止服务...${plain}"
                if systemctl stop "$service_name"; then
                    echo -e "${green}服务已停止${plain}"
                else
                    echo -e "${red}停止服务失败${plain}"
                fi
            fi
            ;;
        4)
            show_openvpn_config "$service_name"
            ;;
        5)
            return 0
            ;;
        *)
            echo -e "${red}无效选择${plain}"
            ;;
    esac
}

# 显示OpenVPN配置文件
show_openvpn_config() {
    local service_name="$1"
    
    # 从服务名推断配置文件路径
    local config_name=""
    if [[ "$service_name" == openvpn-client@* ]]; then
        config_name=$(echo "$service_name" | sed 's/openvpn-client@\(.*\)\.service/\1/')
        local config_path="/etc/openvpn/client/${config_name}.conf"
    else
        config_name=$(echo "$service_name" | sed 's/openvpn@\(.*\)\.service/\1/')
        local config_path="/etc/openvpn/${config_name}.conf"
    fi
    
    echo -e "\n${yellow}OpenVPN配置文件：${plain}$config_path"
    
    if [[ -f "$config_path" ]]; then
        echo -e "${cyan}==================== 配置文件内容 ====================${plain}"
        cat "$config_path"
        echo -e "${cyan}==================== 配置文件结束 ====================${plain}"
        
        # 检查相关脚本
        local script_dir=$(dirname "$config_path")
        local up_script="$script_dir/route-up.sh"
        local down_script="$script_dir/route-down.sh"
        
        if [[ -f "$up_script" ]]; then
            echo -e "\n${yellow}route-up.sh 脚本存在：${plain}$up_script"
            echo -e "${cyan}脚本内容预览：${plain}"
            head -20 "$up_script"
        fi
        
        if [[ -f "$down_script" ]]; then
            echo -e "\n${yellow}route-down.sh 脚本存在：${plain}$down_script"
            echo -e "${cyan}脚本内容预览：${plain}"
            head -20 "$down_script"
        fi
    else
        echo -e "${red}配置文件不存在：$config_path${plain}"
    fi
}

############################################################
# 选项 10: 一键式OpenVPN策略路由设置
############################################################

setup_openvpn_routing() {
    echo -e "${green}=== 一键式OpenVPN策略路由设置 ===${plain}"
    
    echo -e "${yellow}此功能将帮助您设置OpenVPN策略路由，保持所有入站端口可访问${plain}"
    echo -e "${cyan}功能特性：${plain}"
    echo -e "  - 自动检测网络环境和服务器IP"
    echo -e "  - 基于源地址的策略路由（更稳定可靠）"
    echo -e "  - 保持所有入站端口（SSH、HTTP等）正常可访问"
    echo -e "  - 服务器主动发起的流量通过VPN出站"
    echo -e "  - 无需复杂的iptables规则，兼容性更好"
    echo -e "  - ${green}VPN断线自动恢复原始网络设置${plain}"
    
    echo -e "\n${yellow}请选择操作模式：${plain}"
    echo -e "  ${cyan}1.${plain} 新建OpenVPN配置 (默认)"
    echo -e "  ${cyan}2.${plain} 修改现有OpenVPN配置"
    echo -e "  ${cyan}3.${plain} 恢复原始网络设置 (清理所有VPN路由)"
    echo -e "  ${cyan}4.${plain} 查看OpenVPN连接状态和日志"
    
    local operation_mode
    read -rp "请选择操作模式 [1-4] (默认1): " operation_mode
    
    # 如果用户直接按回车，使用默认值1
    if [[ -z "$operation_mode" ]]; then
        operation_mode="1"
        echo -e "${green}使用默认模式: 新建OpenVPN配置${plain}"
    fi
    
    case $operation_mode in
        1)
            echo -e "\n${green}选择模式: 新建OpenVPN配置${plain}"
            ;;
        2)
            echo -e "\n${green}选择模式: 修改现有OpenVPN配置${plain}"
            ;;
        3)
            echo -e "\n${green}选择模式: 恢复原始网络设置${plain}"
            restore_original_network
            return 0
            ;;
        4)
            echo -e "\n${green}选择模式: 查看OpenVPN连接状态和日志${plain}"
            view_openvpn_status
            return 0
            ;;
        *)
            echo -e "${red}无效选择，使用默认模式: 新建OpenVPN配置${plain}"
            operation_mode="1"
            ;;
    esac
    
    read -rp "确认执行OpenVPN策略路由设置？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}设置已取消${plain}"
        return 0
    fi
    
    echo -e "\n${green}开始执行OpenVPN策略路由设置脚本...${plain}"
    
    # 创建临时脚本文件
    local temp_script="/tmp/openvpn_routing_setup.sh"
    
    cat << 'EOF' > "$temp_script"
#!/bin/bash

# ==============================================================================
#  一键式 OpenVPN 策略路由设置脚本 (版本 2)
#  功能:
#  1. 提示用户输入文件名并直接粘贴OpenVPN配置内容。
#  2. 自动检测网络环境 (网关, 网卡)。
#  3. 创建独立的路由表以保留 SSH 连接。
#  4. 生成 route-up.sh 和 route-down.sh 脚本。
#  5. 修改 OpenVPN 客户端配置以启用策略路由。
#  6. 所有出站流量将通过 VPN，但 SSH 连接将保持直连。
# ==============================================================================

# --- 变量和颜色定义 ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- 核心函数 ---

# 检查脚本是否以 root 权限运行
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误：此脚本必须以 root 权限运行。请使用 'sudo ./setup_vpn_routing_v2.sh'。${NC}"
        exit 1
    fi
}

# 自动安装缺失的依赖
install_dependencies() {
    echo -e "${YELLOW}正在自动安装缺失的依赖项...${NC}"
    
    # 检测系统类型
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu系统
        echo -e "${GREEN}检测到Debian/Ubuntu系统，使用apt-get安装依赖${NC}"
        apt-get update -y
        apt-get install -y openvpn iptables iproute2
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL系统
        echo -e "${GREEN}检测到CentOS/RHEL系统，使用yum安装依赖${NC}"
        yum install -y epel-release
        yum install -y openvpn iptables iproute
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora系统
        echo -e "${GREEN}检测到Fedora系统，使用dnf安装依赖${NC}"
        dnf install -y openvpn iptables iproute
    elif command -v pacman >/dev/null 2>&1; then
        # Arch Linux系统
        echo -e "${GREEN}检测到Arch Linux系统，使用pacman安装依赖${NC}"
        pacman -Sy --noconfirm openvpn iptables iproute2
    elif command -v apk >/dev/null 2>&1; then
        # Alpine Linux系统
        echo -e "${GREEN}检测到Alpine Linux系统，使用apk安装依赖${NC}"
        apk update
        apk add openvpn iptables iproute2
    else
        echo -e "${RED}无法检测到支持的包管理器，请手动安装依赖：openvpn iptables iproute2${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}依赖安装完成${NC}"
}

# 检查所需的依赖命令
check_dependencies() {
    echo -e "${YELLOW}正在检查依赖项...${NC}"
    local missing_deps=0
    local missing_packages=()
    
    for cmd in openvpn iptables ip; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}  -> 依赖 '$cmd' 未找到${NC}"
            missing_deps=1
            missing_packages+=("$cmd")
        else
            echo -e "${GREEN}  -> 依赖 '$cmd' 已找到${NC}"
        fi
    done

    if [ "$missing_deps" -eq 1 ]; then
        echo -e "${YELLOW}发现缺失的依赖项: ${missing_packages[*]}${NC}"
        read -p "$(echo -e ${YELLOW}"是否自动安装缺失的依赖项？(y/n): "${NC})" auto_install
        
        if [[ "$auto_install" == [Yy] ]]; then
            install_dependencies
            
            # 再次检查依赖是否安装成功
            echo -e "${YELLOW}验证依赖安装结果...${NC}"
            for cmd in openvpn iptables ip; do
                if ! command -v "$cmd" &> /dev/null; then
                    echo -e "${RED}  -> 依赖 '$cmd' 安装失败${NC}"
                    echo -e "${RED}请手动安装后重试${NC}"
                    exit 1
                else
                    echo -e "${GREEN}  -> 依赖 '$cmd' 安装成功${NC}"
                fi
            done
        else
            echo -e "${RED}请手动安装缺失的依赖项后重试${NC}"
            echo -e "${YELLOW}安装命令示例：${NC}"
            echo -e "${CYAN}  Ubuntu/Debian: sudo apt-get update && sudo apt-get install openvpn iptables iproute2${NC}"
            echo -e "${CYAN}  CentOS/RHEL: sudo yum install epel-release && sudo yum install openvpn iptables iproute${NC}"
            echo -e "${CYAN}  Fedora: sudo dnf install openvpn iptables iproute${NC}"
            exit 1
        fi
    fi
}

# 自动检测默认网关和主网卡
get_network_info() {
    echo -e "${YELLOW}正在自动检测网络信息...${NC}"
    local route_info
    route_info=$(ip route get 8.8.8.8)

    GATEWAY_IP=$(echo "$route_info" | awk '/via/ {print $3}')
    MAIN_IF=$(echo "$route_info" | awk '/dev/ {print $5}')

    if [ -z "$GATEWAY_IP" ] || [ -z "$MAIN_IF" ]; then
        echo -e "${RED}错误：无法自动检测到默认网关或主网卡。请检查您的网络配置。${NC}"
        exit 1
    fi
    echo -e "${GREEN}  -> 检测到原始默认网关 (Gateway): ${GATEWAY_IP}${NC}"
    echo -e "${GREEN}  -> 检测到主网卡名称 (Interface): ${MAIN_IF}${NC}"
}

# 【已优化】提示用户输入文件名并直接粘贴配置内容
get_ovpn_config() {
    OVPN_CLIENT_DIR="/etc/openvpn/client"
    mkdir -p "$OVPN_CLIENT_DIR"
    
    # 选择输入方式
    echo -e "${yellow}请选择配置来源：${plain}"
    echo -e "  ${cyan}1.${plain} 粘贴配置内容 (默认)"
    echo -e "  ${cyan}2.${plain} 读取服务器上已有的 .conf/.ovpn 文件"
    local cfg_mode
    read -rp "请选择 [1-2] (默认1): " cfg_mode
    [[ -z "$cfg_mode" ]] && cfg_mode="1"

    local OVPN_FILENAME
    while true; do
        read -p "$(echo -e ${YELLOW}"请输入生成的配置文件名 (默认: my-vpn.conf): "${NC})" OVPN_FILENAME
        [[ -z "$OVPN_FILENAME" ]] && OVPN_FILENAME="my-vpn.conf"
        if [[ "$OVPN_FILENAME" =~ \.conf$ || "$OVPN_FILENAME" =~ \.ovpn$ ]]; then
            break
        else
            echo -e "${RED}文件名必须以 .conf 或 .ovpn 结尾${NC}"
        fi
    done

    OVPN_CONFIG_FILE="$OVPN_CLIENT_DIR/$OVPN_FILENAME"
    OVPN_SERVICE_NAME=$(basename "$OVPN_FILENAME" | sed 's/\.conf$//' | sed 's/\.ovpn$//')

    if [[ "$cfg_mode" == "2" ]]; then
        # 读取现有文件
        read -rp "请输入现有 .conf/.ovpn 文件的完整路径: " src_path
        if [[ ! -f "$src_path" ]]; then
            echo -e "${red}错误：文件不存在${NC}"
            exit 1
        fi
        cp "$src_path" "$OVPN_CONFIG_FILE"
        echo -e "${green}已复制配置文件到: $OVPN_CONFIG_FILE${NC}"
    else
        # 粘贴模式
        echo -e "${YELLOW}请粘贴您的 OpenVPN 配置，完成后按 Ctrl+D 结束输入${NC}"
        echo -e "${cyan}(提示：若 60 秒内无输入，将取消操作)${plain}"
        local OVPN_CONTENT=""
        local start_ts=$(date +%s)
        while IFS= read -r -t 10 line; do
            OVPN_CONTENT+="$line\n"
            start_ts=$(date +%s) # 重置计时器
        done
        # 超时检测
        local now_ts=$(date +%s)
        if [[ -z "$OVPN_CONTENT" ]]; then
            echo -e "${red}60 秒内未接收到任何内容，已取消${NC}"
            exit 1
        fi
        # 写入
        printf "%b" "$OVPN_CONTENT" > "$OVPN_CONFIG_FILE.tmp"
        mv "$OVPN_CONFIG_FILE.tmp" "$OVPN_CONFIG_FILE"
    fi

    # 在顶部追加加密算法行（若尚未添加）
    if ! grep -q "^data-ciphers" "$OVPN_CONFIG_FILE"; then
        sed -i '1i # 放在 client 配置最顶部\ndata-ciphers          AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC\ndata-ciphers-fallback AES-128-CBC\n' "$OVPN_CONFIG_FILE"
    fi

    echo -e "${green}  -> 配置文件准备完成: $OVPN_CONFIG_FILE${NC}"
}


# 设置独立的路由表
setup_routing_table() {
    echo -e "${YELLOW}正在配置路由表 /etc/iproute2/rt_tables...${NC}"
    if ! grep -q "main_route" /etc/iproute2/rt_tables; then
        echo "100   main_route" >> /etc/iproute2/rt_tables
        echo -e "${GREEN}  -> 已添加路由表 '100 main_route'。${NC}"
    else
        echo -e "${GREEN}  -> 路由表 'main_route' 已存在，无需修改。${NC}"
    fi
}

# 创建 route-up 和 route-down 脚本
create_route_scripts() {
    local script_dir="$OVPN_CLIENT_DIR"
    local up_script="$script_dir/route-up.sh"
    local down_script="$script_dir/route-down.sh"

    echo -e "${YELLOW}正在创建优化的 route-up.sh 脚本（基于源地址策略路由）...${NC}"
    cat << EOL > "$up_script"
#!/bin/bash
# -- 根据您的环境自动填充的变量 --
GATEWAY_IP="${GATEWAY_IP}"
MAIN_IF="${MAIN_IF}"
# -- 配置参数 --
TABLE_ID="main_route"

# 等待网络接口就绪
sleep 5

# --- 第1部分：确保内核参数允许策略路由 ---
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
sysctl -w net.ipv4.conf.\${MAIN_IF}.rp_filter=2

# --- 第2部分：获取服务器公网IP ---
SERVER_IP=\$(ip -4 addr show \${MAIN_IF} | awk '/inet /{print \$2}' | cut -d/ -f1 | head -1)
if [[ -z "\$SERVER_IP" ]]; then
    echo "错误：无法获取服务器IP地址"
    exit 1
fi
echo "检测到服务器IP: \$SERVER_IP"

# --- 第3部分：配置策略路由 ---
# 创建保留路由表，所有流量通过原网关
ip route replace default via \${GATEWAY_IP} dev \${MAIN_IF} table \${TABLE_ID}

# 源地址策略：凡是源为公网IP的包一律走保留表
# 这确保所有入站连接的回复都通过原网关返回
ip rule add from \${SERVER_IP}/32 table \${TABLE_ID} prio 100

# --- 第4部分：刷新路由缓存 ---
ip route flush cache

echo "策略路由设置完成："
echo "- 服务器IP: \$SERVER_IP"
echo "- 所有从 \$SERVER_IP 发出的流量将通过原网关(\${GATEWAY_IP})路由"
echo "- 其他流量将通过VPN路由"

exit 0
EOL
    echo -e "${GREEN}  -> 脚本 '$up_script' 已创建。${NC}"

    echo -e "${YELLOW}正在创建优化的 route-down.sh 脚本...${NC}"
    cat << EOL > "$down_script"
#!/bin/bash
# -- 根据您的环境自动填充的变量 --
MAIN_IF="${MAIN_IF}"
TABLE_ID="main_route"

# --- 获取服务器公网IP ---
SERVER_IP=\$(ip -4 addr show \${MAIN_IF} | awk '/inet /{print \$2}' | cut -d/ -f1 | head -1)

# --- 清除策略路由规则 ---
if [[ -n "\$SERVER_IP" ]]; then
    ip rule delete from \${SERVER_IP}/32 table \${TABLE_ID} prio 100 2>/dev/null
    echo "已删除源地址策略路由规则: \$SERVER_IP"
fi

# 清空路由表
ip route flush table \${TABLE_ID} 2>/dev/null

# --- 恢复内核默认值 ---
sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1
sysctl -w net.ipv4.conf.\${MAIN_IF}.rp_filter=1 >/dev/null 2>&1

# 刷新路由缓存
ip route flush cache

echo "网络设置已恢复到原始状态"
exit 0
EOL
    echo -e "${GREEN}  -> 脚本 '$down_script' 已创建。${NC}"

    echo -e "${YELLOW}正在为脚本添加执行权限...${NC}"
    chmod +x "$up_script" "$down_script"
    echo -e "${GREEN}  -> 权限设置完成。${NC}"
}

# 修改 OpenVPN 配置文件
modify_ovpn_config() {
    echo -e "${YELLOW}正在修改 OpenVPN 配置文件: $OVPN_CONFIG_FILE...${NC}"

    # 1. 注释掉 redirect-gateway def1
    if grep -q "redirect-gateway def1" "$OVPN_CONFIG_FILE"; then
        sed -i 's/^\s*redirect-gateway def1/#redirect-gateway def1/' "$OVPN_CONFIG_FILE"
        echo -e "${GREEN}  -> 已注释掉 'redirect-gateway def1'。${NC}"
    else
        echo -e "${GREEN}  -> 'redirect-gateway def1' 未找到，无需注释。${NC}"
    fi

    # 2. 添加脚本指令
    local script_dir="$OVPN_CLIENT_DIR"
    
    # 删除旧的指令以防万一
    sed -i '/^script-security/d' "$OVPN_CONFIG_FILE"
    sed -i 's#^up .*##' "$OVPN_CONFIG_FILE"
    sed -i 's#^down .*##' "$OVPN_CONFIG_FILE"
    # 清理可能产生的空行
    sed -i '/^$/N;/^\n$/D' "$OVPN_CONFIG_FILE"


    # 添加新的指令到文件末尾
    cat << EOL >> "$OVPN_CONFIG_FILE"

# --- 由 setup_vpn_routing.sh 脚本自动添加 ---
script-security 2
up $script_dir/route-up.sh
down $script_dir/route-down.sh
EOL
    echo -e "${GREEN}  -> 已添加 script-security, up, 和 down 指令。${NC}"
}

# 自动重启OpenVPN服务并验证
restart_and_verify_openvpn() {
    echo -e "\n${GREEN}================= 配置完成! =================${NC}"
    echo -e "${YELLOW}所有配置已自动完成。正在自动重启 OpenVPN 服务...${NC}"
    
    # 停止可能正在运行的服务
    systemctl stop openvpn-client@${OVPN_SERVICE_NAME}.service >/dev/null 2>&1
    
    # 重新加载systemd配置
    systemctl daemon-reload
    
    # 启动OpenVPN服务
    echo -e "${YELLOW}正在启动 OpenVPN 服务: openvpn-client@${OVPN_SERVICE_NAME}.service${NC}"
    if systemctl start openvpn-client@${OVPN_SERVICE_NAME}.service; then
        echo -e "${GREEN}OpenVPN 服务启动成功${NC}"
    else
        echo -e "${RED}OpenVPN 服务启动失败，请检查配置${NC}"
        return 1
    fi
    
    echo -e "${yellow}实时输出 OpenVPN 日志 (15 秒)...${plain}"
    journalctl -fu openvpn-client@${OVPN_SERVICE_NAME}.service --since "now" &
    local jpid=$!
    sleep 15
    kill $jpid >/dev/null 2>&1
     
    # 检查服务状态
    echo -e "\n${YELLOW}检查服务状态:${NC}"
    systemctl status openvpn-client@${OVPN_SERVICE_NAME}.service --no-pager -l
    
    # 验证连接
    echo -e "\n${GREEN}================= 连接验证 =================${NC}"
    echo -e "${YELLOW}验证 SSH 连接状态:${NC}"
    if [[ -n "$SSH_CLIENT" ]]; then
        echo -e "${GREEN}✓ SSH 连接正常 (连接来源: ${SSH_CLIENT%% *})${NC}"
    else
        echo -e "${YELLOW}! 无法检测到 SSH 连接信息${NC}"
    fi
    
    echo -e "\n${YELLOW}检查当前外网IP地址:${NC}"
    local current_ip
    current_ip=$(timeout 10 curl -s ip.sb)
    if [[ -n "$current_ip" ]]; then
        echo -e "${GREEN}当前外网IP: $current_ip${NC}"
        echo -e "${CYAN}如果这是您的 VPN 服务器 IP，说明 VPN 连接成功${NC}"
    else
        echo -e "${YELLOW}无法获取外网IP，尝试备用方法...${NC}"
        current_ip=$(timeout 10 curl -s ifconfig.me)
        if [[ -n "$current_ip" ]]; then
            echo -e "${GREEN}当前外网IP: $current_ip${NC}"
            echo -e "${CYAN}如果这是您的 VPN 服务器 IP，说明 VPN 连接成功${NC}"
        else
            echo -e "${RED}无法获取外网IP地址，请手动检查网络连接${NC}"
        fi
    fi
    
    echo -e "\n${GREEN}================= 验证完成 =================${NC}"
    echo -e "${YELLOW}说明:${NC}"
    echo -e "1. ${GREEN}您的 SSH 连接应该没有断开${NC}"
    echo -e "2. ${GREEN}显示的IP应该是您的 VPN 服务器 IP${NC}"
    echo -e "3. ${CYAN}可以从其他机器 ping 您的服务器公网 IP 来验证连通性${NC}"
    echo -e "\n${YELLOW}管理命令:${NC}"
    echo -e "• 查看服务状态: ${CYAN}sudo systemctl status openvpn-client@${OVPN_SERVICE_NAME}.service${NC}"
    echo -e "• 停止服务: ${CYAN}sudo systemctl stop openvpn-client@${OVPN_SERVICE_NAME}.service${NC}"
    echo -e "• 重启服务: ${CYAN}sudo systemctl restart openvpn-client@${OVPN_SERVICE_NAME}.service${NC}"
    echo -e "• 查看日志: ${CYAN}sudo journalctl -u openvpn-client@${OVPN_SERVICE_NAME}.service -f${NC}"
}

# 选择现有配置文件
select_existing_config() {
    OVPN_CLIENT_DIR="/etc/openvpn/client"
    
    if [[ ! -d "$OVPN_CLIENT_DIR" ]]; then
        echo -e "\${RED}错误：OpenVPN客户端目录不存在: $OVPN_CLIENT_DIR\${NC}"
        exit 1
    fi
    
    # 查找现有的配置文件
    local config_files=()
    while IFS= read -r -d '' file; do
        config_files+=("$(basename "$file")")
    done < <(find "$OVPN_CLIENT_DIR" -name "*.conf" -o -name "*.ovpn" -print0 2>/dev/null)
    
    if [[ ${#config_files[@]} -eq 0 ]]; then
        echo -e "\${RED}错误：在 $OVPN_CLIENT_DIR 中未找到任何 .conf 或 .ovpn 配置文件\${NC}"
        echo -e "\${YELLOW}请先使用模式1创建配置文件，或手动放置配置文件到该目录\${NC}"
        exit 1
    fi
    
    echo -e "\${YELLOW}找到以下配置文件：\${NC}"
    for i in "${!config_files[@]}"; do
        echo -e "  \${CYAN}$((i+1)).  ${config_files[i]}\${NC}"
    done
    
    local choice
    while true; do
        read -p "$(echo -e \${YELLOW}"请选择要修改的配置文件 [1-${#config_files[@]}]: "\${NC})" choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#config_files[@]}" ]]; then
            break
        else
            echo -e "\${RED}无效选择，请输入 1-${#config_files[@]} 之间的数字\${NC}"
        fi
    done
    
    local selected_file="${config_files[$((choice-1))]}"
    OVPN_CONFIG_FILE="$OVPN_CLIENT_DIR/$selected_file"
    OVPN_SERVICE_NAME=$(basename "$selected_file" | sed 's/\.conf$//' | sed 's/\.ovpn$//')
    
    echo -e "\${GREEN}  -> 选择的配置文件: $OVPN_CONFIG_FILE\${NC}"
    echo -e "\${GREEN}  -> 对应的服务名: $OVPN_SERVICE_NAME\${NC}"
}

# --- 主逻辑 ---
main() {
    local operation_mode="\$1"
    
    echo -e "\${GREEN}====================================================\${NC}"
    echo -e "\${GREEN}  OpenVPN 保留 SSH 策略路由一键配置脚本 (v2)  \${NC}"
    echo -e "\${GREEN}====================================================\${NC}"
    
    check_root
    check_dependencies
    get_network_info
    
    if [[ "\$operation_mode" == "2" ]]; then
        # 模式2: 修改现有配置
        echo -e "\${YELLOW}模式2: 修改现有配置文件\${NC}"
        select_existing_config
    else
        # 模式1: 新建配置 (默认)
        echo -e "\${YELLOW}模式1: 新建配置文件\${NC}"
        get_ovpn_config
    fi
    
    setup_routing_table
    create_route_scripts
    modify_ovpn_config
    restart_and_verify_openvpn
}

# 执行主函数，传入操作模式参数
main "$operation_mode"
EOF
    
    # 设置脚本执行权限
    chmod +x "$temp_script"
    
    # 执行脚本，传入操作模式参数
    bash "$temp_script" "$operation_mode"
    
    # 清理临时文件
    rm -f "$temp_script"
    
    echo -e "\n${green}OpenVPN策略路由设置完成！${plain}"
    
    # 询问用户是否要启动网络监控服务
    echo -e "\n${yellow}=== 网络监控服务设置 ===${plain}"
    echo -e "${cyan}推荐启用网络监控服务，当VPN断线时自动恢复原始网络设置${plain}"
    read -rp "是否创建并启动网络监控服务？(y/n): " enable_monitor
    
    if [[ "$enable_monitor" == [Yy] ]]; then
        create_network_monitor
        
        echo -e "\n${yellow}是否立即启动监控服务？${plain}"
        read -rp "启动监控服务？(y/n): " start_monitor
        
        if [[ "$start_monitor" == [Yy] ]]; then
            systemctl start openvpn-monitor
            systemctl enable openvpn-monitor
            echo -e "${green}✓ 网络监控服务已启动并设置为开机自启${plain}"
            echo -e "${cyan}监控日志：tail -f /var/log/openvpn-monitor.log${plain}"
        else
            echo -e "${yellow}监控服务已创建但未启动${plain}"
            echo -e "${cyan}手动启动：systemctl start openvpn-monitor${plain}"
        fi
    else
        echo -e "${yellow}跳过网络监控服务设置${plain}"
        echo -e "${cyan}如需手动恢复网络设置，请运行脚本选择选项10-3${plain}"
    fi
}

############################################################
# 选项 11: 安装3x-ui面板
############################################################

install_3xui() {
    echo -e "${green}=== 安装3x-ui面板 ===${plain}"
    
    echo -e "${yellow}3x-ui 是一个功能强大的多协议代理面板${plain}"
    echo -e "${cyan}功能特性：${plain}"
    echo -e "  - 支持多种协议 (VMess, VLESS, Trojan, Shadowsocks等)"
    echo -e "  - Web界面管理"
    echo -e "  - 流量统计和用户管理"
    echo -e "  - 自动续签SSL证书"
    echo -e "  - 订阅功能"
    echo -e "  - 系统状态监控"
    
    read -rp "确认安装3x-ui面板？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}安装已取消${plain}"
        return 0
    fi
    
    echo -e "\n${green}开始安装3x-ui面板...${plain}"
    echo -e "${yellow}注意：安装过程中请按照提示设置管理员账户和端口${plain}"
    
    # 执行3x-ui安装脚本
    bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
    
    echo -e "\n${green}3x-ui面板安装完成！${plain}"
    echo -e "${yellow}提示：${plain}"
    echo -e "  - 请记住安装过程中设置的管理员账户、密码和端口"
    echo -e "  - 默认访问地址: ${cyan}https://你的服务器IP:设置的端口${plain}"
    echo -e "  - 建议立即登录面板并配置SSL证书"
    echo -e "  - 可使用命令 ${cyan}x-ui${plain} 来管理面板"
}

############################################################
# 选项 14: 更新脚本到最新版本
############################################################

update_script() {
    echo -e "${green}=== 更新脚本到最新版本 ===${plain}"
    
    echo -e "${yellow}此功能将从GitHub仓库下载最新版本的脚本${plain}"
    echo -e "${cyan}更新源: https://github.com/Shannon-x/super-tool${plain}"
    
    read -rp "确认更新脚本到最新版本？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}更新已取消${plain}"
        return 0
    fi
    
    echo -e "\n${green}开始更新脚本...${plain}"
    
    # 获取当前脚本的完整路径
    local current_script=$(realpath "$0")
    local script_dir=$(dirname "$current_script")
    local script_name=$(basename "$current_script")
    local backup_name="${script_name}.backup.$(date +%Y%m%d_%H%M%S)"
    
    echo -e "${yellow}当前脚本路径: $current_script${plain}"
    
    # 备份当前脚本
    echo -e "${yellow}备份当前脚本...${plain}"
    if cp "$current_script" "$script_dir/$backup_name"; then
        echo -e "${green}备份成功: $script_dir/$backup_name${plain}"
    else
        echo -e "${red}备份失败，更新中止${plain}"
        return 1
    fi
    
    # 下载最新版本
    echo -e "${yellow}正在下载最新版本...${plain}"
    local temp_script="/tmp/super-tool-latest.sh"
    
    if curl -L -o "$temp_script" "https://raw.githubusercontent.com/Shannon-x/super-tool/master/super-tool.sh"; then
        echo -e "${green}下载成功${plain}"
    else
        echo -e "${red}下载失败，请检查网络连接${plain}"
        return 1
    fi
    
    # 检查下载的文件是否有效
    if [[ ! -s "$temp_script" ]]; then
        echo -e "${red}下载的文件为空，更新失败${plain}"
        rm -f "$temp_script"
        return 1
    fi
    
    # 检查语法
    echo -e "${yellow}检查新脚本语法...${plain}"
    if bash -n "$temp_script"; then
        echo -e "${green}语法检查通过${plain}"
    else
        echo -e "${red}新脚本语法检查失败，更新中止${plain}"
        rm -f "$temp_script"
        return 1
    fi
    
    # 替换当前脚本
    echo -e "${yellow}替换当前脚本...${plain}"
    if cp "$temp_script" "$current_script"; then
        chmod +x "$current_script"
        echo -e "${green}脚本更新成功！${plain}"
        
        # 检查新版本号
        echo -e "${yellow}检查新版本信息...${plain}"
        if grep -q "版本:" "$current_script"; then
            local new_version=$(grep "版本:" "$current_script" | head -1 | sed 's/.*版本: //' | sed 's/ *$//')
            echo -e "${green}新版本: $new_version${plain}"
        fi
        
        echo -e "\n${cyan}更新完成！${plain}"
        echo -e "${yellow}备份文件保存在: $script_dir/$backup_name${plain}"
        echo -e "${yellow}请重新运行脚本以使用最新版本${plain}"
        
        # 清理临时文件
        rm -f "$temp_script"
        
        # 提示用户重新运行
        read -rp "是否立即重新运行新版本脚本？(y/n): " restart
        if [[ "$restart" == [Yy] ]]; then
            echo -e "${green}正在重新运行脚本...${plain}"
            exec "$current_script"
        fi
    else
        echo -e "${red}替换脚本失败${plain}"
        rm -f "$temp_script"
        return 1
    fi
}

############################################################
# 选项 12: DD系统重装功能 (使用reinstall脚本)
############################################################

# 显示支持的系统列表
show_supported_systems() {
    echo -e "${green}=== 支持的系统列表 ===${plain}"
    echo -e "${cyan}1.  Anolis     ${plain}- 版本: 7, 8, 23"
    echo -e "${cyan}2.  Rocky      ${plain}- 版本: 8, 9, 10"
    echo -e "${cyan}3.  Oracle     ${plain}- 版本: 8, 9"
    echo -e "${cyan}4.  AlmaLinux  ${plain}- 版本: 8, 9, 10"
    echo -e "${cyan}5.  OpenCloudOS${plain}- 版本: 8, 9, 23"
    echo -e "${cyan}6.  CentOS     ${plain}- 版本: 9, 10"
    echo -e "${cyan}7.  Fedora     ${plain}- 版本: 41, 42"
    echo -e "${cyan}8.  NixOS      ${plain}- 版本: 25.05"
    echo -e "${cyan}9.  Debian     ${plain}- 版本: 9, 10, 11, 12"
    echo -e "${cyan}10. OpenSUSE   ${plain}- 版本: 15.6, tumbleweed"
    echo -e "${cyan}11. Alpine     ${plain}- 版本: 3.19, 3.20, 3.21, 3.22"
    echo -e "${cyan}12. OpenEuler  ${plain}- 版本: 20.03, 22.03, 24.03, 25.03"
    echo -e "${cyan}13. Ubuntu     ${plain}- 版本: 16.04, 18.04, 20.04, 22.04, 24.04, 25.04 [--minimal]"
    echo -e "${cyan}14. Kali       ${plain}- 最新版本"
    echo -e "${cyan}15. Arch       ${plain}- 最新版本"
    echo -e "${cyan}16. Gentoo     ${plain}- 最新版本"
    echo -e "${cyan}17. AOSC       ${plain}- 最新版本"
    echo -e "${cyan}18. FNOS       ${plain}- 最新版本"
    echo -e "${cyan}19. RedHat     ${plain}- 需要提供镜像URL"
}

# 获取系统选择
get_system_choice() {
    while true; do
        show_supported_systems
        echo -e "\n${yellow}请选择要安装的系统：${plain}"
        read -rp "输入系统编号 [1-19]: " sys_choice
        
        case $sys_choice in
            1) SYSTEM_NAME="anolis"; get_version_choice "7|8|23"; break ;;
            2) SYSTEM_NAME="rocky"; get_version_choice "8|9|10"; break ;;
            3) SYSTEM_NAME="oracle"; get_version_choice "8|9"; break ;;
            4) SYSTEM_NAME="almalinux"; get_version_choice "8|9|10"; break ;;
            5) SYSTEM_NAME="opencloudos"; get_version_choice "8|9|23"; break ;;
            6) SYSTEM_NAME="centos"; get_version_choice "9|10"; break ;;
            7) SYSTEM_NAME="fedora"; get_version_choice "41|42"; break ;;
            8) SYSTEM_NAME="nixos"; SYSTEM_VERSION="25.05"; break ;;
            9) SYSTEM_NAME="debian"; get_version_choice "9|10|11|12"; break ;;
            10) SYSTEM_NAME="opensuse"; get_version_choice "15.6|tumbleweed"; break ;;
            11) SYSTEM_NAME="alpine"; get_version_choice "3.19|3.20|3.21|3.22"; break ;;
            12) SYSTEM_NAME="openeuler"; get_version_choice "20.03|22.03|24.03|25.03"; break ;;
            13) SYSTEM_NAME="ubuntu"; get_ubuntu_version; break ;;
            14) SYSTEM_NAME="kali"; SYSTEM_VERSION=""; break ;;
            15) SYSTEM_NAME="arch"; SYSTEM_VERSION=""; break ;;
            16) SYSTEM_NAME="gentoo"; SYSTEM_VERSION=""; break ;;
            17) SYSTEM_NAME="aosc"; SYSTEM_VERSION=""; break ;;
            18) SYSTEM_NAME="fnos"; SYSTEM_VERSION=""; break ;;
            19) SYSTEM_NAME="redhat"; get_redhat_image; break ;;
            *)
                echo -e "${red}无效选择，请输入 1-19${plain}"
                ;;
        esac
    done
}

# 获取版本选择
get_version_choice() {
    local available_versions="$1"
    echo -e "\n${yellow}可用版本: ${cyan}$available_versions${plain}"
    while true; do
        read -rp "请输入版本号: " version_input
        if [[ "$available_versions" =~ $version_input ]]; then
            SYSTEM_VERSION="$version_input"
            break
        else
            echo -e "${red}无效版本，请从以下版本中选择: $available_versions${plain}"
        fi
    done
}

# 获取Ubuntu版本（支持--minimal选项）
get_ubuntu_version() {
    echo -e "\n${yellow}Ubuntu 可用版本: ${cyan}16.04, 18.04, 20.04, 22.04, 24.04, 25.04${plain}"
    while true; do
        read -rp "请输入Ubuntu版本号: " version_input
        if [[ "$version_input" =~ ^(16\.04|18\.04|20\.04|22\.04|24\.04|25\.04)$ ]]; then
            SYSTEM_VERSION="$version_input"
            
            echo -e "\n${yellow}是否安装最小化版本？${plain}"
            read -rp "安装最小化版本 (y/n): " minimal_choice
            if [[ "$minimal_choice" == [Yy] ]]; then
                UBUNTU_MINIMAL="--minimal"
            else
                UBUNTU_MINIMAL=""
            fi
            break
        else
            echo -e "${red}无效版本，请输入: 16.04, 18.04, 20.04, 22.04, 24.04, 25.04${plain}"
        fi
    done
}

# 获取RedHat镜像URL
get_redhat_image() {
    echo -e "\n${yellow}RedHat 系统需要提供镜像URL${plain}"
    echo -e "${cyan}示例: http://access.cdn.redhat.com/xxx.qcow2${plain}"
    while true; do
        read -rp "请输入RedHat镜像URL: " image_url
        if [[ -n "$image_url" && "$image_url" =~ ^https?:// ]]; then
            REDHAT_IMAGE="--img=\"$image_url\""
            SYSTEM_VERSION=""
            break
        else
            echo -e "${red}请输入有效的HTTP/HTTPS URL${plain}"
        fi
    done
}

# 设置root密码
set_root_password() {
    echo -e "\n${yellow}=== 设置root密码 ===${plain}"
    while true; do
        read -rsp "请输入root密码: " password1
        echo
        read -rsp "请再次确认密码: " password2
        echo
        
        if [[ "$password1" == "$password2" ]]; then
            if [[ ${#password1} -lt 6 ]]; then
                echo -e "${red}密码长度至少需要6位，请重新输入${plain}"
                continue
            fi
            ROOT_PASSWORD="$password1"
            echo -e "${green}密码设置成功${plain}"
            break
        else
            echo -e "${red}两次输入的密码不一致，请重新输入${plain}"
        fi
    done
}

# 设置SSH密钥
set_ssh_key() {
    echo -e "\n${yellow}=== SSH密钥设置 ===${plain}"
    echo -e "${cyan}支持的密钥格式：${plain}"
    echo -e "  - ssh-rsa ..."
    echo -e "  - ssh-ed25519 ..."
    echo -e "  - ecdsa-sha2-nistp256/384/521 ..."
    echo -e "  - http://path/to/public_key"
    echo -e "  - github:your_username"
    echo -e "  - gitlab:your_username"
    echo -e "  - /path/to/public_key"
    echo -e "  - C:\\path\\to\\public_key"
    
    read -rp "是否设置SSH密钥登录？(y/n): " use_ssh_key
    
    if [[ "$use_ssh_key" == [Yy] ]]; then
        echo -e "\n${yellow}请输入SSH公钥或路径：${plain}"
        read -rp "SSH密钥: " ssh_key_input
        
        if [[ -n "$ssh_key_input" ]]; then
            SSH_KEY="--ssh-key \"$ssh_key_input\""
            echo -e "${green}SSH密钥设置成功${plain}"
            echo -e "${yellow}注意: 使用SSH密钥时，root密码将为空${plain}"
        else
            echo -e "${red}SSH密钥不能为空${plain}"
            SSH_KEY=""
        fi
    else
        SSH_KEY=""
        echo -e "${yellow}跳过SSH密钥设置${plain}"
    fi
}

# 设置SSH端口
set_ssh_port() {
    echo -e "\n${yellow}=== SSH端口设置 ===${plain}"
    read -rp "是否修改SSH端口？(y/n): " change_port
    
    if [[ "$change_port" == [Yy] ]]; then
        while true; do
            read -rp "请输入SSH端口 (1-65535): " port_input
            if [[ "$port_input" =~ ^[0-9]+$ ]] && [ "$port_input" -ge 1 ] && [ "$port_input" -le 65535 ]; then
                SSH_PORT="--ssh-port $port_input"
                echo -e "${green}SSH端口设置为: $port_input${plain}"
                break
            else
                echo -e "${red}请输入有效的端口号 (1-65535)${plain}"
            fi
        done
    else
        SSH_PORT=""
        echo -e "${yellow}使用默认SSH端口 22${plain}"
    fi
}

# 下载reinstall脚本
download_reinstall_script() {
    echo -e "\n${green}正在下载reinstall脚本...${plain}"
    
    # 尝试curl，如果失败则尝试wget
    if command -v curl >/dev/null 2>&1; then
        if curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh; then
            echo -e "${green}✓ 使用curl下载成功${plain}"
            return 0
        else
            echo -e "${yellow}curl下载失败，尝试wget...${plain}"
        fi
    fi
    
    if command -v wget >/dev/null 2>&1; then
        if wget -O reinstall.sh https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh; then
            echo -e "${green}✓ 使用wget下载成功${plain}"
            return 0
        else
            echo -e "${red}wget下载失败${plain}"
            return 1
        fi
    fi
    
    echo -e "${red}错误：系统中未找到curl或wget命令${plain}"
    return 1
}

# 构建并执行重装命令
execute_reinstall() {
    echo -e "\n${green}=== 构建重装命令 ===${plain}"
    
    # 基础命令
    local cmd="bash reinstall.sh $SYSTEM_NAME"
    
    # 添加版本号（如果有）
    if [[ -n "$SYSTEM_VERSION" ]]; then
        cmd="$cmd $SYSTEM_VERSION"
    fi
    
    # 添加Ubuntu最小化选项
    if [[ -n "$UBUNTU_MINIMAL" ]]; then
        cmd="$cmd $UBUNTU_MINIMAL"
    fi
    
    # 添加RedHat镜像选项
    if [[ -n "$REDHAT_IMAGE" ]]; then
        cmd="$cmd $REDHAT_IMAGE"
    fi
    
    # 添加密码选项
    if [[ -n "$ROOT_PASSWORD" ]]; then
        cmd="$cmd --password \"$ROOT_PASSWORD\""
    fi
    
    # 添加SSH密钥选项
    if [[ -n "$SSH_KEY" ]]; then
        cmd="$cmd $SSH_KEY"
    fi
    
    # 添加SSH端口选项
    if [[ -n "$SSH_PORT" ]]; then
        cmd="$cmd $SSH_PORT"
    fi
    
    echo -e "${yellow}将要执行的命令：${plain}"
    echo -e "${cyan}$cmd${plain}"
    
    echo -e "\n${red}警告：此操作将完全重装系统，所有数据将被清除！${plain}"
    echo -e "${red}请确保您已备份重要数据！${plain}"
    echo -e "\n${yellow}系统: $SYSTEM_NAME${plain}"
    if [[ -n "$SYSTEM_VERSION" ]]; then
        echo -e "${yellow}版本: $SYSTEM_VERSION${plain}"
    fi
    if [[ -n "$SSH_KEY" ]]; then
        echo -e "${yellow}SSH密钥: 已设置${plain}"
    fi
    if [[ -n "$SSH_PORT" ]]; then
        echo -e "${yellow}SSH端口: 已设置${plain}"
    fi
    
    echo -e "\n${yellow}安装过程可能需要一段时间，请耐心等待...${plain}"
    echo -e "${yellow}安装期间请观察日志输出${plain}"
    
    read -rp "确认执行系统重装？(请输入 'YES' 确认): " final_confirm
    
    if [[ "$final_confirm" == "YES" ]]; then
        echo -e "\n${green}开始执行系统重装...${plain}"
        echo -e "${yellow}================================${plain}"
        
        # 执行重装命令
        eval $cmd
        
        echo -e "\n${yellow}================================${plain}"
        echo -e "${green}重装命令执行完成${plain}"
        echo -e "${yellow}请观察上方输出信息${plain}"
        
        # 清理脚本文件
        if [[ -f "reinstall.sh" ]]; then
            rm -f reinstall.sh
            echo -e "${green}已清理临时脚本文件${plain}"
        fi
    else
        echo -e "${red}重装已取消${plain}"
        # 清理脚本文件
        if [[ -f "reinstall.sh" ]]; then
            rm -f reinstall.sh
        fi
        return 1
    fi
}

# DD系统重装主函数
dd_system_reinstall() {
    echo -e "${green}=== DD系统重装功能 ===${plain}"
    echo -e "${yellow}此功能使用reinstall脚本重装系统${plain}"
    echo -e "${red}注意：此操作会完全清除当前系统，请谨慎使用！${plain}"
    
    read -rp "确认继续？(y/n): " continue_choice
    if [[ "$continue_choice" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 初始化变量
    SYSTEM_NAME=""
    SYSTEM_VERSION=""
    ROOT_PASSWORD=""
    SSH_KEY=""
    SSH_PORT=""
    UBUNTU_MINIMAL=""
    REDHAT_IMAGE=""
    
    # 步骤1: 选择系统
    echo -e "\n${green}步骤1: 选择要安装的系统${plain}"
    get_system_choice
    
    # 步骤2: 设置root密码
    echo -e "\n${green}步骤2: 设置root密码${plain}"
    set_root_password
    
    # 步骤3: 设置SSH密钥（可选）
    echo -e "\n${green}步骤3: 设置SSH密钥（可选）${plain}"
    set_ssh_key
    
    # 步骤4: 设置SSH端口（可选）
    echo -e "\n${green}步骤4: 设置SSH端口（可选）${plain}"
    set_ssh_port
    
    # 步骤5: 下载脚本
    echo -e "\n${green}步骤5: 下载reinstall脚本${plain}"
    if ! download_reinstall_script; then
        echo -e "${red}下载脚本失败，无法继续${plain}"
        return 1
    fi
    
    # 步骤6: 执行重装
    echo -e "\n${green}步骤6: 执行系统重装${plain}"
    execute_reinstall
}

############################################################
# 选项 13: 修改主机名与登录信息
############################################################

# 生成ASCII艺术字
generate_ascii_art() {
    # 彩色定义
    local RED='\033[1;31m'
    local GREEN='\033[1;32m'
    local YELLOW='\033[1;33m'
    local BLUE='\033[1;34m'
    local CYAN='\033[1;36m'
    local MAGENTA='\033[1;35m'
    local WHITE='\033[1;37m'
    local NC='\033[0m'
    
    echo -e "${CYAN}  █████╗ ██╗██████╗ ███████╗██╗   ██╗███████╗███████╗${NC}"
    echo -e "${CYAN} ██╔══██╗██║██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝${NC}"
    echo -e "${CYAN} ███████║██║██████╔╝███████╗██║   ██║█████╗  █████╗  ${NC}"
    echo -e "${CYAN} ██╔══██║██║██╔══██╗╚════██║██║   ██║██╔══╝  ██╔══╝  ${NC}"
    echo -e "${CYAN} ██║  ██║██║██║  ██║███████║╚██████╔╝██║     ███████╗${NC}"
    echo -e "${CYAN} ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝     ╚══════╝${NC}"
    echo -e "${WHITE}                                                     ${NC}"
    echo -e "${RED}苏菲家宽 - 极度纯净家宽网络${NC}"
    echo -e "${BLUE}AirSufe Network Service${NC}"
    echo -e "${MAGENTA}家宽主机：${CYAN}airsufe.com${NC}"
    echo -e "${MAGENTA}家宽代理：${CYAN}sufe.pro${NC}"
}

# 获取当前主机名信息
get_current_hostname_info() {
    echo -e "${green}=== 当前主机信息 ===${plain}"
    echo -e "${yellow}当前主机名: ${cyan}$(hostname)${plain}"
    echo -e "${yellow}完整主机名: ${cyan}$(hostname -f 2>/dev/null || hostname)${plain}"
    
    if [[ -f /etc/hostname ]]; then
        echo -e "${yellow}/etc/hostname: ${cyan}$(cat /etc/hostname)${plain}"
    fi
    
    echo -e "${yellow}/etc/hosts 内容:${plain}"
    if [[ -f /etc/hosts ]]; then
        echo -e "${cyan}$(cat /etc/hosts)${plain}"
    else
        echo -e "${red}/etc/hosts 文件不存在${plain}"
    fi
    
    echo -e "\n${yellow}当前登录信息 (/etc/motd):${plain}"
    if [[ -f /etc/motd ]]; then
        if [[ -s /etc/motd ]]; then
            echo -e "${cyan}$(cat /etc/motd)${plain}"
        else
            echo -e "${yellow}MOTD 文件为空${plain}"
        fi
    else
        echo -e "${yellow}MOTD 文件不存在${plain}"
    fi
}

# 验证主机名格式
validate_hostname() {
    local hostname="$1"
    
    # 检查长度
    if [[ ${#hostname} -gt 63 ]]; then
        echo -e "${red}错误：主机名长度不能超过63个字符${plain}"
        return 1
    fi
    
    # 检查格式
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$ ]]; then
        echo -e "${red}错误：主机名格式不正确${plain}"
        echo -e "${yellow}主机名规则：${plain}"
        echo -e "  - 只能包含字母、数字和连字符(-)"
        echo -e "  - 必须以字母或数字开头和结尾"
        echo -e "  - 不能连续出现连字符"
        return 1
    fi
    
    return 0
}

# 设置新主机名
set_new_hostname() {
    local new_hostname="$1"
    
    echo -e "\n${green}正在设置新主机名: ${cyan}$new_hostname${plain}"
    
    # 备份原有配置
    if [[ -f /etc/hostname ]]; then
        cp /etc/hostname /etc/hostname.backup.$(date +%Y%m%d_%H%M%S)
        echo -e "${green}已备份原 /etc/hostname${plain}"
    fi
    
    if [[ -f /etc/hosts ]]; then
        cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S)
        echo -e "${green}已备份原 /etc/hosts${plain}"
    fi
    
    # 设置新主机名
    echo "$new_hostname" > /etc/hostname
    
    # 立即应用主机名
    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl set-hostname "$new_hostname"
        echo -e "${green}✓ 使用 hostnamectl 设置主机名${plain}"
    else
        hostname "$new_hostname"
        echo -e "${green}✓ 使用 hostname 命令设置主机名${plain}"
    fi
    
    # 更新 /etc/hosts
    update_hosts_file "$new_hostname"
    
    echo -e "${green}✓ 主机名设置完成${plain}"
}

# 更新 /etc/hosts 文件
update_hosts_file() {
    local new_hostname="$1"
    
    echo -e "\n${green}正在更新 /etc/hosts 文件...${plain}"
    
    # 创建新的 hosts 文件内容
    local temp_hosts="/tmp/hosts.new"
    
    # 保留原有的非 127.0.0.1 和 ::1 条目，但移除旧主机名
    if [[ -f /etc/hosts ]]; then
        grep -v "^127\.0\.0\.1.*$(hostname)$" /etc/hosts | \
        grep -v "^::1.*$(hostname)$" > "$temp_hosts"
    fi
    
    # 确保包含基本的 localhost 条目
    if ! grep -q "^127\.0\.0\.1.*localhost" "$temp_hosts" 2>/dev/null; then
        echo "127.0.0.1    localhost" > "$temp_hosts.tmp"
        if [[ -f "$temp_hosts" ]]; then
            cat "$temp_hosts" >> "$temp_hosts.tmp"
        fi
        mv "$temp_hosts.tmp" "$temp_hosts"
    fi
    
    # 添加新主机名条目
    {
        echo "127.0.0.1    $new_hostname"
        echo "::1          $new_hostname"
    } >> "$temp_hosts"
    
    # 替换原文件
    mv "$temp_hosts" /etc/hosts
    
    echo -e "${green}✓ /etc/hosts 文件更新完成${plain}"
    echo -e "${yellow}新的 /etc/hosts 内容:${plain}"
    echo -e "${cyan}$(cat /etc/hosts)${plain}"
}

# 设置登录横幅
set_login_banner() {
    echo -e "\n${green}正在设置登录横幅...${plain}"
    
    # 备份原 MOTD
    if [[ -f /etc/motd ]]; then
        cp /etc/motd /etc/motd.backup.$(date +%Y%m%d_%H%M%S)
        echo -e "${green}已备份原 /etc/motd${plain}"
    fi
    
    # 生成新的 MOTD
    generate_ascii_art > /etc/motd
    
    # 添加系统信息（去除uname -o等内核行）
    cat >> /etc/motd << EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  欢迎使用 AirSufe 网络服务
  主机名: $(hostname)
  当前时间: $(date '+%Y-%m-%d %H:%M:%S %Z')
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
    
    echo -e "${green}✓ 登录横幅设置完成${plain}"
    echo -e "\n${yellow}新的登录横幅预览:${plain}"
    echo -e "${cyan}$(cat /etc/motd)${plain}"
}

# 主机名和登录信息修改主函数
modify_hostname_and_motd() {
    echo -e "${green}=== 修改主机名与登录信息 ===${plain}"
    echo -e "${yellow}此功能将帮助您修改服务器主机名并设置个性化登录信息${plain}"
    
    # 显示当前信息
    get_current_hostname_info
    
    echo -e "\n${yellow}是否继续修改主机名和登录信息？${plain}"
    read -rp "继续 (y/n): " continue_choice
    if [[ "$continue_choice" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 获取新主机名
    while true; do
        echo -e "\n${green}请输入新的主机名：${plain}"
        echo -e "${yellow}建议格式: 字母数字组合，如 vps-hk1, server-01, airsufe-node 等${plain}"
        read -rp "新主机名: " new_hostname
        
        if [[ -z "$new_hostname" ]]; then
            echo -e "${red}主机名不能为空${plain}"
            continue
        fi
        
        if validate_hostname "$new_hostname"; then
            break
        fi
    done
    
    echo -e "\n${yellow}=== 确认修改信息 ===${plain}"
    echo -e "${yellow}当前主机名: ${cyan}$(hostname)${plain}"
    echo -e "${yellow}新主机名: ${cyan}$new_hostname${plain}"
    echo -e "${yellow}登录横幅: ${cyan}AirSufe 苏菲家宽 ASCII 艺术字${plain}"
    
    read -rp "确认执行修改？(y/n): " confirm_change
    if [[ "$confirm_change" != [Yy] ]]; then
        echo -e "${yellow}修改已取消${plain}"
        return 0
    fi
    
    # 执行修改
    echo -e "\n${green}开始执行修改...${plain}"
    
    # 1. 设置主机名
    set_new_hostname "$new_hostname"
    
    # 2. 设置登录横幅
    set_login_banner
    
    echo -e "\n${green}✅ 主机名和登录信息修改完成！${plain}"
    echo -e "${yellow}修改内容：${plain}"
    echo -e "  ✓ 主机名已更改为: ${cyan}$new_hostname${plain}"
    echo -e "  ✓ 更新了 /etc/hostname"
    echo -e "  ✓ 更新了 /etc/hosts"
    echo -e "  ✓ 设置了 AirSufe 登录横幅"
    
    echo -e "\n${yellow}注意事项：${plain}"
    echo -e "  - 主机名修改立即生效"
    echo -e "  - 登录横幅在下次 SSH 登录时显示"
    echo -e "  - 原配置文件已自动备份"
    echo -e "  - 如需恢复，可使用备份文件"
    
    echo -e "\n${cyan}测试新设置：${plain}"
    echo -e "  当前主机名: ${green}$(hostname)${plain}"
    
    read -rp "是否立即测试显示登录横幅？(y/n): " show_banner
    if [[ "$show_banner" == [Yy] ]]; then
        echo -e "\n${green}=== 登录横幅预览 ===${plain}"
        cat /etc/motd
    fi
}

############################################################
# 安装Claude Code
############################################################

install_claude_code() {
    echo -e "${green}=== 安装Claude Code ===${plain}"
    
    # 步骤1：安装Node.js和npm
    echo -e "${yellow}步骤1：安装Node.js和npm${plain}"
    
    # 检测操作系统 - 使用更强大的检测逻辑
    local detected_os=""
    
    # 方法1：检查 /etc/os-release
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        detected_os=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        echo -e "${cyan}从 /etc/os-release 检测到: $detected_os${plain}"
    fi
    
    # 方法2：如果方法1失败，使用传统检测
    if [[ -z "$detected_os" ]]; then
        if [[ -f /etc/redhat-release ]]; then
            detected_os="centos"
        elif command -v apt-get &> /dev/null; then
            detected_os="debian"
        elif command -v yum &> /dev/null; then
            detected_os="centos"
        fi
        echo -e "${cyan}使用传统方法检测到: $detected_os${plain}"
    fi
    
    # 方法3：显示更多调试信息
    echo -e "${cyan}全局变量 release: '$release'${plain}"
    echo -e "${cyan}检测到的系统: '$detected_os'${plain}"
    
    # 统一处理不同的系统名称
    case "$detected_os" in
        "ubuntu"|"debian"|"linuxmint"|"pop"|"elementary")
            echo -e "${green}使用 Debian/Ubuntu 系列安装方法${plain}"
            if ! command -v node &> /dev/null; then
                echo -e "${cyan}正在安装Node.js和npm...${plain}"
                # 更新包列表
                apt-get update
                # 安装 curl 如果不存在
                apt-get install -y curl
                # 安装 Node.js
                curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
                apt-get install -y nodejs
            else
                echo -e "${green}Node.js已安装，版本: $(node --version)${plain}"
            fi
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"alma"|"oracle")
            echo -e "${green}使用 CentOS/RHEL 系列安装方法${plain}"
            if ! command -v node &> /dev/null; then
                echo -e "${cyan}正在安装Node.js和npm...${plain}"
                # 安装 curl 如果不存在
                yum install -y curl
                # 安装 Node.js
                curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash -
                yum install -y nodejs
            else
                echo -e "${green}Node.js已安装，版本: $(node --version)${plain}"
            fi
            ;;
        *)
            echo -e "${red}不支持的操作系统: '$detected_os'${plain}"
            echo -e "${yellow}支持的操作系统: Ubuntu, Debian, CentOS, RHEL, Fedora${plain}"
            echo -e "${yellow}如果您使用的是兼容系统，请联系脚本作者${plain}"
            
            # 显示系统信息帮助调试
            echo -e "\n${yellow}系统信息调试：${plain}"
            [[ -f /etc/os-release ]] && echo -e "${cyan}/etc/os-release 内容：${plain}" && cat /etc/os-release
            echo -e "${cyan}可用的包管理器：${plain}"
            command -v apt-get &> /dev/null && echo "  - apt-get: 可用"
            command -v yum &> /dev/null && echo "  - yum: 可用"
            command -v dnf &> /dev/null && echo "  - dnf: 可用"
            
            return 1
            ;;
    esac
    
    # 验证安装
    if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
        echo -e "${red}Node.js或npm安装失败${plain}"
        return 1
    fi
    
    echo -e "${green}Node.js版本: $(node --version)${plain}"
    echo -e "${green}npm版本: $(npm --version)${plain}"
    
    # 步骤2：安装Claude Code
    echo -e "\n${yellow}步骤2：安装Claude Code${plain}"
    echo -e "${cyan}正在安装@anthropic-ai/claude-code...${plain}"
    
    if npm install -g @anthropic-ai/claude-code; then
        echo -e "${green}Claude Code安装成功${plain}"
    else
        echo -e "${red}Claude Code安装失败${plain}"
        return 1
    fi
    
    # 步骤3：创建配置文件
    echo -e "\n${yellow}步骤3：创建配置文件${plain}"
    
    # 创建配置目录
    echo -e "${cyan}创建配置目录...${plain}"
    mkdir -p ~/.claude
    
    # 创建完整的配置文件
    echo -e "${cyan}创建配置文件...${plain}"
    cat > ~/.claude/settings.json << 'EOF'
{
  "env": {
    "ANTHROPIC_API_KEY": "test",
    "ANTHROPIC_BASE_URL": "https://claudeapi.848999.xyz"
  },
  "permissions": {
    "allow": [],
    "deny": []
  },
  "apiKeyHelper": "echo 'test'",
  "model": "opus"
}
EOF
    
    # 验证配置文件
    echo -e "\n${yellow}验证配置文件：${plain}"
    if [[ -f ~/.claude/settings.json ]]; then
        echo -e "${green}配置文件创建成功，内容如下：${plain}"
        cat ~/.claude/settings.json
    else
        echo -e "${red}配置文件创建失败${plain}"
        return 1
    fi
    
    # 启动Claude Code
    echo -e "\n${yellow}启动Claude Code${plain}"
    echo -e "${cyan}正在启动Claude Code...${plain}"
    echo -e "${green}Claude Code已安装并配置完成！${plain}"
    echo -e "${yellow}您可以通过以下命令启动Claude Code：${plain}"
    echo -e "${cyan}claude-code${plain}"
    
    read -rp "是否现在启动Claude Code？(y/n): " start_claude
    if [[ "$start_claude" == [Yy] ]]; then
        echo -e "${cyan}正在启动Claude Code...${plain}"
        claude-code
    fi
}

############################################################
# 主菜单和脚本执行逻辑
############################################################

show_menu() {
    echo -e "
  ${green}多功能服务器工具脚本 (v4.9)${plain}
  ---
  ${yellow}0.${plain} 退出脚本
      ${yellow}1.${plain} 端口转发管理 (设置/查看规则)
  ${yellow}2.${plain} 安装 / 更新 V2bX
  ${yellow}3.${plain} 为 Hysteria2 节点设置出站规则
  ${yellow}4.${plain} 为 vless/shadowsocks 节点配置出站规则
  ${yellow}5.${plain} 支付站点拦截管理 / shadowsocks节点安全
  ${yellow}6.${plain} 安装哪吒探针
  ${yellow}7.${plain} 安装1Panel管理面板
  ${yellow}8.${plain} 执行网络测速
  ${yellow}9.${plain} 设置isufe快捷命令
  ${yellow}10.${plain} 一键式OpenVPN策略路由设置 (含故障恢复)
  ${yellow}11.${plain} 安装3x-ui面板
  ${yellow}12.${plain} DD系统重装 (使用reinstall脚本)
  ${yellow}13.${plain} 修改主机名与登录信息
  ${yellow}14.${plain} 安装Claude Code
  ${yellow}15.${plain} 服务器基本设置 (SSH/Fail2ban/更新/Swap)
  ${yellow}16.${plain} 防止谷歌送中
  ${yellow}17.${plain} 增加V2bX节点
  ${yellow}18.${plain} 更新脚本到最新版本
  ${yellow}19.${plain} 删除脚本并卸载isufe快捷命令
  ---"
    read -rp "请输入选项 [0-19]: " choice
    
    case $choice in
        0)
            exit 0
            ;;
        1)
            port_forwarding_menu
            ;;
        2)
            run_v2bx_installer
            ;;
        3)
            setup_hy2_outbound
            ;;
        4)
            setup_vless_ss_outbound
            ;;
        5)
            # 提供子选项：查看状态、移除拦截、为SS节点添加中国大陆禁止规则，或修复inboundTag
            echo -e "\n${yellow}支付站点拦截管理与shadowsocks节点安全：${plain}"
            echo -e "  ${cyan}1.${plain} 查看当前拦截状态"
            echo -e "  ${cyan}2.${plain} 移除银行和支付站点拦截规则"
            echo -e "  ${cyan}3.${plain} 检查shadowsocks节点并添加中国大陆禁止规则"
            echo -e "  ${cyan}4.${plain} 修复路由配置中的inboundTag格式问题"
            read -rp "请选择操作 [1-4]: " payment_choice
            
            case $payment_choice in
                1)
                    show_payment_block_status
                    ;;
                2)
                    remove_payment_blocks
                    ;;
                3)
                    check_and_block_ss_china
                    ;;
                4)
                    fix_inbound_tags
                    ;;
                *)
                    echo -e "${red}无效的选择${plain}"
                    ;;
            esac
            ;;
        6)
            install_nezha_agent
            ;;
        7)
            install_1panel
            ;;
        8)
            run_network_speedtest
            ;;
        9)
            setup_isufe_command
            ;;
        10)
            setup_openvpn_routing
            ;;
        11)
            install_3xui
            ;;
        12)
            dd_system_reinstall
            ;;
        13)
            modify_hostname_and_motd
            ;;
        14)
            install_claude_code
            ;;
        15)
            server_security_menu
            ;;
        16)
            google_protection_menu
            ;;
        17)
            add_v2bx_node
            ;;
        18)
            update_script
            ;;
        19)
            uninstall_script
            ;;
        *)
            echo -e "${red}无效的选项，请输入 0-19${plain}"
            ;;
    esac
}

# 设置isufe快捷命令
setup_isufe_command() {
    echo -e "${green}=== 设置isufe快捷命令 ===${plain}"
    
    local raw_url="https://raw.githubusercontent.com/Shannon-x/super-tool/master/super-tool.sh"
    local install_dir="/usr/local/bin"
    local persistent_script="$install_dir/super-tool.sh"
    local script_path=$(realpath "$0")
    local target_path="$install_dir/isufe"
    local current_user=$(whoami)

    # 如果当前脚本来自进程替换（/proc），则下载到持久位置
    if [[ "$script_path" == /proc/* ]]; then
        echo -e "${yellow}检测到脚本运行自进程替换，正在下载脚本到持久位置${plain}"
        if curl -fsSL "$raw_url" -o "$persistent_script"; then
            chmod +x "$persistent_script"
            script_path="$persistent_script"
            echo -e "${green}脚本已下载到: $persistent_script${plain}"
        else
            echo -e "${red}下载脚本失败，请检查网络${plain}"
            return 1
        fi
    fi
    
    echo -e "${yellow}当前脚本路径: $script_path${plain}"
    echo -e "${yellow}目标安装路径: $target_path${plain}"
    echo -e "${yellow}当前用户: $current_user${plain}"
    
    # 检查现有安装状态
    if [[ -L "$target_path" ]]; then
        local link_target=$(readlink "$target_path")
        echo -e "${yellow}检测到现有符号链接: $target_path -> $link_target${plain}"
        
        if [[ "$link_target" == "$script_path" ]]; then
            echo -e "${green}符号链接已正确设置${plain}"
        else
            echo -e "${yellow}符号链接指向不同的文件，将重新设置${plain}"
        fi
    elif [[ -f "$target_path" ]]; then
        echo -e "${yellow}检测到现有文件: $target_path${plain}"
    fi
    
    # 检查PATH环境变量
    if echo "$PATH" | grep -q "/usr/local/bin"; then
        echo -e "${green}✓ /usr/local/bin 已在PATH中${plain}"
    else
        echo -e "${red}✗ /usr/local/bin 不在PATH中${plain}"
        echo -e "${yellow}建议将以下内容添加到 ~/.bashrc 或 ~/.profile:${plain}"
        echo -e "${cyan}export PATH=/usr/local/bin:\$PATH${plain}"
    fi
    
    # 询问用户是否设置
    echo -e "\n${cyan}设置 'isufe' 快捷命令的选项：${plain}"
    echo -e "  ${cyan}1.${plain} 设置到 /usr/local/bin/isufe (推荐)"
    echo -e "  ${cyan}2.${plain} 设置到 /usr/bin/isufe (系统目录)"
    echo -e "  ${cyan}3.${plain} 添加别名到当前用户配置"
    echo -e "  ${cyan}4.${plain} 取消设置"
    
    local setup_choice
    read -rp "请选择设置方式 [1-4] (默认1): " setup_choice
    
    if [[ -z "$setup_choice" ]]; then
        setup_choice="1"
    fi
    
    case $setup_choice in
        1)
            echo -e "\n${green}设置到 /usr/local/bin/isufe${plain}"
            if ln -sf "$script_path" "$target_path" 2>/dev/null; then
                chmod +x "$target_path" 2>/dev/null
                echo -e "${green}✓ 快捷命令设置成功！${plain}"
                test_isufe_command "$target_path"
            else
                echo -e "${red}✗ 设置失败，尝试使用sudo权限...${plain}"
                if sudo ln -sf "$script_path" "$target_path"; then
                    sudo chmod +x "$target_path"
                    echo -e "${green}✓ 快捷命令设置成功！${plain}"
                    test_isufe_command "$target_path"
                else
                    echo -e "${red}✗ 设置失败${plain}"
                    show_manual_setup "$script_path" "$target_path"
                fi
            fi
            ;;
        2)
            local target_path_sys="/usr/bin/isufe"
            echo -e "\n${green}设置到 /usr/bin/isufe${plain}"
            if sudo ln -sf "$script_path" "$target_path_sys"; then
                sudo chmod +x "$target_path_sys"
                echo -e "${green}✓ 快捷命令设置成功！${plain}"
                test_isufe_command "$target_path_sys"
            else
                echo -e "${red}✗ 设置失败${plain}"
                show_manual_setup "$script_path" "$target_path_sys"
            fi
            ;;
        3)
            echo -e "\n${green}添加别名到用户配置${plain}"
            setup_alias "$script_path"
            ;;
        4)
            echo -e "${yellow}已取消设置${plain}"
            return 0
            ;;
        *)
            echo -e "${red}无效选择，已取消设置${plain}"
            return 1
            ;;
    esac
}

# 测试isufe命令
test_isufe_command() {
    local cmd_path="$1"
    echo -e "\n${yellow}测试命令...${plain}"
    
    if [[ -x "$cmd_path" ]]; then
        echo -e "${green}✓ 文件存在且可执行${plain}"
    else
        echo -e "${red}✗ 文件不存在或不可执行${plain}"
        return 1
    fi
    
    if command -v isufe >/dev/null 2>&1; then
        echo -e "${green}✓ isufe 命令可以找到${plain}"
        echo -e "${cyan}命令位置: $(which isufe)${plain}"
        echo -e "${green}现在您可以在任何地方输入 'isufe' 来启动脚本${plain}"
    else
        echo -e "${red}✗ isufe 命令无法找到${plain}"
        echo -e "${yellow}可能需要重新加载环境变量或重新登录${plain}"
        echo -e "${cyan}尝试运行: source ~/.bashrc 或重新登录${plain}"
    fi
}

# 设置别名
setup_alias() {
    local script_path="$1"
    local shell_rc=""
    
    # 检测用户的shell
    if [[ "$SHELL" == *"bash"* ]]; then
        shell_rc="$HOME/.bashrc"
    elif [[ "$SHELL" == *"zsh"* ]]; then
        shell_rc="$HOME/.zshrc"
    else
        shell_rc="$HOME/.profile"
    fi
    
    echo -e "${yellow}检测到shell: $SHELL${plain}"
    echo -e "${yellow}将添加别名到: $shell_rc${plain}"
    
    # 检查是否已存在别名
    if [[ -f "$shell_rc" ]] && grep -q "alias isufe=" "$shell_rc"; then
        echo -e "${yellow}别名已存在，将更新...${plain}"
        sed -i.bak "/alias isufe=/d" "$shell_rc"
    fi
    
    # 添加别名
    echo "alias isufe='bash $script_path'" >> "$shell_rc"
    echo -e "${green}✓ 别名已添加到 $shell_rc${plain}"
    echo -e "${cyan}请运行以下命令使别名生效:${plain}"
    echo -e "${cyan}source $shell_rc${plain}"
    echo -e "${yellow}或者重新登录系统${plain}"
}

# 显示手动设置方法
show_manual_setup() {
    local script_path="$1"
    local target_path="$2"
    
    echo -e "\n${yellow}手动设置方法：${plain}"
    echo -e "${cyan}方法1 - 创建符号链接:${plain}"
    echo -e "  sudo ln -sf $script_path $target_path"
    echo -e "  sudo chmod +x $target_path"
    echo -e "\n${cyan}方法2 - 添加别名:${plain}"
    echo -e "  echo \"alias isufe='bash $script_path'\" >> ~/.bashrc"
    echo -e "  source ~/.bashrc"
    echo -e "\n${cyan}方法3 - 复制文件:${plain}"
    echo -e "  sudo cp $script_path $target_path"
    echo -e "  sudo chmod +x $target_path"
}

############################################################
# 服务器安全设置功能
############################################################

# 1. 添加SSH密钥登录
setup_ssh_key_login() {
    echo -e "${green}=== 设置SSH密钥登录 ===${plain}"
    
    echo -e "${yellow}请选择SSH密钥设置方式：${plain}"
    echo -e "  ${cyan}1.${plain} 手动输入SSH公钥"
    echo -e "  ${cyan}2.${plain} 从URL下载公钥 (如GitHub: https://github.com/username.keys)"
    echo -e "  ${cyan}3.${plain} 从本地文件读取公钥"
    echo -e "  ${cyan}4.${plain} 使用预设的公钥"
    
    local choice
    read -rp "请选择 [1-4]: " choice
    
    local public_key=""
    
    case $choice in
        1)
            echo -e "${yellow}请输入完整的SSH公钥：${plain}"
            echo -e "${cyan}格式示例: ssh-rsa AAAAB3NzaC1yc2E... user@hostname${plain}"
            read -rp "公钥: " public_key
            ;;
        2)
            echo -e "${yellow}请输入公钥URL：${plain}"
            echo -e "${cyan}示例: https://github.com/username.keys${plain}"
            read -rp "URL: " key_url
            if [[ -n "$key_url" ]]; then
                echo -e "${yellow}正在下载公钥...${plain}"
                public_key=$(curl -fsSL "$key_url" 2>/dev/null | head -1)
                if [[ -z "$public_key" ]]; then
                    echo -e "${red}无法从URL下载公钥${plain}"
                    return 1
                fi
                echo -e "${green}下载成功！${plain}"
            fi
            ;;
        3)
            echo -e "${yellow}请输入公钥文件路径：${plain}"
            read -rp "文件路径: " key_file
            if [[ -f "$key_file" ]]; then
                public_key=$(cat "$key_file" | head -1)
                echo -e "${green}读取文件成功！${plain}"
            else
                echo -e "${red}文件不存在: $key_file${plain}"
                return 1
            fi
            ;;
        4)
            public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDr/1TncOySPMDS4gfQXcknFmqRspdKESWtFxYBRzHUFxt2i/7qoPY+FG3YqWnm3wawtUvMKHRtflvCEGhO1fZl5ZqLBxSILfWX9IDlPcaL7K9DN7ZVtLqOcQb6ADzp2Q8ZW4n+b6qOjlBsxZr34sYcz5hzdsEz+0Zr3YbRvQlFYjaivQdi4nYigMcFru2TKqOz/Wxuhg1i4HFTKthzuDSNzLjL0zu6pSlglB2oLVJJrUt8ARswrqEoylk5+7aLPIEoz2sLm7liA9e7N7ITnZZNVYt9ZZ6jeeVpTVnR2qZV6SnqL3/iGIWtY50u7l+dbF/jN0b7XSuKGNN7dLGck0GAbVa4yp/dC5Bk7zqVALDaQRLkNjJ/r+kKBkZM9f6iHMYnSNBvNou5lAh4ZhP1scXuN6OhWHqrUxyG0esq8CEIEmPUEyMwnaA69FMqnrBT8RQR0I3enFxMOY2E9zc/2BJsZo6CMD2nPqXMffNZ9I4zBHesdYf9vy8uyl7wBQC87wlNzm1dX3s1TXYm4LXrFHeTHyddG2q+fmOq4y6tS0tDmGp7Q2Dccic6LV1IDM9lgUdlxAm90+C9A8Ew8MzrSjLdSzTouORhNr6tTGF7lubg1BtjtElcVXF3Jf4KX52I/wkXo3iszGUF4rmZpxHinWJTLCwvvX26YkrHGWWb3473gw== shuhao1024@gmail.com"
            echo -e "${yellow}使用预设公钥${plain}"
            ;;
        *)
            echo -e "${red}无效选择${plain}"
            return 1
            ;;
    esac
    
    # 验证公钥格式
    if [[ -z "$public_key" ]]; then
        echo -e "${red}公钥不能为空${plain}"
        return 1
    fi
    
    # 基本公钥格式验证
    if [[ ! "$public_key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-) ]]; then
        echo -e "${red}错误：公钥格式不正确${plain}"
        echo -e "${yellow}公钥应该以 ssh-rsa、ssh-ed25519 或 ecdsa-sha2- 开头${plain}"
        return 1
    fi
    
    # 提取公钥注释（用户信息）
    local key_comment=$(echo "$public_key" | awk '{print $3}')
    if [[ -z "$key_comment" ]]; then
        key_comment="imported-key"
    fi
    
    local ssh_dir="$HOME/.ssh"
    local authorized_keys="$ssh_dir/authorized_keys"
    
    echo -e "${yellow}将要添加的公钥：${plain}"
    echo -e "${cyan}类型: $(echo "$public_key" | awk '{print $1}')${plain}"
    echo -e "${cyan}注释: $key_comment${plain}"
    echo -e "${cyan}公钥指纹: $(echo "$public_key" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || echo "无法计算")${plain}"
    
    read -rp "确认添加此SSH公钥？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 创建.ssh目录
    if [[ ! -d "$ssh_dir" ]]; then
        echo -e "${yellow}创建 $ssh_dir 目录...${plain}"
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        # 确保目录所有者正确
        chown "$USER:$(id -gn)" "$ssh_dir" 2>/dev/null || true
    fi
    
    # 备份现有的authorized_keys文件
    if [[ -f "$authorized_keys" ]]; then
        local backup_file="${authorized_keys}.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${yellow}备份现有授权密钥文件到：${plain}${cyan}$backup_file${plain}"
        cp "$authorized_keys" "$backup_file"
    fi
    
    # 检查密钥是否已存在（比较公钥的第二字段）
    local key_data=$(echo "$public_key" | awk '{print $2}')
    if [[ -f "$authorized_keys" ]] && grep -q "$key_data" "$authorized_keys"; then
        echo -e "${yellow}检测到相同的公钥已存在，将更新...${plain}"
        # 删除现有的相同公钥
        grep -v "$key_data" "$authorized_keys" > "${authorized_keys}.tmp" 2>/dev/null || true
        mv "${authorized_keys}.tmp" "$authorized_keys"
    fi
    
    # 添加新密钥
    echo "$public_key" >> "$authorized_keys"
    chmod 600 "$authorized_keys"
    # 确保文件所有者正确
    chown "$USER:$(id -gn)" "$authorized_keys" 2>/dev/null || true
    
    echo -e "${green}✓ SSH公钥已成功添加！${plain}"
    echo -e "${yellow}授权密钥文件：${plain}${cyan}$authorized_keys${plain}"
    echo -e "${yellow}文件权限：${plain}${cyan}$(ls -la $authorized_keys)${plain}"
    
    # 验证和优化SSH配置
    echo -e "\n${yellow}检查和优化SSH服务配置...${plain}"
    local sshd_config="/etc/ssh/sshd_config"
    local config_changed=false
    
    if [[ -f "$sshd_config" ]]; then
        # 备份SSH配置
        local sshd_backup="${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$sshd_config" "$sshd_backup"
        echo -e "${yellow}备份SSH配置到：${plain}${cyan}$sshd_backup${plain}"
        
        # 确保启用公钥认证
        if ! grep -q "^PubkeyAuthentication yes" "$sshd_config"; then
            echo -e "${yellow}启用公钥认证...${plain}"
            if grep -q "^PubkeyAuthentication" "$sshd_config"; then
                sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$sshd_config"
            else
                echo "PubkeyAuthentication yes" >> "$sshd_config"
            fi
            config_changed=true
        fi
        
        # 确保指定正确的授权密钥文件路径
        if ! grep -q "^AuthorizedKeysFile.*authorized_keys" "$sshd_config"; then
            echo -e "${yellow}设置授权密钥文件路径...${plain}"
            if grep -q "^AuthorizedKeysFile" "$sshd_config"; then
                sed -i 's|^AuthorizedKeysFile.*|AuthorizedKeysFile .ssh/authorized_keys|' "$sshd_config"
            else
                echo "AuthorizedKeysFile .ssh/authorized_keys" >> "$sshd_config"
            fi
            config_changed=true
        fi
        
        # 验证SSH配置
        if sshd -t; then
            echo -e "${green}✓ SSH配置验证通过${plain}"
            
            # 如果配置有变化，重启SSH服务
            if [[ "$config_changed" == true ]]; then
                echo -e "${yellow}重启SSH服务以应用配置更改...${plain}"
                if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
                    echo -e "${green}✓ SSH服务已重启${plain}"
                else
                    echo -e "${red}⚠ SSH服务重启失败，但密钥已添加${plain}"
                fi
            fi
        else
            echo -e "${red}✗ SSH配置验证失败，恢复备份${plain}"
            cp "$sshd_backup" "$sshd_config"
        fi
    fi
    
    # 验证SSH服务状态
    echo -e "\n${yellow}检查SSH服务状态...${plain}"
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        echo -e "${green}✓ SSH服务正在运行${plain}"
    else
        echo -e "${red}⚠ SSH服务未运行，正在尝试启动...${plain}"
        if systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null; then
            echo -e "${green}✓ SSH服务已启动${plain}"
        else
            echo -e "${red}✗ 无法启动SSH服务，请手动检查${plain}"
        fi
    fi
    
    # 显示连接测试建议
    echo -e "\n${green}=== SSH密钥配置完成 ===${plain}"
    echo -e "${cyan}测试连接建议：${plain}"
    echo -e "  1. ${yellow}保持当前SSH连接不要断开${plain}"
    echo -e "  2. ${yellow}开启新的终端测试密钥登录${plain}"
    echo -e "  3. ${yellow}确认密钥登录成功后再考虑禁用密码登录${plain}"
    
    # 获取服务器IP和端口信息
    local server_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "your-server-ip")
    local ssh_port=$(grep "^Port " "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "22")
    
    echo -e "\n${cyan}测试命令示例：${plain}"
    echo -e "  ${yellow}ssh -i /path/to/private_key -p $ssh_port $USER@$server_ip${plain}"
    
    echo -e "\n${cyan}提示：${plain}"
    echo -e "  - 现在可以使用密钥登录服务器"
    echo -e "  - 私钥文件权限应设为 600 (chmod 600 private_key)"
    echo -e "  - 建议测试密钥登录成功后再禁用密码登录"
    echo -e "  - 请确保保存好对应的私钥文件"
}

# 2. 禁止密码登录
disable_password_login() {
    echo -e "${green}=== 禁止SSH密码登录 ===${plain}"
    
    local sshd_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "$sshd_config" ]]; then
        echo -e "${red}错误：未找到SSH配置文件 $sshd_config${plain}"
        return 1
    fi
    
    echo -e "${red}⚠ 警告：禁用密码登录后，只能通过SSH密钥登录！${plain}"
    echo -e "${yellow}请确保：${plain}"
    echo -e "  1. 已正确添加SSH公钥"
    echo -e "  2. 已测试密钥登录成功"
    echo -e "  3. 有其他方式访问服务器（如控制台）"
    
    read -rp "确认禁用密码登录？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 备份SSH配置文件
    local backup_file="${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${yellow}备份SSH配置文件到：${plain}${cyan}$backup_file${plain}"
    cp "$sshd_config" "$backup_file"
    
    # 修改SSH配置
    echo -e "${yellow}修改SSH配置...${plain}"
    
    # 禁用密码认证
    if grep -q "^PasswordAuthentication" "$sshd_config"; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_config"
    else
        echo "PasswordAuthentication no" >> "$sshd_config"
    fi
    
    # 禁用质询响应认证
    if grep -q "^ChallengeResponseAuthentication" "$sshd_config"; then
        sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$sshd_config"
    else
        echo "ChallengeResponseAuthentication no" >> "$sshd_config"
    fi
    
    # 启用公钥认证（确保）
    if grep -q "^PubkeyAuthentication" "$sshd_config"; then
        sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$sshd_config"
    else
        echo "PubkeyAuthentication yes" >> "$sshd_config"
    fi
    
    # 禁用PAM认证
    if grep -q "^UsePAM" "$sshd_config"; then
        sed -i 's/^UsePAM.*/UsePAM no/' "$sshd_config"
    else
        echo "UsePAM no" >> "$sshd_config"
    fi
    
    # 验证配置
    echo -e "${yellow}验证SSH配置...${plain}"
    if sshd -t; then
        echo -e "${green}✓ SSH配置验证通过${plain}"
        
        # 重启SSH服务
        echo -e "${yellow}重启SSH服务...${plain}"
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            echo -e "${green}✓ SSH服务已重启${plain}"
            echo -e "${green}✓ 密码登录已禁用！${plain}"
            echo -e "${cyan}当前SSH配置：${plain}"
            echo -e "  - 密码认证：${red}禁用${plain}"
            echo -e "  - 公钥认证：${green}启用${plain}"
            echo -e "  - 质询响应认证：${red}禁用${plain}"
        else
            echo -e "${red}✗ SSH服务重启失败${plain}"
            echo -e "${yellow}恢复配置文件...${plain}"
            cp "$backup_file" "$sshd_config"
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
            return 1
        fi
    else
        echo -e "${red}✗ SSH配置验证失败，恢复备份${plain}"
        cp "$backup_file" "$sshd_config"
        return 1
    fi
    
    echo -e "\n${yellow}重要提示：${plain}"
    echo -e "  - ${red}密码登录已被禁用${plain}"
    echo -e "  - ${green}只能使用SSH密钥登录${plain}"
    echo -e "  - 配置备份：${cyan}$backup_file${plain}"
}

# 3. 安装并配置Fail2ban
setup_fail2ban() {
    echo -e "${green}=== 安装并配置Fail2ban ===${plain}"
    
    # 检测操作系统
    local os_release=""
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_release="$ID"
    fi
    
    echo -e "${yellow}检测到操作系统：${plain}${cyan}$os_release${plain}"
    
    # 检查Fail2ban是否已安装
    if command -v fail2ban-server >/dev/null 2>&1; then
        echo -e "${green}Fail2ban 已安装${plain}"
    else
        echo -e "${yellow}正在安装 Fail2ban...${plain}"
        
        case "$os_release" in
            "ubuntu"|"debian")
                apt-get update -y
                apt-get install -y fail2ban
                ;;
            "centos"|"rhel"|"fedora")
                if command -v dnf >/dev/null 2>&1; then
                    dnf install -y epel-release
                    dnf install -y fail2ban
                else
                    yum install -y epel-release
                    yum install -y fail2ban
                fi
                ;;
            "arch")
                pacman -S --noconfirm fail2ban
                ;;
            *)
                echo -e "${red}不支持的操作系统，请手动安装 Fail2ban${plain}"
                return 1
                ;;
        esac
        
        if command -v fail2ban-server >/dev/null 2>&1; then
            echo -e "${green}✓ Fail2ban 安装成功${plain}"
        else
            echo -e "${red}✗ Fail2ban 安装失败${plain}"
            return 1
        fi
    fi
    
    # 创建自定义配置
    local jail_local="/etc/fail2ban/jail.local"
    
    echo -e "${yellow}配置 Fail2ban...${plain}"
    
    # 备份现有配置
    if [[ -f "$jail_local" ]]; then
        local backup_file="${jail_local}.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${yellow}备份现有配置到：${plain}${cyan}$backup_file${plain}"
        cp "$jail_local" "$backup_file"
    fi
    
    # 创建配置文件
    cat > "$jail_local" << 'EOF'
[DEFAULT]
# 封禁时间：600小时 = 25天
bantime = 2160000

# 在findtime时间内
findtime = 600

# 失败maxretry次后封禁
maxretry = 3

# 忽略的IP（本地IP）
ignoreip = 127.0.0.1/8 ::1

# 后端
backend = auto

# 邮件配置（可选）
# destemail = your-email@domain.com
# sender = fail2ban@hostname
# mta = sendmail

# 动作
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 2160000
findtime = 600

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 2160000
findtime = 300

[nginx-http-auth]
enabled = false
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 6

[nginx-noscript]
enabled = false
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = false
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = false
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
EOF
    
    # 针对CentOS/RHEL系统调整日志路径
    if [[ "$os_release" == "centos" || "$os_release" == "rhel" || "$os_release" == "fedora" ]]; then
        sed -i 's|/var/log/auth.log|/var/log/secure|g' "$jail_local"
    fi
    
    # 启动并启用Fail2ban服务
    echo -e "${yellow}启动 Fail2ban 服务...${plain}"
    systemctl enable fail2ban
    systemctl start fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        echo -e "${green}✓ Fail2ban 服务已启动并启用${plain}"
    else
        echo -e "${red}✗ Fail2ban 服务启动失败${plain}"
        return 1
    fi
    
    # 显示状态
    echo -e "\n${green}=== Fail2ban 配置完成 ===${plain}"
    echo -e "${yellow}配置详情：${plain}"
    echo -e "  - 封禁时间：${cyan}600小时（25天）${plain}"
    echo -e "  - 检查窗口：${cyan}10分钟${plain}"
    echo -e "  - 最大重试：${cyan}3次${plain}"
    echo -e "  - SSH保护：${green}已启用${plain}"
    echo -e "  - SSH DDoS保护：${green}已启用${plain}"
    
    echo -e "\n${cyan}常用管理命令：${plain}"
    echo -e "  - 查看状态：${yellow}fail2ban-client status${plain}"
    echo -e "  - 查看SSH监控：${yellow}fail2ban-client status sshd${plain}"
    echo -e "  - 解封IP：${yellow}fail2ban-client set sshd unbanip <IP>${plain}"
    echo -e "  - 查看日志：${yellow}tail -f /var/log/fail2ban.log${plain}"
    
    # 显示当前状态
    echo -e "\n${yellow}当前 Fail2ban 状态：${plain}"
    fail2ban-client status 2>/dev/null || echo -e "${red}无法获取状态信息${plain}"
}

# 4. 更新系统包
update_system_packages() {
    echo -e "${green}=== 更新系统包 ===${plain}"
    
    # 检测操作系统
    local os_release=""
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_release="$ID"
    fi
    
    echo -e "${yellow}检测到操作系统：${plain}${cyan}$os_release${plain}"
    
    read -rp "确认更新系统包？这可能需要一些时间 (y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    echo -e "${yellow}开始更新系统包...${plain}"
    
    case "$os_release" in
        "ubuntu"|"debian")
            echo -e "${cyan}更新包列表...${plain}"
            apt-get update -y
            echo -e "${cyan}升级系统包...${plain}"
            apt-get upgrade -y
            echo -e "${cyan}清理不需要的包...${plain}"
            apt-get autoremove -y
            apt-get autoclean
            ;;
        "centos"|"rhel"|"fedora")
            if command -v dnf >/dev/null 2>&1; then
                echo -e "${cyan}更新包列表和系统包...${plain}"
                dnf update -y
                echo -e "${cyan}清理包缓存...${plain}"
                dnf autoremove -y
                dnf clean all
            else
                echo -e "${cyan}更新包列表和系统包...${plain}"
                yum update -y
                echo -e "${cyan}清理包缓存...${plain}"
                yum autoremove -y
                yum clean all
            fi
            ;;
        "arch")
            echo -e "${cyan}更新包列表和系统包...${plain}"
            pacman -Syu --noconfirm
            echo -e "${cyan}清理包缓存...${plain}"
            pacman -Sc --noconfirm
            ;;
        *)
            echo -e "${red}不支持的操作系统${plain}"
            return 1
            ;;
    esac
    
    echo -e "${green}✓ 系统包更新完成${plain}"
    
    # 检查是否需要重启
    if [[ -f /var/run/reboot-required ]]; then
        echo -e "${yellow}⚠ 系统更新完成，建议重启系统${plain}"
        read -rp "是否现在重启系统？(y/n): " reboot_confirm
        if [[ "$reboot_confirm" == [Yy] ]]; then
            echo -e "${red}系统将在5秒后重启...${plain}"
            sleep 5
            reboot
        fi
    fi
}

# 5. 更改SSH登录端口
change_ssh_port() {
    echo -e "${green}=== 更改SSH登录端口 ===${plain}"
    
    local sshd_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "$sshd_config" ]]; then
        echo -e "${red}错误：未找到SSH配置文件 $sshd_config${plain}"
        return 1
    fi
    
    # 获取当前SSH端口
    local current_port
    current_port=$(grep "^Port " "$sshd_config" | awk '{print $2}' 2>/dev/null)
    if [[ -z "$current_port" ]]; then
        current_port="22"
    fi
    
    echo -e "${yellow}当前SSH端口：${plain}${cyan}$current_port${plain}"
    
    read -rp "请输入新的SSH端口 (1024-65535): " new_port
    
    # 验证端口号
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1024 ]] || [[ "$new_port" -gt 65535 ]]; then
        echo -e "${red}错误：端口号必须是1024-65535之间的数字${plain}"
        return 1
    fi
    
    # 检查端口是否被占用
    if netstat -tuln 2>/dev/null | grep -q ":$new_port "; then
        echo -e "${red}错误：端口 $new_port 已被占用${plain}"
        netstat -tuln | grep ":$new_port "
        return 1
    fi
    
    echo -e "${yellow}将SSH端口从 $current_port 更改为 $new_port${plain}"
    read -rp "确认更改SSH端口？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 备份SSH配置文件
    local backup_file="${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${yellow}备份SSH配置文件到：${plain}${cyan}$backup_file${plain}"
    cp "$sshd_config" "$backup_file"
    
    # 修改SSH配置
    echo -e "${yellow}修改SSH配置...${plain}"
    if grep -q "^Port " "$sshd_config"; then
        sed -i "s/^Port .*/Port $new_port/" "$sshd_config"
    else
        echo "Port $new_port" >> "$sshd_config"
    fi
    
    # 检查并修改套接字配置（systemd）
    echo -e "${yellow}检查SSH套接字配置...${plain}"
    local ssh_socket="/etc/systemd/system/ssh.socket.d/listen.conf"
    local sshd_socket="/etc/systemd/system/sshd.socket.d/listen.conf"
    
    # 为ssh服务创建套接字配置
    if systemctl list-unit-files | grep -q "ssh.socket"; then
        mkdir -p "$(dirname "$ssh_socket")"
        echo -e "${yellow}配置 ssh.socket...${plain}"
        cat > "$ssh_socket" << EOF
[Socket]
ListenStream=
ListenStream=$new_port
EOF
    fi
    
    # 为sshd服务创建套接字配置
    if systemctl list-unit-files | grep -q "sshd.socket"; then
        mkdir -p "$(dirname "$sshd_socket")"
        echo -e "${yellow}配置 sshd.socket...${plain}"
        cat > "$sshd_socket" << EOF
[Socket]
ListenStream=
ListenStream=$new_port
EOF
    fi
    
    # 重新加载systemd配置
    echo -e "${yellow}重新加载systemd配置...${plain}"
    systemctl daemon-reload
    
    # 验证SSH配置
    echo -e "${yellow}验证SSH配置...${plain}"
    if sshd -t; then
        echo -e "${green}✓ SSH配置验证通过${plain}"
        
        # 更新防火墙规则（如果有的话）
        echo -e "${yellow}更新防火墙规则...${plain}"
        
        # ufw (Ubuntu/Debian)
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            echo -e "${cyan}更新UFW防火墙规则...${plain}"
            ufw allow "$new_port/tcp" comment 'SSH'
            if [[ "$current_port" != "22" ]]; then
                ufw delete allow "$current_port/tcp" 2>/dev/null || true
            fi
        fi
        
        # firewalld (CentOS/RHEL/Fedora)
        if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
            echo -e "${cyan}更新firewalld防火墙规则...${plain}"
            firewall-cmd --permanent --add-port="$new_port/tcp"
            if [[ "$current_port" != "22" ]]; then
                firewall-cmd --permanent --remove-port="$current_port/tcp" 2>/dev/null || true
            fi
            firewall-cmd --reload
        fi
        
        # iptables直接规则
        if command -v iptables >/dev/null 2>&1; then
            echo -e "${cyan}添加iptables规则...${plain}"
            iptables -A INPUT -p tcp --dport "$new_port" -j ACCEPT 2>/dev/null || true
        fi
        
        # 重启SSH服务
        echo -e "${yellow}重启SSH服务...${plain}"
        
        # 停止套接字服务（如果存在）
        systemctl stop ssh.socket 2>/dev/null || true
        systemctl stop sshd.socket 2>/dev/null || true
        
        # 重启SSH服务
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            echo -e "${green}✓ SSH服务已重启${plain}"
            
            # 启动套接字服务（如果存在）
            systemctl start ssh.socket 2>/dev/null || true
            systemctl start sshd.socket 2>/dev/null || true
            
            echo -e "${green}✓ SSH端口已成功更改为 $new_port${plain}"
            
            # 验证端口监听状态
            echo -e "${yellow}验证端口监听状态...${plain}"
            sleep 3
            if netstat -tuln 2>/dev/null | grep -q ":$new_port "; then
                echo -e "${green}✓ SSH正在监听端口 $new_port${plain}"
                netstat -tuln | grep ":$new_port "
            else
                echo -e "${red}⚠ 未检测到端口 $new_port 的监听状态${plain}"
            fi
            
        else
            echo -e "${red}✗ SSH服务重启失败，恢复配置${plain}"
            cp "$backup_file" "$sshd_config"
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
            return 1
        fi
    else
        echo -e "${red}✗ SSH配置验证失败，恢复备份${plain}"
        cp "$backup_file" "$sshd_config"
        return 1
    fi
    
    echo -e "\n${green}=== SSH端口更改完成 ===${plain}"
    echo -e "${yellow}重要信息：${plain}"
    echo -e "  - 新SSH端口：${cyan}$new_port${plain}"
    echo -e "  - 旧SSH端口：${yellow}$current_port${plain}"
    echo -e "  - 配置备份：${cyan}$backup_file${plain}"
    echo -e "\n${red}⚠ 重要提醒：${plain}"
    echo -e "  - ${red}请立即测试新端口的SSH连接${plain}"
    echo -e "  - ${yellow}连接命令：ssh -p $new_port user@server${plain}"
    echo -e "  - ${red}确认新端口可用后再断开当前连接${plain}"
    echo -e "  - ${yellow}如果无法连接，请使用其他方式访问服务器恢复配置${plain}"
}

# 6. 设置Swap交换内存
setup_swap_memory() {
    echo -e "${green}=== 设置Swap交换内存 ===${plain}"
    
    # 检查当前swap状态
    echo -e "${yellow}当前Swap状态：${plain}"
    local current_swap=$(free -h | grep "Swap:" | awk '{print $2}')
    local current_used=$(free -h | grep "Swap:" | awk '{print $3}')
    
    if [[ "$current_swap" == "0B" ]]; then
        echo -e "  ${red}当前无Swap交换内存${plain}"
    else
        echo -e "  ${cyan}总大小: $current_swap${plain}"
        echo -e "  ${cyan}已使用: $current_used${plain}"
        echo -e "  ${cyan}详细信息:${plain}"
        free -h | grep -E "Mem:|Swap:"
    fi
    
    # 检查现有swap文件
    echo -e "\n${yellow}检查现有swap文件...${plain}"
    if [[ -f /swapfile ]]; then
        local swap_size=$(ls -lh /swapfile | awk '{print $5}')
        echo -e "  ${yellow}发现现有swap文件: /swapfile (${swap_size})${plain}"
        
        read -rp "是否要删除现有swap文件并重新创建？(y/n): " recreate_swap
        if [[ "$recreate_swap" == [Yy] ]]; then
            echo -e "${yellow}正在删除现有swap文件...${plain}"
            swapoff /swapfile 2>/dev/null || true
            rm -f /swapfile
            # 从fstab中移除
            sed -i '/\/swapfile/d' /etc/fstab
            echo -e "${green}✓ 现有swap文件已删除${plain}"
        else
            echo -e "${yellow}保留现有swap文件，操作已取消${plain}"
            return 0
        fi
    fi
    
    # 询问swap大小
    echo -e "\n${yellow}请输入要创建的Swap大小（单位：GB）：${plain}"
    echo -e "${cyan}建议配置：${plain}"
    echo -e "  - 内存 <= 2GB: 建议 2-4GB Swap"
    echo -e "  - 内存 2-8GB: 建议 2-4GB Swap"
    echo -e "  - 内存 > 8GB: 建议 2GB Swap"
    echo -e "  - 通常设置为内存的1-2倍即可"
    
    local swap_size_gb
    while true; do
        read -rp "请输入Swap大小（GB，1-32）: " swap_size_gb
        
        if [[ "$swap_size_gb" =~ ^[0-9]+$ ]] && [[ "$swap_size_gb" -ge 1 ]] && [[ "$swap_size_gb" -le 32 ]]; then
            break
        else
            echo -e "${red}请输入有效的数字（1-32）${plain}"
        fi
    done
    
    # 检查磁盘空间
    echo -e "\n${yellow}检查磁盘空间...${plain}"
    local available_space=$(df / | tail -1 | awk '{print $4}')
    local required_space=$((swap_size_gb * 1024 * 1024))  # 转换为KB
    
    if [[ $available_space -lt $required_space ]]; then
        echo -e "${red}错误：磁盘空间不足${plain}"
        echo -e "  需要: ${cyan}${swap_size_gb}GB${plain}"
        echo -e "  可用: ${cyan}$((available_space / 1024 / 1024))GB${plain}"
        return 1
    fi
    
    echo -e "${green}✓ 磁盘空间充足${plain}"
    
    # 确认创建
    echo -e "\n${yellow}=== 确认Swap配置 ===${plain}"
    echo -e "  ${cyan}Swap大小: ${swap_size_gb}GB${plain}"
    echo -e "  ${cyan}Swap文件: /swapfile${plain}"
    echo -e "  ${cyan}持久化: 是（自动加入/etc/fstab）${plain}"
    
    read -rp "确认创建Swap交换内存？(y/n): " confirm_create
    if [[ "$confirm_create" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 创建swap文件
    echo -e "\n${green}开始创建Swap交换内存...${plain}"
    
    echo -e "${yellow}1. 创建swap文件 (${swap_size_gb}GB)...${plain}"
    if dd if=/dev/zero of=/swapfile bs=1G count=$swap_size_gb status=progress; then
        echo -e "${green}✓ swap文件创建成功${plain}"
    else
        echo -e "${red}✗ swap文件创建失败${plain}"
        return 1
    fi
    
    # 设置权限
    echo -e "${yellow}2. 设置文件权限...${plain}"
    chmod 600 /swapfile
    echo -e "${green}✓ 文件权限设置完成${plain}"
    
    # 格式化为swap
    echo -e "${yellow}3. 格式化为swap格式...${plain}"
    if mkswap /swapfile; then
        echo -e "${green}✓ swap格式化完成${plain}"
    else
        echo -e "${red}✗ swap格式化失败${plain}"
        rm -f /swapfile
        return 1
    fi
    
    # 启用swap
    echo -e "${yellow}4. 启用swap...${plain}"
    if swapon /swapfile; then
        echo -e "${green}✓ swap已启用${plain}"
    else
        echo -e "${red}✗ swap启用失败${plain}"
        rm -f /swapfile
        return 1
    fi
    
    # 添加到fstab实现持久化
    echo -e "${yellow}5. 配置开机自动挂载...${plain}"
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
        echo -e "${green}✓ 已添加到/etc/fstab，开机自动挂载${plain}"
    else
        echo -e "${yellow}⚠ /etc/fstab中已存在swap配置${plain}"
    fi
    
    # 优化swap设置
    echo -e "${yellow}6. 优化swap设置...${plain}"
    
    # 设置swappiness (推荐值10，减少对swap的依赖)
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl vm.swappiness=10
    
    # 设置vfs_cache_pressure (推荐值50，平衡缓存回收)
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
    sysctl vm.vfs_cache_pressure=50
    
    echo -e "${green}✓ swap优化设置完成${plain}"
    
    # 验证配置
    echo -e "\n${green}=== Swap创建完成 ===${plain}"
    echo -e "${yellow}验证结果：${plain}"
    
    # 显示swap状态
    echo -e "${cyan}Swap状态：${plain}"
    free -h | grep -E "Mem:|Swap:"
    
    # 显示swap详细信息
    echo -e "\n${cyan}Swap详细信息：${plain}"
    swapon --show
    
    # 显示系统参数
    echo -e "\n${cyan}系统参数：${plain}"
    echo -e "  swappiness: $(cat /proc/sys/vm/swappiness)"
    echo -e "  vfs_cache_pressure: $(cat /proc/sys/vm/vfs_cache_pressure)"
    
    # 显示fstab配置
    echo -e "\n${cyan}持久化配置：${plain}"
    grep swap /etc/fstab
    
    echo -e "\n${green}✅ Swap交换内存设置完成！${plain}"
    echo -e "${yellow}配置摘要：${plain}"
    echo -e "  ✓ Swap大小: ${cyan}${swap_size_gb}GB${plain}"
    echo -e "  ✓ Swap文件: ${cyan}/swapfile${plain}"
    echo -e "  ✓ 开机自动挂载: ${green}已配置${plain}"
    echo -e "  ✓ 系统优化: ${green}已完成${plain}"
    echo -e "  ✓ swappiness: ${cyan}10${plain} (降低swap使用频率)"
    echo -e "  ✓ vfs_cache_pressure: ${cyan}50${plain} (平衡缓存回收)"
    
    echo -e "\n${cyan}提示：${plain}"
    echo -e "  - Swap已立即生效，无需重启"
    echo -e "  - 重启后会自动挂载"
    echo -e "  - 如需删除swap：swapoff /swapfile && rm /swapfile"
    echo -e "  - 监控swap使用：free -h 或 htop"
}

# 服务器基本设置主菜单
server_security_menu() {
    echo -e "\n${yellow}服务器基本设置：${plain}"
    echo -e "  ${cyan}1.${plain} 添加SSH密钥登录"
    echo -e "  ${cyan}2.${plain} 禁止密码登录"
    echo -e "  ${cyan}3.${plain} 安装Fail2ban并配置（600小时封禁）"
    echo -e "  ${cyan}4.${plain} 更新系统包"
    echo -e "  ${cyan}5.${plain} 更改SSH登录端口"
    echo -e "  ${cyan}6.${plain} 设置Swap交换内存"
    read -rp "请选择操作 [1-6]: " security_choice
    
    case $security_choice in
        1)
            setup_ssh_key_login
            ;;
        2)
            disable_password_login
            ;;
        3)
            setup_fail2ban
            ;;
        4)
            update_system_packages
            ;;
        5)
            change_ssh_port
            ;;
        6)
            setup_swap_memory
            ;;
        *)
            echo -e "${red}无效的选择${plain}"
            ;;
    esac
}

# 脚本主入口
main() {
    pre_check
    
    # 检查是否首次运行，如果是则询问是否设置快捷命令
    if ! command -v isufe >/dev/null 2>&1; then
        echo -e "${yellow}检测到这是首次运行，推荐设置快捷命令${plain}"
        read -rp "是否现在设置 'isufe' 快捷命令？(y/n): " first_setup
        if [[ "$first_setup" == [Yy] ]]; then
            setup_isufe_command
            echo ""
        fi
    fi
    
    show_menu
}

# 防止谷歌送中菜单
google_protection_menu() {
    echo -e "\n${green}=== 防止谷歌送中 ===${plain}"
    echo -e "  ${cyan}1.${plain} 添加防止送中的措施"
    echo -e "  ${cyan}2.${plain} 取消送中的安全措施"
    echo -e "  ${cyan}3.${plain} 恢复默认的route.json配置"
    read -rp "请选择操作 [1-3]: " google_choice
    
    case $google_choice in
        1)
            add_google_protection
            ;;
        2)
            remove_google_protection
            ;;
        3)
            restore_default_route_config
            ;;
        *)
            echo -e "${red}无效的选择${plain}"
            ;;
    esac
}

# 解析socks链接
parse_socks_url() {
    local socks_url="$1"
    
    # 检查是否是socks5://格式
    if [[ "$socks_url" =~ ^socks5://([^:]+):([^@]+)@([^:]+):([0-9]+)$ ]]; then
        SOCKS_USER="${BASH_REMATCH[1]}"
        SOCKS_PASS="${BASH_REMATCH[2]}"
        SOCKS_HOST="${BASH_REMATCH[3]}"
        SOCKS_PORT="${BASH_REMATCH[4]}"
        return 0
    # 检查是否是user:pass@host:port格式
    elif [[ "$socks_url" =~ ^([^:]+):([^@]+)@([^:]+):([0-9]+)$ ]]; then
        SOCKS_USER="${BASH_REMATCH[1]}"
        SOCKS_PASS="${BASH_REMATCH[2]}"
        SOCKS_HOST="${BASH_REMATCH[3]}"
        SOCKS_PORT="${BASH_REMATCH[4]}"
        return 0
    else
        return 1
    fi
}

# 添加防止谷歌送中的措施
add_google_protection() {
    echo -e "\n${green}=== 添加防止谷歌送中的措施 ===${plain}"
    
    # 检查必要的配置文件是否存在
    if [[ ! -f "/etc/V2bX/custom_outbound.json" ]]; then
        echo -e "${red}错误：/etc/V2bX/custom_outbound.json 文件不存在${plain}"
        return 1
    fi
    
    if [[ ! -f "/etc/V2bX/route.json" ]]; then
        echo -e "${red}错误：/etc/V2bX/route.json 文件不存在${plain}"
        return 1
    fi
    
    # 获取socks链接
    echo -e "${yellow}请输入socks代理链接：${plain}"
    echo -e "${cyan}支持格式：${plain}"
    echo -e "  1. socks5://user:pass@host:port"
    echo -e "  2. user:pass@host:port"
    echo -e "${cyan}示例：${plain}socks5://xLx8QrYjrX:CDFU7QE75x@london3xui.848999.xyz:50010"
    read -rp "请输入socks链接: " socks_input
    
    if [[ -z "$socks_input" ]]; then
        echo -e "${red}错误：socks链接不能为空${plain}"
        return 1
    fi
    
    # 解析socks链接
    if ! parse_socks_url "$socks_input"; then
        echo -e "${red}错误：无效的socks链接格式${plain}"
        return 1
    fi
    
    echo -e "${green}解析成功：${plain}"
    echo -e "  主机: $SOCKS_HOST"
    echo -e "  端口: $SOCKS_PORT"
    echo -e "  用户: $SOCKS_USER"
    echo -e "  密码: $SOCKS_PASS"
    
    # 备份原始文件
    cp /etc/V2bX/custom_outbound.json /etc/V2bX/custom_outbound.json.bak
    cp /etc/V2bX/route.json /etc/V2bX/route.json.bak
    
    # 修改custom_outbound.json，添加google_out出站
    echo -e "\n${blue}正在修改 custom_outbound.json...${plain}"
    
    # 读取现有配置
    local current_config=$(cat /etc/V2bX/custom_outbound.json)
    
    # 检查是否已经存在google_out
    if echo "$current_config" | grep -q '"tag": "google_out"'; then
        echo -e "${yellow}警告：google_out 出站已存在，将更新配置${plain}"
        # 删除现有的google_out配置
        current_config=$(echo "$current_config" | jq 'del(.[] | select(.tag == "google_out"))')
    fi
    
    # 创建新的google_out配置
    local google_out_config=$(cat <<EOF
{
    "tag": "google_out",
    "protocol": "socks",
    "settings": {
        "servers": [
            {
                "address": "$SOCKS_HOST",
                "port": $SOCKS_PORT,
                "users": [
                    {
                        "user": "$SOCKS_USER",
                        "pass": "$SOCKS_PASS"
                    }
                ]
            }
        ]
    }
}
EOF
)
    
    # 添加新配置到数组中
    local new_config=$(echo "$current_config" | jq ". += [$google_out_config]" --argjson google_out_config "$google_out_config")
    
    # 校验 jq 输出
    if [[ -z "$new_config" || "$new_config" == "null" ]]; then
        echo -e "${red}✗ 处理 custom_outbound.json 时发生错误，未写入新内容${plain}"
        return 1
    fi
    
    # 再用 jq 校验格式
    echo "$new_config" | jq . > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e "${red}✗ 生成的 custom_outbound.json 格式有误，未写入新内容${plain}"
        return 1
    fi
    
    # 写入文件
    echo "$new_config" > /etc/V2bX/custom_outbound.json
    
    if [[ $? -eq 0 ]]; then
        echo -e "${green}✓ custom_outbound.json 更新成功${plain}"
    else
        echo -e "${red}✗ custom_outbound.json 更新失败${plain}"
        return 1
    fi
    
    # 修改route.json，添加谷歌路由规则
    echo -e "\n${blue}正在修改 route.json...${plain}"
    
    local route_config=$(cat /etc/V2bX/route.json)
    
    # 检查是否已经存在谷歌路由规则
    if echo "$route_config" | grep -q '"domain": \["geosite:google"\]'; then
        echo -e "${yellow}警告：谷歌路由规则已存在，将更新配置${plain}"
        # 删除现有的谷歌路由规则
        route_config=$(echo "$route_config" | jq '.rules = (.rules | map(select(.domain != ["geosite:google"])))')
    fi
    
    # 创建新的谷歌路由规则
    local google_rule=$(cat <<EOF
{
    "type": "field",
    "domain": ["geosite:google"],
    "outboundTag": "google_out"
}
EOF
)
    
    # 将谷歌规则插入到rules数组的开头（优先级更高）
    local new_route_config=$(echo "$route_config" | jq --argjson google_rule "$google_rule" '.rules = [$google_rule] + .rules')
    
    # 校验 jq 输出
    if [[ -z "$new_route_config" || "$new_route_config" == "null" ]]; then
        echo -e "${red}✗ 处理 route.json 时发生错误，未写入新内容${plain}"
        return 1
    fi
    
    # 再用 jq 校验格式
    echo "$new_route_config" | jq . > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e "${red}✗ 生成的 route.json 格式有误，未写入新内容${plain}"
        return 1
    fi
    
    # 写入文件
    echo "$new_route_config" > /etc/V2bX/route.json
    
    if [[ $? -eq 0 ]]; then
        echo -e "${green}✓ route.json 更新成功${plain}"
    else
        echo -e "${red}✗ route.json 更新失败${plain}"
        return 1
    fi
    
    # 修改所有hy2开头的yaml配置文件
    echo -e "\n${blue}正在修改 Hysteria2 配置文件...${plain}"
    
    local hy2_files=$(find /etc/V2bX -name "hy2*.yaml" 2>/dev/null)
    
    if [[ -z "$hy2_files" ]]; then
        echo -e "${yellow}警告：未找到 hy2*.yaml 配置文件${plain}"
    else
        for hy2_file in $hy2_files; do
            echo -e "  处理文件: $hy2_file"
            
            # 备份原文件
            cp "$hy2_file" "${hy2_file}.bak"
            
            # 创建新的配置内容
            cat > "$hy2_file" <<EOF
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

ignoreClientBandwidth: false
disableUDP: false
udpIdleTimeout: 60s

resolver:
  type: system

# --- 出站配置 ---
outbounds:
  # 这是新增的谷歌专用出站
  - name: google_out
    type: socks5
    socks5:
      addr: $SOCKS_HOST:$SOCKS_PORT
      username: $SOCKS_USER
      password: $SOCKS_PASS
  # 这是原来的默认 socks5 出站
  - name: socks5_out
    type: socks5
    socks5:
      addr: 23.142.16.246:12734
      username: vxj7qzplne
      password: mu4rtok938
  # 这是直连出站
  - name: direct
    type: direct

# --- ACL 规则 ---
acl:
  inline:
    # 规则1：局域网和私有地址，直连
    - "direct(geosite:private)"
    # 规则2：所有 Google 相关的域名，走 google_out 专用代理 (此行为已修改)
    - "google_out(geosite:google)"
    # 规则3：其他所有未匹配到的流量，全部走 socks5_out 代理
    - "socks5_out(all)"

  # GeoIP 和 GeoSite 文件路径
  geoip: geoip.dat
  geosite: geosite.dat

# --- 伪装配置保持不变 ---
masquerade:
  type: 404
EOF
    
            if [[ $? -eq 0 ]]; then
                echo -e "${green}    ✓ $hy2_file 更新成功${plain}"
            else
                echo -e "${red}    ✗ $hy2_file 更新失败${plain}"
            fi
        done
    fi
    
    # 重启V2bX服务
    echo -e "\n${blue}正在重启 V2bX 服务...${plain}"
    systemctl restart v2bx
    
    if [[ $? -eq 0 ]]; then
        echo -e "${green}✓ V2bX 服务重启成功${plain}"
    else
        echo -e "${red}✗ V2bX 服务重启失败${plain}"
        echo -e "${yellow}请手动运行: systemctl restart v2bx${plain}"
    fi
    
    echo -e "\n${green}=== 防止谷歌送中措施添加完成 ===${plain}"
    echo -e "${cyan}已完成以下操作：${plain}"
    echo -e "  1. 在 custom_outbound.json 中添加了 google_out 出站"
    echo -e "  2. 在 route.json 中添加了谷歌域名路由规则"
    echo -e "  3. 更新了所有 hy2*.yaml 配置文件"
    echo -e "  4. 重启了 V2bX 服务"
    echo -e "\n${yellow}注意：${plain}所有谷歌相关域名现在将通过专用代理访问"
}

# 恢复默认的route.json配置
restore_default_route_config() {
    echo -e "\n${green}=== 恢复默认的route.json配置 ===${plain}"
    
    echo -e "${yellow}此操作将：${plain}"
    echo -e "  1. 备份当前的 route.json 文件"
    echo -e "  2. 创建一个基础的 route.json 配置"
    echo -e "  3. 重启 V2bX 服务"
    
    read -rp "确定要继续吗？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 备份当前文件（如果存在且不为空）
    if [[ -f "/etc/V2bX/route.json" ]] && [[ -s "/etc/V2bX/route.json" ]]; then
        local backup_file="/etc/V2bX/route.json.backup.$(date +%Y%m%d_%H%M%S)"
        cp "/etc/V2bX/route.json" "$backup_file"
        echo -e "${green}已备份当前配置到：${plain}${backup_file}"
    fi
    
    # 创建默认的route.json配置
    echo -e "\n${blue}正在创建默认的 route.json 配置...${plain}"
    
    cat > /etc/V2bX/route.json << 'EOF'
{
  "domainStrategy": "AsIs",
  "rules": [
    {
      "type": "field",
      "outboundTag": "block",
      "ip": ["geoip:private"]
    },
    {
      "type": "field",
      "outboundTag": "block",
      "domain": [
        "regexp:(api|ps|sv|offnavi|newvector|ulog.imap|newloc)(.map|).(baidu|n.shifen).com",
        "regexp:(.+.|^)(360|so).(cn|com)",
        "regexp:(Subject|HELO|SMTP)",
        "regexp:(torrent|.torrent|peer_id=|info_hash|get_peers|find_node|BitTorrent|announce_peer|announce.php?passkey=)",
        "regexp:(^.@)(guerrillamail|guerrillamailblock|sharklasers|grr|pokemail|spam4|bccto|chacuo|027168).(info|biz|com|de|net|org|me|la)",
        "regexp:(.?)(xunlei|sandai|Thunder|XLLiveUD)(.)",
        "regexp:(..||)(dafahao|mingjinglive|botanwang|minghui|dongtaiwang|falunaz|epochtimes|ntdtv|falundafa|falungong|wujieliulan|zhengjian).(org|com|net)",
        "regexp:(ed2k|.torrent|peer_id=|announce|info_hash|get_peers|find_node|BitTorrent|announce_peer|announce.php?passkey=|magnet:|xunlei|sandai|Thunder|XLLiveUD|bt_key)",
        "regexp:(.+.|^)(360).(cn|com|net)",
        "regexp:(.*.||)(guanjia.qq.com|qqpcmgr|QQPCMGR)",
        "regexp:(.*.||)(rising|kingsoft|duba|xindubawukong|jinshanduba).(com|net|org)",
        "regexp:(.*.||)(netvigator|torproject).(com|cn|net|org)",
        "regexp:(..||)(visa|mycard|gash|beanfun|bank).",
        "regexp:(.*.||)(gov|12377|12315|talk.news.pts.org|creaders|zhuichaguoji|efcc.org|cyberpolice|aboluowang|tuidang|epochtimes|zhengjian|110.qq|mingjingnews|inmediahk|xinsheng|breakgfw|chengmingmag|jinpianwang|qi-gong|mhradio|edoors|renminbao|soundofhope|xizang-zhiye|bannedbook|ntdtv|12321|secretchina|dajiyuan|boxun|chinadigitaltimes|dwnews|huaglad|oneplusnews|epochweekly|cn.rfi).(cn|com|org|net|club|fr|tw|hk|eu|info|me)",
        "regexp:(.*.||)(miaozhen|cnzz|talkingdata|umeng).(cn|com)",
        "regexp:(.*.||)(mycard).(com|tw)",
        "regexp:(.*.||)(gash).(com|tw)",
        "regexp:(.bank.)",
        "regexp:(.*.||)(pincong).(rocks)",
        "regexp:(.*.||)(taobao).(com)",
        "regexp:(.*.||)(laomoe|jiyou|ssss|lolicp|vv1234|0z|4321q|868123|ksweb|mm126).(com|cloud|fun|cn|gs|xyz|cc)",
        "regexp:(flows|miaoko).(pages).(dev)"
      ]
    },
    {
      "type": "field",
      "outboundTag": "block",
      "ip": [
        "127.0.0.1/32",
        "10.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "172.16.0.0/12"
      ]
    },
    {
      "type": "field",
      "outboundTag": "block",
      "protocol": ["bittorrent"]
    }
  ]
}
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "${green}✓ 默认 route.json 配置创建成功${plain}"
    else
        echo -e "${red}✗ 创建默认 route.json 配置失败${plain}"
        return 1
    fi
    
    # 验证JSON格式
    jq . /etc/V2bX/route.json > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e "${red}✗ 生成的 route.json 格式有误${plain}"
        return 1
    fi
    
    # 重启V2bX服务
    echo -e "\n${blue}正在重启 V2bX 服务...${plain}"
    systemctl restart v2bx
    
    if [[ $? -eq 0 ]]; then
        echo -e "${green}✓ V2bX 服务重启成功${plain}"
    else
        echo -e "${red}✗ V2bX 服务重启失败${plain}"
        echo -e "${yellow}请手动运行: systemctl restart v2bx${plain}"
    fi
    
    echo -e "\n${green}=== 默认route.json配置恢复完成 ===${plain}"
    echo -e "${cyan}已创建基础的路由配置，包含：${plain}"
    echo -e "  - 基本的域名和IP拦截规则"
    echo -e "  - BT下载拦截规则"
    echo -e "  - 恶意软件拦截规则"
    echo -e "\n${yellow}注意：${plain}您可能需要根据实际需求调整路由规则"
}

# 取消防止谷歌送中的措施
remove_google_protection() {
    echo -e "\n${green}=== 取消防止谷歌送中的措施 ===${plain}"
    
    # 检查必要的配置文件是否存在
    if [[ ! -f "/etc/V2bX/custom_outbound.json" ]]; then
        echo -e "${red}错误：/etc/V2bX/custom_outbound.json 文件不存在${plain}"
        return 1
    fi
    
    if [[ ! -f "/etc/V2bX/route.json" ]]; then
        echo -e "${red}错误：/etc/V2bX/route.json 文件不存在${plain}"
        return 1
    fi
    
    # 确认操作
    echo -e "${yellow}此操作将：${plain}"
    echo -e "  1. 从 custom_outbound.json 中删除 google_out 出站"
    echo -e "  2. 从 route.json 中删除谷歌域名路由规则"
    echo -e "  3. 从所有 hy2*.yaml 配置文件中删除谷歌相关配置（保留其他配置）"
    echo -e "  4. 重启 V2bX 服务"
    
    read -rp "确定要继续吗？(y/n): " confirm
    if [[ "$confirm" != [Yy] ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    # 修改custom_outbound.json，删除google_out出站
    echo -e "\n${blue}正在修改 custom_outbound.json...${plain}"
    
    local current_config=$(cat /etc/V2bX/custom_outbound.json)
    
    # 检查文件是否为空
    if [[ -z "$current_config" ]]; then
        echo -e "${red}错误：custom_outbound.json 文件为空，无法处理${plain}"
        echo -e "${yellow}请检查 custom_outbound.json 文件内容或从备份恢复${plain}"
        return 1
    fi
    
    # 检查是否存在google_out
    if echo "$current_config" | grep -q '"tag": "google_out"'; then
        # 删除google_out配置
        local new_config=$(echo "$current_config" | jq 'del(.[] | select(.tag == "google_out"))')
        
        # 校验 jq 输出
        if [[ -z "$new_config" || "$new_config" == "null" ]]; then
            echo -e "${red}✗ 处理 custom_outbound.json 时发生错误，未写入新内容，原文件已保留${plain}"
            return 1
        fi
        
        # 再用 jq 校验格式
        echo "$new_config" | jq . > /dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            echo -e "${red}✗ 生成的 custom_outbound.json 格式有误，未写入新内容，原文件已保留${plain}"
            return 1
        fi
        
        # 写入文件
        echo "$new_config" > /etc/V2bX/custom_outbound.json
        
        if [[ $? -eq 0 ]]; then
            echo -e "${green}✓ 已从 custom_outbound.json 中删除 google_out${plain}"
        else
            echo -e "${red}✗ 删除 google_out 失败${plain}"
            return 1
        fi
    else
        echo -e "${yellow}警告：custom_outbound.json 中未找到 google_out 配置${plain}"
    fi
    
    # 修改route.json，删除谷歌路由规则
    echo -e "\n${blue}正在修改 route.json...${plain}"
    
    local route_config=$(cat /etc/V2bX/route.json)
    
    # 检查文件是否为空
    if [[ -z "$route_config" ]]; then
        echo -e "${red}错误：route.json 文件为空，无法处理${plain}"
        echo -e "${yellow}请检查 route.json 文件内容或从备份恢复${plain}"
        return 1
    fi
    
    # 检查是否存在谷歌路由规则
    if echo "$route_config" | grep -q '"domain": \["geosite:google"\]'; then
        # 删除谷歌路由规则
        local new_route_config=$(echo "$route_config" | jq '.rules = (.rules | map(select(.domain != ["geosite:google"])))')
        
        # 校验 jq 输出
        if [[ -z "$new_route_config" || "$new_route_config" == "null" ]]; then
            echo -e "${red}✗ 处理 route.json 时发生错误，未写入新内容，原文件已保留${plain}"
            return 1
        fi
        
        # 再用 jq 校验格式
        echo "$new_route_config" | jq . > /dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            echo -e "${red}✗ 生成的 route.json 格式有误，未写入新内容，原文件已保留${plain}"
            return 1
        fi
        
        # 写入文件
        echo "$new_route_config" > /etc/V2bX/route.json
        
        if [[ $? -eq 0 ]]; then
            echo -e "${green}✓ 已从 route.json 中删除谷歌路由规则${plain}"
        else
            echo -e "${red}✗ 删除谷歌路由规则失败${plain}"
            return 1
        fi
    else
        echo -e "${yellow}警告：route.json 中未找到谷歌路由规则${plain}"
    fi
    
    # 修改所有hy2开头的yaml配置文件，只删除谷歌相关配置
    echo -e "\n${blue}正在修改 Hysteria2 配置文件...${plain}"
    
    local hy2_files=$(find /etc/V2bX -name "hy2*.yaml" 2>/dev/null)
    
    if [[ -z "$hy2_files" ]]; then
        echo -e "${yellow}警告：未找到 hy2*.yaml 配置文件${plain}"
    else
        for hy2_file in $hy2_files; do
            echo -e "  处理文件: $hy2_file"
            
            # 检查文件是否存在谷歌相关配置
            if grep -q "google_out" "$hy2_file"; then
                # 创建临时文件来存储修改后的内容
                local temp_file=$(mktemp)
                
                # 删除google_out出站配置和相关ACL规则
                sed '/# 这是新增的谷歌专用出站/,/password: /d' "$hy2_file" | \
                sed '/# 规则2：所有 Google 相关的域名，走 google_out 专用代理/d' | \
                sed '/- "google_out(geosite:google)"/d' > "$temp_file"
                
                # 将修改后的内容写回原文件
                if mv "$temp_file" "$hy2_file"; then
                    echo -e "${green}    ✓ $hy2_file 中的谷歌配置已删除${plain}"
                else
                    echo -e "${red}    ✗ $hy2_file 修改失败${plain}"
                    rm -f "$temp_file"
                fi
            else
                echo -e "${yellow}    警告：$hy2_file 中未找到谷歌配置${plain}"
            fi
            
            # 删除备份文件
            local backup_file="${hy2_file}.bak"
            if [[ -f "$backup_file" ]]; then
                rm -f "$backup_file"
            fi
        done
    fi
    
    # 恢复其他配置文件的备份
    echo -e "\n${blue}正在恢复配置文件备份...${plain}"
    
    if [[ -f "/etc/V2bX/custom_outbound.json.bak" ]]; then
        echo -e "  恢复 custom_outbound.json 备份"
        rm -f "/etc/V2bX/custom_outbound.json.bak"
    fi
    
    if [[ -f "/etc/V2bX/route.json.bak" ]]; then
        echo -e "  恢复 route.json 备份"
        rm -f "/etc/V2bX/route.json.bak"
    fi
    
    # 重启V2bX服务
    echo -e "\n${blue}正在重启 V2bX 服务...${plain}"
    systemctl restart v2bx
    
    if [[ $? -eq 0 ]]; then
        echo -e "${green}✓ V2bX 服务重启成功${plain}"
    else
        echo -e "${red}✗ V2bX 服务重启失败${plain}"
        echo -e "${yellow}请手动运行: systemctl restart v2bx${plain}"
    fi
    
    echo -e "\n${green}=== 防止谷歌送中措施已取消 ===${plain}"
    echo -e "${cyan}已完成以下操作：${plain}"
    echo -e "  1. 从 custom_outbound.json 中删除了 google_out 出站"
    echo -e "  2. 从 route.json 中删除了谷歌域名路由规则"
    echo -e "  3. 从所有 hy2*.yaml 配置文件中删除了谷歌相关配置"
    echo -e "  4. 重启了 V2bX 服务"
    echo -e "\n${yellow}注意：${plain}谷歌相关域名现在将使用默认路由规则，其他socks配置保持不变"
}

# 删除脚本并卸载isufe快捷命令
uninstall_script() {
    echo -e "${red}=== 删除脚本并卸载isufe快捷命令 ===${plain}"
    
    echo -e "${red}⚠ 警告：此操作将完全删除脚本和所有相关文件！${plain}"
    echo -e "${yellow}将要执行的操作：${plain}"
    echo -e "  1. 删除isufe快捷命令"
    echo -e "  2. 删除脚本文件"
    echo -e "  3. 清理用户别名配置"
    echo -e "  4. 清理相关备份文件"
    
    echo -e "\n${red}此操作不可逆，请确认您真的要删除脚本！${plain}"
    read -rp "请输入 'DELETE' 确认删除: " confirm_delete
    
    if [[ "$confirm_delete" != "DELETE" ]]; then
        echo -e "${yellow}操作已取消${plain}"
        return 0
    fi
    
    echo -e "\n${yellow}开始执行删除操作...${plain}"
    
    # 1. 删除isufe快捷命令
    echo -e "${yellow}步骤1: 删除isufe快捷命令...${plain}"
    
    # 检查并删除符号链接
    local isufe_paths=("/usr/local/bin/isufe" "/usr/bin/isufe")
    for path in "${isufe_paths[@]}"; do
        if [[ -L "$path" ]]; then
            echo -e "${cyan}删除符号链接: $path${plain}"
            if sudo rm -f "$path" 2>/dev/null; then
                echo -e "${green}✓ 已删除: $path${plain}"
            else
                echo -e "${red}✗ 删除失败: $path${plain}"
            fi
        elif [[ -f "$path" ]]; then
            echo -e "${cyan}删除文件: $path${plain}"
            if sudo rm -f "$path" 2>/dev/null; then
                echo -e "${green}✓ 已删除: $path${plain}"
            else
                echo -e "${red}✗ 删除失败: $path${plain}"
            fi
        fi
    done
    
    # 2. 删除脚本文件
    echo -e "\n${yellow}步骤2: 删除脚本文件...${plain}"
    
    local script_path=$(realpath "$0")
    local persistent_script="/usr/local/bin/super-tool.sh"
    
    # 删除当前脚本（如果不是从/proc运行）
    if [[ "$script_path" != /proc/* ]] && [[ -f "$script_path" ]]; then
        echo -e "${cyan}删除脚本文件: $script_path${plain}"
        if rm -f "$script_path" 2>/dev/null; then
            echo -e "${green}✓ 已删除: $script_path${plain}"
        else
            echo -e "${red}✗ 删除失败: $script_path${plain}"
        fi
    fi
    
    # 删除持久化脚本
    if [[ -f "$persistent_script" ]]; then
        echo -e "${cyan}删除持久化脚本: $persistent_script${plain}"
        if sudo rm -f "$persistent_script" 2>/dev/null; then
            echo -e "${green}✓ 已删除: $persistent_script${plain}"
        else
            echo -e "${red}✗ 删除失败: $persistent_script${plain}"
        fi
    fi
    
    # 3. 清理用户别名配置
    echo -e "\n${yellow}步骤3: 清理用户别名配置...${plain}"
    
    local shell_configs=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile")
    for config in "${shell_configs[@]}"; do
        if [[ -f "$config" ]]; then
            echo -e "${cyan}清理别名配置: $config${plain}"
            # 备份配置文件
            cp "$config" "${config}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
            
            # 删除isufe别名
            if grep -q "alias isufe=" "$config"; then
                sed -i.bak "/alias isufe=/d" "$config" 2>/dev/null || true
                echo -e "${green}✓ 已清理别名: $config${plain}"
            fi
        fi
    done
    
    # 4. 清理相关备份文件
    echo -e "\n${yellow}步骤4: 清理相关备份文件...${plain}"
    
    # 查找并删除相关的备份文件
    local backup_patterns=(
        "$HOME/.bashrc.backup.*"
        "$HOME/.zshrc.backup.*"
        "$HOME/.profile.backup.*"
        "$HOME/.bash_profile.backup.*"
        "/usr/local/bin/super-tool.sh.backup.*"
    )
    
    for pattern in "${backup_patterns[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                echo -e "${cyan}删除备份文件: $file${plain}"
                rm -f "$file" 2>/dev/null || true
            fi
        done 2>/dev/null || true
    done
    
    # 5. 验证删除结果
    echo -e "\n${yellow}步骤5: 验证删除结果...${plain}"
    
    local deletion_success=true
    
    # 检查isufe命令是否还存在
    if command -v isufe >/dev/null 2>&1; then
        echo -e "${red}⚠ isufe命令仍然存在: $(which isufe)${plain}"
        deletion_success=false
    else
        echo -e "${green}✓ isufe命令已成功删除${plain}"
    fi
    
    # 检查脚本文件是否还存在
    if [[ -f "$script_path" ]]; then
        echo -e "${red}⚠ 脚本文件仍然存在: $script_path${plain}"
        deletion_success=false
    else
        echo -e "${green}✓ 脚本文件已成功删除${plain}"
    fi
    
    if [[ -f "$persistent_script" ]]; then
        echo -e "${red}⚠ 持久化脚本仍然存在: $persistent_script${plain}"
        deletion_success=false
    else
        echo -e "${green}✓ 持久化脚本已成功删除${plain}"
    fi
    
    # 6. 完成提示
    echo -e "\n${green}=== 删除操作完成 ===${plain}"
    
    if [[ "$deletion_success" == true ]]; then
        echo -e "${green}✓ 脚本和isufe快捷命令已成功删除！${plain}"
        echo -e "${yellow}提示：${plain}"
        echo -e "  - 如果当前会话中有别名，请重新登录或运行 'source ~/.bashrc' 使更改生效"
        echo -e "  - 所有相关文件已清理完毕"
        echo -e "  - 感谢您使用super-tool脚本！"
    else
        echo -e "${yellow}⚠ 部分文件删除失败，请手动检查${plain}"
        echo -e "${cyan}建议手动删除以下文件：${plain}"
        echo -e "  - $(which isufe 2>/dev/null || echo "isufe命令位置")"
        echo -e "  - $script_path"
        echo -e "  - $persistent_script"
    fi
    
    echo -e "\n${red}脚本将在5秒后退出...${plain}"
    sleep 5
    exit 0
}

############################################################
# 功能 18: 增加V2bX节点
############################################################

# 增加V2bX节点主函数
add_v2bx_node() {
    echo -e "${green}=== 增加V2bX节点 ===${plain}"
    
    local config_file="/etc/V2bX/config.json"
    
    # 检查配置文件是否存在
    if [[ ! -f "$config_file" ]]; then
        echo -e "${red}错误：V2bX配置文件 $config_file 不存在${plain}"
        echo -e "${yellow}请先安装V2bX（选择功能2）${plain}"
        return 1
    fi
    
    local added_nodes=0
    local continue_adding=true
    
    while $continue_adding; do
        # 显示当前节点信息
        show_current_nodes
        
        # 获取节点信息
        echo -e "\n${yellow}请输入新节点信息：${plain}"
        
        local node_id
        while true; do
            read -rp "节点ID（数字）: " node_id
            if [[ "$node_id" =~ ^[0-9]+$ ]]; then
                # 检查节点ID是否已存在
                if check_node_id_exists "$node_id"; then
                    echo -e "${red}错误：节点ID $node_id 已存在，请选择其他ID${plain}"
                    continue
                fi
                break
            else
                echo -e "${red}错误：请输入有效的数字${plain}"
            fi
        done
        
        # 选择节点类型
        echo -e "\n${yellow}请选择节点类型：${plain}"
        echo -e "  ${cyan}1.${plain} vless"
        echo -e "  ${cyan}2.${plain} shadowsocks"
        echo -e "  ${cyan}3.${plain} hysteria2"
        
        local node_type
        while true; do
            read -rp "请选择节点类型 [1-3]: " type_choice
            case $type_choice in
                1)
                    node_type="vless"
                    break
                    ;;
                2)
                    node_type="shadowsocks"
                    break
                    ;;
                3)
                    node_type="hysteria2"
                    break
                    ;;
                *)
                    echo -e "${red}无效选择，请输入1-3${plain}"
                    ;;
            esac
        done
        
        # 根据节点类型添加节点
        local add_success=false
        case $node_type in
            "vless"|"shadowsocks")
                if add_xray_node "$node_id" "$node_type"; then
                    add_success=true
                fi
                ;;
            "hysteria2")
                if add_hysteria2_node "$node_id"; then
                    add_success=true
                fi
                ;;
        esac
        
        # 如果添加成功，增加计数器
        if $add_success; then
            ((added_nodes++))
        fi
        
        # 询问是否继续添加节点
        echo -e "\n${yellow}是否继续添加更多节点？${plain}"
        read -rp "继续添加 (y/n): " continue_choice
        if [[ "$continue_choice" != [Yy] ]]; then
            continue_adding=false
        fi
    done
    
    # 显示添加结果总结
    echo -e "\n${green}=== 节点添加完成 ===${plain}"
    echo -e "${yellow}本次共添加了 ${cyan}${added_nodes}${plain} ${yellow}个节点${plain}"
    
    if [[ $added_nodes -gt 0 ]]; then
        echo -e "\n${yellow}重要提示：${plain}"
        echo -e "  ${cyan}请重启V2bX服务使所有新节点生效：${plain}"
        echo -e "  ${green}systemctl restart V2bX${plain}"
        echo -e "\n${yellow}建议操作：${plain}"
        echo -e "  1. 检查服务状态：${cyan}systemctl status V2bX${plain}"
        echo -e "  2. 查看服务日志：${cyan}journalctl -u V2bX -f${plain}"
        echo -e "  3. 验证节点配置：${cyan}检查面板中的节点状态${plain}"
    fi
}

# 显示当前节点信息
show_current_nodes() {
    echo -e "\n${cyan}当前V2bX节点信息：${plain}"
    
    python3 << 'EOF'
import json
import sys

config_file = "/etc/V2bX/config.json"

try:
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    # 显示Cores配置
    cores = config.get('Cores', [])
    if cores:
        print(f"  可用核心: {len(cores)} 个")
        for i, core in enumerate(cores, 1):
            core_type = core.get('Type', 'N/A')
            print(f"    {i}. {core_type}")
    else:
        print("  警告: 未找到核心配置")
    
    # 显示节点配置
    nodes = config.get('Nodes', [])
    if not nodes:
        print("  暂无节点")
        sys.exit(0)
    
    print(f"\n  共有 {len(nodes)} 个节点:")
    for i, node in enumerate(nodes, 1):
        node_id = node.get('NodeID', 'N/A')
        node_type = node.get('NodeType', 'N/A')
        api_host = node.get('ApiHost', 'N/A')
        core = node.get('Core', 'N/A')
        
        # 对于hysteria2节点，显示额外信息
        if core == 'hysteria2':
            cert_domain = node.get('CertConfig', {}).get('CertDomain', 'N/A')
            print(f"  {i}. ID: {node_id}, 类型: {node_type}, 核心: {core}, 主机: {api_host}, 证书域名: {cert_domain}")
        else:
            print(f"  {i}. ID: {node_id}, 类型: {node_type}, 核心: {core}, 主机: {api_host}")
        
except Exception as e:
    print(f"读取配置文件时出错: {e}")
    sys.exit(1)
EOF
}

# 检查节点ID是否已存在
check_node_id_exists() {
    local node_id="$1"
    
    python3 << EOF
import json
import sys

config_file = "/etc/V2bX/config.json"
target_id = int("$node_id")

try:
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    nodes = config.get('Nodes', [])
    for node in nodes:
        if node.get('NodeID') == target_id:
            sys.exit(0)  # 节点ID已存在
    
    sys.exit(1)  # 节点ID不存在
    
except Exception as e:
    print(f"检查节点ID时出错: {e}")
    sys.exit(1)
EOF
    
    return $?
}

# 添加xray节点（vless/shadowsocks）
add_xray_node() {
    local node_id="$1"
    local node_type="$2"
    
    echo -e "\n${green}添加 ${node_type} 节点（ID: ${node_id}）${plain}"
    
    # 备份配置文件
    local backup_file="/etc/V2bX/config.json.backup.$(date +%Y%m%d_%H%M%S)"
    cp "/etc/V2bX/config.json" "$backup_file"
    echo -e "${green}已备份配置文件到：${plain}${backup_file}"
    
    # 添加节点
    python3 << EOF
import json
import sys
from datetime import datetime

def add_xray_node():
    config_file = "/etc/V2bX/config.json"
    node_id = int("$node_id")
    node_type = "$node_type"
    
    try:
        # 读取现有配置
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # 创建新节点配置
        new_node = {
            "Core": "xray",
            "ApiHost": "https://www.isufe.me",
            "ApiKey": "ycUIogRFk8njnqLd4yqP0jaetB5H+Ya5cknDxDHb2UA=",
            "NodeID": node_id,
            "NodeType": node_type,
            "Timeout": 30,
            "ListenIP": "0.0.0.0",
            "SendIP": "0.0.0.0",
            "DeviceOnlineMinTraffic": 200,
            "EnableProxyProtocol": False,
            "EnableUot": True,
            "EnableTFO": True,
            "DNSType": "UseIPv4",
            "CertConfig": {
                "CertMode": "none",
                "RejectUnknownSni": False,
                "CertDomain": "example.com",
                "CertFile": "/etc/V2bX/fullchain.cer",
                "KeyFile": "/etc/V2bX/cert.key",
                "Email": "v2bx@github.com",
                "Provider": "cloudflare",
                "DNSEnv": {
                    "EnvName": "env1"
                }
            }
        }
        
        # 添加节点到配置
        if 'Nodes' not in config:
            config['Nodes'] = []
        
        config['Nodes'].append(new_node)
        
        # 写回配置文件
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        
        print(f"✅ 成功添加 {node_type} 节点（ID: {node_id}）")
        print(f"   - 核心: xray")
        print(f"   - 主机: https://www.isufe.me")
        print(f"   - 类型: {node_type}")
        print(f"   - 监听IP: 0.0.0.0")
        print(f"   - 证书模式: none")
        
        return True
        
    except Exception as e:
        print(f"添加节点时出错: {e}")
        return False

if __name__ == "__main__":
    success = add_xray_node()
    sys.exit(0 if success else 1)
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "\n${green}✅ ${node_type} 节点添加成功（ID: ${node_id}）${plain}"
        return 0
    else
        echo -e "${red}❌ 添加节点失败${plain}"
        echo -e "${yellow}可以使用备份文件恢复：${plain}"
        echo -e "${cyan}cp ${backup_file} /etc/V2bX/config.json${plain}"
        return 1
    fi
}

# 添加hysteria2节点
add_hysteria2_node() {
    local node_id="$1"
    
    echo -e "\n${green}添加 hysteria2 节点（ID: ${node_id}）${plain}"
    
    # 获取证书域名
    local cert_domain
    while true; do
        read -rp "请输入证书域名（如：ushome01.388898.xyz）: " cert_domain
        if [[ -n "$cert_domain" ]]; then
            break
        else
            echo -e "${red}错误：证书域名不能为空${plain}"
        fi
    done
    
    # 备份配置文件
    local backup_file="/etc/V2bX/config.json.backup.$(date +%Y%m%d_%H%M%S)"
    cp "/etc/V2bX/config.json" "$backup_file"
    echo -e "${green}已备份配置文件到：${plain}${backup_file}"
    
    # 添加节点
    python3 << EOF
import json
import sys
from datetime import datetime

def add_hysteria2_node():
    config_file = "/etc/V2bX/config.json"
    node_id = int("$node_id")
    cert_domain = "$cert_domain"
    
    try:
        # 读取现有配置
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # 确保Cores配置存在且包含hysteria2
        if 'Cores' not in config:
            config['Cores'] = []
        
        # 检查是否已有hysteria2核心配置
        has_hysteria2_core = False
        for core in config['Cores']:
            if core.get('Type') == 'hysteria2':
                has_hysteria2_core = True
                break
        
        # 如果没有hysteria2核心配置，添加一个
        if not has_hysteria2_core:
            hysteria2_core = {
                "Type": "hysteria2",
                "Log": {
                    "Level": "error"
                }
            }
            config['Cores'].append(hysteria2_core)
            print("✅ 已添加hysteria2核心配置")
        
        # 创建新节点配置（完全按照用户提供的模板）
        new_node = {
            "Core": "hysteria2",
            "ApiHost": "https://www.isufe.me",
            "ApiKey": "ycUIogRFk8njnqLd4yqP0jaetB5H+Ya5cknDxDHb2UA=",
            "NodeID": node_id,
            "NodeType": "hysteria2",
            "Hysteria2ConfigPath": "/etc/V2bX/hy2config.yaml",
            "Timeout": 30,
            "ListenIP": "",
            "SendIP": "0.0.0.0",
            "DeviceOnlineMinTraffic": 200,
            "CertConfig": {
                "CertMode": "dns",
                "RejectUnknownSni": False,
                "CertDomain": cert_domain,
                "CertFile": "/etc/V2bX/fullchain.cer",
                "KeyFile": "/etc/V2bX/cert.key",
                "Email": "v2bx@github.com",
                "Provider": "cloudflare",
                "DNSEnv": {
                    "CLOUDFLARE_DNS_API_TOKEN": "0GLqZFZPM36ikBhiR3M2pJtAFHI1qUW3YF4Unqi0"
                }
            }
        }
        
        # 添加节点到配置
        if 'Nodes' not in config:
            config['Nodes'] = []
        
        config['Nodes'].append(new_node)
        
        # 写回配置文件
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        
        print(f"✅ 成功添加 hysteria2 节点（ID: {node_id}）")
        print(f"   - 核心: hysteria2")
        print(f"   - 主机: https://www.isufe.me")
        print(f"   - 类型: hysteria2")
        print(f"   - 证书域名: {cert_domain}")
        print(f"   - 证书模式: dns（自动使用DNS签名）")
        print(f"   - 配置文件: /etc/V2bX/hy2config.yaml")
        
        return True
        
    except Exception as e:
        print(f"添加节点时出错: {e}")
        return False

if __name__ == "__main__":
    success = add_hysteria2_node()
    sys.exit(0 if success else 1)
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "\n${green}✅ hysteria2 节点添加成功（ID: ${node_id}）${plain}"
        echo -e "${yellow}证书配置信息：${plain}"
        echo -e "  - 证书域名: ${cyan}${cert_domain}${plain}"
        echo -e "  - 证书模式: ${cyan}dns（自动DNS签名）${plain}"
        echo -e "  - 提供商: ${cyan}cloudflare${plain}"
        echo -e "\n${yellow}重要提示：${plain}"
        echo -e "  - 已确保配置文件包含hysteria2核心配置"
        echo -e "  - 节点配置完全按照标准模板生成"
        return 0
    else
        echo -e "${red}❌ 添加节点失败${plain}"
        echo -e "${yellow}可以使用备份文件恢复：${plain}"
        echo -e "${cyan}cp ${backup_file} /etc/V2bX/config.json${plain}"
        return 1
    fi
}

# 执行主函数
main