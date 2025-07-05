#!/bin/bash

#====================================================
# 多功能服务器工具脚本
#
#   功能 1: 设置 IPTables 端口转发并持久化
#   功能 2: 安装/更新 V2bX
#   功能 3: 为 Hysteria2 节点设置出站规则
#   功能 4: 为 vless/shadowsocks 节点配置出站规则
#   功能 5: 移除银行和支付站点拦截规则
#   功能 6: 安装哪吒探针
#   功能 7: 安装1Panel管理面板
#   功能 8: 执行网络测速
#   功能 9: 设置isufe快捷命令
#   功能 10: 一键式OpenVPN策略路由设置
#   功能 11: 安装3x-ui面板
#   功能 12: 更新脚本到最新版本
#
#   作者: Gemini (基于用户需求优化)
#   版本: 3.5
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

    # 获取用户输入
    read -rp "请选择协议 (1 for TCP, 2 for UDP, 3 for Both): " proto_choice
    read -rp "请输入要转发的源端口或端口范围 (例如 8000 或 10000:20000): " source_ports
    read -rp "请输入目标端口 (流量将被重定向到此端口): " dest_port

    # 输入验证
    if [[ -z "$source_ports" || -z "$dest_port" ]]; then
        echo -e "${red}错误：源端口和目标端口不能为空！${plain}"
        return 1
    fi
    # 简单验证端口格式
    if ! [[ "$source_ports" =~ ^[0-9]+(:[0-9]+)?$ && "$dest_port" =~ ^[0-9]+$ ]]; then
        echo -e "${red}错误：端口格式不正确！${plain}"
        return 1
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
            return 1
            ;;
    esac
    
    # 如果规则应用成功，则持久化
    if [[ $success -eq 0 ]]; then
        persist_rules
        echo -e "\n${green}端口转发设置完成！${plain}"
        echo -e "${yellow}当前PREROUTING规则列表:${plain}"
        iptables -t nat -L PREROUTING -n --line-numbers
    fi
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
                # 确认配置
                echo -e "\n${yellow}请确认节点 ${node_id} 的出站配置：${plain}"
                echo -e "  节点ID: ${cyan}${node_id}${plain}"
                echo -e "  配置文件: ${cyan}${config_path}${plain}"
                echo -e "  SOCKS5服务器: ${cyan}${host}:${port}${plain}"
                echo -e "  用户名: ${cyan}${username}${plain}"
                echo -e "  密码: ${cyan}${password}${plain}"
                
                read -rp "确认创建此配置？(y/n): " confirm
                if [[ "$confirm" == [Yy] ]]; then
                    # 创建配置目录
                    mkdir -p "$(dirname "$config_path")"
                    
                    # 生成配置文件
                    generate_hy2_config "$config_path" "$host" "$port" "$username" "$password"
                    
                    echo -e "${green}节点 ${node_id} 配置完成！${plain}"
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
            if node.get('NodeType') in ['vless', 'shadowsocks']:
                nodes.append({
                    'NodeID': node.get('NodeID'),
                    'NodeType': node.get('NodeType'),
                    'ApiHost': node.get('ApiHost', '')
                })
    
    if nodes:
        for node in nodes:
            api_host = node['ApiHost'].replace('https://', '').replace('http://', '')
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
    local node_mappings="$1"  # 格式: "NodeID:NodeType:ApiHost:SocksTag,..."
    
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
            parts = mapping.strip().split(':')
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
    
    # 节点映射
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
                    node_mappings="${node_mappings},${node_id}:${node_type}:${api_host}:${selected_socks}"
                else
                    node_mappings="${node_id}:${node_type}:${api_host}:${selected_socks}"
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

route_file = "$route_file"

# 需要移除的支付相关规则模式
payment_patterns = [
    r'regexp:\(\.bank\.\)',  # .bank. 域名
    r'regexp:\(\.\*\|\|\)\(visa\|mycard\|gash\|beanfun\|bank\)\.',  # visa|mycard|gash|beanfun|bank
    r'regexp:\(\.\*\|\|\)\(mycard\)\.\(com\|tw\)',  # mycard.(com|tw)
    r'regexp:\(\.\*\|\|\)\(gash\)\.\(com\|tw\)',    # gash.(com|tw)
]

try:
    # 读取配置文件
    with open(route_file, 'r') as f:
        config = json.load(f)
    
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
                    should_remove = False
                    for pattern in payment_patterns:
                        if re.search(pattern, domain):
                            should_remove = True
                            removed_count += 1
                            print(f"移除规则: {domain}")
                            break
                    
                    if not should_remove:
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

route_file = "$route_file"

# 支付相关规则模式
payment_patterns = {
    'bank': r'regexp:\(\.bank\.\)',
    'visa_mycard_gash_beanfun': r'regexp:\(\.\*\|\|\)\(visa\|mycard\|gash\|beanfun\|bank\)\.',
    'mycard_sites': r'regexp:\(\.\*\|\|\)\(mycard\)\.\(com\|tw\)',
    'gash_sites': r'regexp:\(\.\*\|\|\)\(gash\)\.\(com\|tw\)',
}

try:
    with open(route_file, 'r') as f:
        config = json.load(f)
    
    if 'rules' not in config:
        print("配置文件中未找到 rules 字段")
        return
    
    found_blocks = {}
    
    # 检查是否存在支付相关的阻断规则
    for rule in config['rules']:
        if rule.get('type') == 'field' and rule.get('outboundTag') == 'block':
            domains = rule.get('domain', [])
            for domain in domains:
                for name, pattern in payment_patterns.items():
                    if re.search(pattern, domain):
                        if name not in found_blocks:
                            found_blocks[name] = []
                        found_blocks[name].append(domain)
    
    if found_blocks:
        print("发现以下支付站点拦截规则:")
        for name, rules in found_blocks.items():
            print(f"  {name}: {len(rules)} 条规则")
            for rule in rules:
                print(f"    - {rule}")
    else:
        print("未发现支付站点拦截规则 - 所有支付站点应该可以正常访问")
    
except Exception as e:
    print(f"检查配置文件时出错: {e}")
EOF
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
    
    # 删除所有带有main_route表的规则
    while ip rule list | grep -q "main_route"; do
        local rule_prio=$(ip rule list | grep "main_route" | head -1 | awk '{print $1}' | tr -d ':')
        if [[ -n "$rule_prio" ]]; then
            ip rule del prio "$rule_prio" >/dev/null 2>&1
        else
            break
        fi
    done
    
    # 删除所有带有fwmark 0x100的规则
    while ip rule list | grep -q "fwmark 0x100"; do
        local rule_prio=$(ip rule list | grep "fwmark 0x100" | head -1 | awk '{print $1}' | tr -d ':')
        if [[ -n "$rule_prio" ]]; then
            ip rule del prio "$rule_prio" >/dev/null 2>&1
        else
            break
        fi
    done
    
    # 清空main_route路由表
    ip route flush table main_route >/dev/null 2>&1
    
    # 清理iptables规则
    echo -e "${yellow}正在清理iptables规则...${plain}"
    
    # 清理mangle表中的MARK和CONNMARK规则
    iptables -t mangle -D PREROUTING -j CONNMARK --save-mark >/dev/null 2>&1
    iptables -t mangle -D OUTPUT -j CONNMARK --restore-mark >/dev/null 2>&1
    
    # 清理所有带有MARK --set-mark 0x100的规则
    while iptables -t mangle -L PREROUTING -n --line-numbers | grep -q "MARK.*0x100"; do
        local line_num=$(iptables -t mangle -L PREROUTING -n --line-numbers | grep "MARK.*0x100" | head -1 | awk '{print $1}')
        if [[ -n "$line_num" ]]; then
            iptables -t mangle -D PREROUTING "$line_num" >/dev/null 2>&1
        else
            break
        fi
    done
    
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
FWMARK="0x100"
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
    
    # 清理策略路由规则
    while ip rule list | grep -q "main_route"; do
        local rule_prio=$(ip rule list | grep "main_route" | head -1 | awk '{print $1}' | tr -d ':')
        if [[ -n "$rule_prio" ]]; then
            ip rule del prio "$rule_prio" >/dev/null 2>&1
        else
            break
        fi
    done
    
    # 清理fwmark规则
    while ip rule list | grep -q "fwmark $FWMARK"; do
        local rule_prio=$(ip rule list | grep "fwmark $FWMARK" | head -1 | awk '{print $1}' | tr -d ':')
        if [[ -n "$rule_prio" ]]; then
            ip rule del prio "$rule_prio" >/dev/null 2>&1
        else
            break
        fi
    done
    
    # 清空路由表
    ip route flush table "$TABLE_ID" >/dev/null 2>&1
    
    # 清理iptables规则
    iptables -t mangle -D PREROUTING -j CONNMARK --save-mark >/dev/null 2>&1
    iptables -t mangle -D OUTPUT -j CONNMARK --restore-mark >/dev/null 2>&1
    
    # 清理MARK规则
    while iptables -t mangle -L PREROUTING -n --line-numbers | grep -q "MARK.*$FWMARK"; do
        local line_num=$(iptables -t mangle -L PREROUTING -n --line-numbers | grep "MARK.*$FWMARK" | head -1 | awk '{print $1}')
        if [[ -n "$line_num" ]]; then
            iptables -t mangle -D PREROUTING "$line_num" >/dev/null 2>&1
        else
            break
        fi
    done
    
    # 恢复内核参数
    sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1
    
    # 检测主网卡并恢复其rp_filter
    local main_if=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {print $5}' | head -1)
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

############################################################
# 选项 10: 一键式OpenVPN策略路由设置
############################################################

setup_openvpn_routing() {
    echo -e "${green}=== 一键式OpenVPN策略路由设置 ===${plain}"
    
    echo -e "${yellow}此功能将帮助您设置OpenVPN策略路由，保持SSH连接不断开${plain}"
    echo -e "${cyan}功能特性：${plain}"
    echo -e "  - 自动检测网络环境"
    echo -e "  - 创建独立路由表保留SSH连接"
    echo -e "  - 生成route-up和route-down脚本"
    echo -e "  - 修改OpenVPN配置启用策略路由"
    echo -e "  - 所有出站流量通过VPN，SSH连接保持直连"
    echo -e "  - ${green}新增：VPN断线自动恢复原始网络设置${plain}"
    
    echo -e "\n${yellow}请选择操作模式：${plain}"
    echo -e "  ${cyan}1.${plain} 新建OpenVPN配置 (默认)"
    echo -e "  ${cyan}2.${plain} 修改现有OpenVPN配置"
    echo -e "  ${cyan}3.${plain} 恢复原始网络设置 (清理所有VPN路由)"
    
    local operation_mode
    read -rp "请选择操作模式 [1-3] (默认1): " operation_mode
    
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

    echo -e "${YELLOW}正在创建优化的 route-up.sh 脚本...${NC}"
    cat << EOL > "$up_script"
#!/bin/bash
# -- 根据您的环境自动填充的变量 --
GATEWAY_IP="${GATEWAY_IP}"
MAIN_IF="${MAIN_IF}"
# -- 配置参数 --
FWMARK="0x100"
TABLE_ID="main_route"
# 等待网络接口就绪
sleep 5
# --- 第1部分：确保内核参数允许策略路由 ---
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
sysctl -w net.ipv4.conf.\${MAIN_IF}.rp_filter=2
# --- 第2部分：配置iptables，为入站连接打标记 ---
iptables -t mangle -A PREROUTING -i \${MAIN_IF} -j MARK --set-mark \${FWMARK}
iptables -t mangle -A PREROUTING -j CONNMARK --save-mark
iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark
# --- 第3部分：配置策略路由 ---
ip route replace default via \${GATEWAY_IP} dev \${MAIN_IF} table \${TABLE_ID}
ip rule add fwmark \${FWMARK} table \${TABLE_ID} prio 100
# --- 第4部分：刷新路由缓存 ---
ip route flush cache
exit 0
EOL
    echo -e "${GREEN}  -> 脚本 '$up_script' 已创建。${NC}"

    echo -e "${YELLOW}正在创建优化的 route-down.sh 脚本...${NC}"
    cat << EOL > "$down_script"
#!/bin/bash
FWMARK="0x100"
TABLE_ID="main_route"
MAIN_IF="${MAIN_IF}"
# -- 清除规则 (与添加顺序相反) --
ip rule del prio 100
ip route flush table \${TABLE_ID}
iptables -t mangle -D OUTPUT -j CONNMARK --restore-mark
iptables -t mangle -D PREROUTING -j CONNMARK --save-mark
iptables -t mangle -D PREROUTING -i \${MAIN_IF} -j MARK --set-mark \${FWMARK}
# -- 恢复内核默认值 --
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.conf.\${MAIN_IF}.rp_filter=1
# 刷新路由缓存
ip route flush cache
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
# 选项 12: 更新脚本到最新版本
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
# 主菜单和脚本执行逻辑
############################################################

show_menu() {
    echo -e "
  ${green}多功能服务器工具脚本 (v3.5)${plain}
  ---
  ${yellow}0.${plain} 退出脚本
  ${yellow}1.${plain} 设置端口转发 (IPTables Redirect)
  ${yellow}2.${plain} 安装 / 更新 V2bX
  ${yellow}3.${plain} 为 Hysteria2 节点设置出站规则
  ${yellow}4.${plain} 为 vless/shadowsocks 节点配置出站规则
  ${yellow}5.${plain} 移除银行和支付站点拦截规则
  ${yellow}6.${plain} 安装哪吒探针
  ${yellow}7.${plain} 安装1Panel管理面板
  ${yellow}8.${plain} 执行网络测速
  ${yellow}9.${plain} 设置isufe快捷命令
  ${yellow}10.${plain} 一键式OpenVPN策略路由设置 (含故障恢复)
  ${yellow}11.${plain} 安装3x-ui面板
  ${yellow}12.${plain} 更新脚本到最新版本
  ---"
    read -rp "请输入选项 [0-12]: " choice
    
    case $choice in
        0)
            exit 0
            ;;
        1)
            setup_port_forwarding
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
            # 提供子选项：查看状态或移除拦截
            echo -e "\n${yellow}支付站点拦截管理：${plain}"
            echo -e "  ${cyan}1.${plain} 查看当前拦截状态"
            echo -e "  ${cyan}2.${plain} 移除银行和支付站点拦截规则"
            read -rp "请选择操作 [1-2]: " payment_choice
            
            case $payment_choice in
                1)
                    show_payment_block_status
                    ;;
                2)
                    remove_payment_blocks
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
            update_script
            ;;
        *)
            echo -e "${red}无效的选项，请输入 0-12${plain}"
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

# 执行主函数
main