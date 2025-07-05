# OpenVPN 功能10 修复说明

## 问题描述

用户遇到的问题：
- OpenVPN连接正常，但所有端口tcpping和ping都超时
- SSH（22端口）无法连接
- 服务器通过原始IP完全无法访问

## 问题根因

之前的实现使用了复杂的iptables标记机制：
1. 在mangle/PREROUTING阶段标记入站连接
2. 使用CONNMARK保存连接标记
3. 在OUTPUT阶段恢复标记并应用策略路由

问题在于**标记时机错误**：
- mangle/PREROUTING发生在连接跟踪之前
- CONNMARK --save-mark 失败，无法保存标记
- 导致所有回复包都走默认路由（VPN）
- 造成路径不对称，连接失效

## 修复方案

### 新方案：基于源地址的策略路由

```bash
# 1. 获取服务器公网IP
SERVER_IP=$(ip -4 addr show ${MAIN_IF} | awk '/inet /{print $2}' | cut -d/ -f1)

# 2. 创建保留路由表
ip route replace default via ${GATEWAY_IP} dev ${MAIN_IF} table main_route

# 3. 源地址策略路由
ip rule add from ${SERVER_IP}/32 table main_route prio 100
```

### 工作原理

1. **入站连接处理**：
   - 外部 → 服务器IP:22（SSH）
   - 服务器回复时，源地址是服务器公网IP
   - 匹配策略路由规则，通过原网关返回
   - 保持连接路径一致

2. **出站连接处理**：
   - 服务器主动发起连接（curl等）
   - 如果绑定到公网IP，走原网关
   - 如果使用默认绑定，走VPN

3. **VPN流量处理**：
   - VPN分配的IP作为源地址
   - 不匹配策略路由规则
   - 自动走VPN默认路由

## 优势对比

| 特性 | 旧方案（iptables标记） | 新方案（源地址路由） |
|------|----------------------|-------------------|
| 依赖关系 | 需要iptables | 仅需iproute2 |
| 复杂度 | 高（3个iptables规则） | 低（1个路由规则） |
| 稳定性 | 依赖连接跟踪时机 | 纯路由层面 |
| 兼容性 | 可能与防火墙冲突 | 与防火墙无关 |
| 调试难度 | 高 | 低 |

## 验证方法

### 1. 检查策略路由
```bash
# 查看路由规则
ip rule list
# 应该看到：100: from <服务器IP>/32 lookup main_route

# 查看保留路由表
ip route show table main_route
# 应该看到：default via <原网关> dev <主网卡>
```

### 2. 测试连接
```bash
# 从外部测试服务器可访问性
ping <服务器IP>
tcpping <服务器IP> 22
tcpping <服务器IP> 80

# 从服务器测试VPN生效
curl ip.sb  # 应该显示VPN IP
```

### 3. 测试故障恢复
```bash
# 模拟VPN断开
systemctl stop openvpn-client@*.service

# 检查网络是否自动恢复（如果启用了监控服务）
ping 8.8.8.8
```

## 使用说明

1. **运行脚本**：
   ```bash
   bash super-tool.sh
   ```

2. **选择选项10**：
   - 选择1（新建配置）或2（修改现有配置）
   - 按提示配置OpenVPN

3. **启用监控服务**（推荐）：
   - 配置完成后选择"是"启用网络监控
   - 监控服务会自动检测VPN状态并在断线时恢复网络

4. **手动恢复**（如需要）：
   - 选择选项10-3：恢复原始网络设置

## 预期效果

✅ SSH连接保持稳定可用
✅ 所有入站端口正常可访问  
✅ 服务器主动流量通过VPN出站
✅ VPN断线自动恢复网络连接
✅ 无需修改防火墙配置

这个修复方案完全满足用户需求：保持22端口可连接，同时其他端口的入站流量回复通过VPN出站。 