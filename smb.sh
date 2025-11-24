#!/usr/bin/env bash
set -euo pipefail

############################################
# Global
############################################
CONF="/etc/samba/smb.conf"
BACKUP_DIR="/etc/samba/backup"
MARK_BEGIN="# === SMBGO-BEGIN ==="
MARK_END="# === SMBGO-END ==="
BIN_PATH="/usr/local/bin/smb"
CREDS_DB="/etc/samba/.smbgo_creds"
BRAND_NAME="孤独制作"
BRAND_LINK="https://github.com/xx2468171796"

# OpenWrt 使用不同的路径
get_bin_path() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    echo "/usr/bin/smb"
  else
    echo "/usr/local/bin/smb"
  fi
}

COLOR_INFO=""
COLOR_WARN=""
COLOR_ERR=""
COLOR_OK=""
COLOR_DIM=""
COLOR_RESET=""
GLYPH_INFO="[i]"
GLYPH_WARN="[!]"
GLYPH_ERR="[x]"
GLYPH_OK="[✓]"
GLYPH_STEP="[*]"

setup_colors() {
  if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    local colors; colors=$(tput colors 2>/dev/null || echo 0)
    if [[ "$colors" -ge 8 ]]; then
      COLOR_INFO="$(tput setaf 6)"
      COLOR_WARN="$(tput setaf 3)"
      COLOR_ERR="$(tput setaf 1)"
      COLOR_OK="$(tput setaf 2)"
      COLOR_DIM="$(tput setaf 8)"
      COLOR_RESET="$(tput sgr0)"
      return
    fi
  fi
  COLOR_RESET=""
}

info()    { printf "%b%s%b %s\n"   "${COLOR_INFO}" "${GLYPH_INFO}" "${COLOR_RESET}" "$*"; }
step()    { printf "%b%s%b %s\n"   "${COLOR_DIM}"  "${GLYPH_STEP}" "${COLOR_RESET}" "$*"; }
warn()    { printf "%b%s%b %s\n"   "${COLOR_WARN}" "${GLYPH_WARN}" "${COLOR_RESET}" "$*"; }
error()   { printf "%b%s%b %s\n"   "${COLOR_ERR}"  "${GLYPH_ERR}"  "${COLOR_RESET}" "$*"; }
success() { printf "%b%s%b %s\n"   "${COLOR_OK}"   "${GLYPH_OK}"   "${COLOR_RESET}" "$*"; }

print_box() {
  local title="$1"
  local border="========================================"
  printf "\n%b%s%b\n" "${COLOR_DIM}" "$border" "${COLOR_RESET}"
  printf "%b%s%b\n" "${COLOR_INFO}" "$title" "${COLOR_RESET}"
  printf "%b%s%b\n\n" "${COLOR_DIM}" "$border" "${COLOR_RESET}"
}

show_brand() {
  printf "%b%s%b %s  %s\n" "${COLOR_DIM}" "[◎]" "${COLOR_RESET}" "$BRAND_NAME" "$BRAND_LINK"
}

OS_ID="unknown"
OS_VER="0"
OS_LIKE=""
IS_OPENWRT="no"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    step "正在尝试提权..."
    exec sudo "$0" "$@"
  fi
}

############################################
# OS Detect
############################################
detect_os() {
  OS_ID="unknown"
  OS_VER="0"
  OS_LIKE=""
  IS_OPENWRT="no"

  if [[ -r /etc/openwrt_release || -r /etc/config/system ]]; then
    OS_ID="openwrt"
    IS_OPENWRT="yes"
    OS_VER="$(grep -oE '[0-9]+(\.[0-9]+)*' /etc/openwrt_release 2>/dev/null | head -n1 || echo 0)"
    return
  fi

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-0}"
    OS_LIKE="${ID_LIKE:-}"
  fi

  if [[ -r /etc/armbian-release ]]; then
    # Armbian 的 ID 可能还是 debian/ubuntu，但我们额外标识一下
    OS_ID="armbian"
  fi
}

warn_old_version_if_needed() {
  case "$OS_ID" in
    centos|rhel|rocky|almalinux)
      major="${OS_VER%%.*}"
      if [[ "$major" =~ ^[0-9]+$ ]] && (( major < 8 )); then
        warn "检测到 RHEL/CentOS 主版本 < 8（如 7.x），已 EOL，建议升级系统。"
      fi
      ;;
    openwrt)
      major="${OS_VER%%.*}"
      if [[ "$major" =~ ^[0-9]+$ ]] && (( major < 21 )); then
        warn "检测到 OpenWrt 版本较旧（<21），Samba 组件可能不全，建议升级固件。"
      fi
      ;;
  esac
}

############################################
# Firewall Detect (only warn)
############################################
detect_firewall() {
  local enabled="no"
  local fw_type=""

  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qi "Status: active"; then 
      enabled="yes"
      fw_type="ufw"
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld 2>/dev/null; then 
      enabled="yes"
      fw_type="firewalld"
    fi
  fi

  if command -v nft >/dev/null 2>&1; then
    if systemctl is-active --quiet nftables 2>/dev/null; then 
      enabled="yes"
      fw_type="nftables"
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    if iptables -S 2>/dev/null | grep -qE "^-P (INPUT|FORWARD) (DROP|REJECT)"; then 
      enabled="yes"
      fw_type="iptables"
    fi
  fi

  if [[ "$enabled" == "yes" ]]; then
    print_box "防火墙检测"
    warn "检测到防火墙启用（类型: $fw_type），SMB 需要放行以下端口："
    printf "    TCP 445/139, UDP 137/138\n"
    warn "请关闭防火墙或手动放行必要端口。"
  else
    step "未检测到启用的防火墙，跳过。"
  fi
}

configure_firewall() {
  print_box "配置防火墙放行 SMB 端口"
  
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
    info "检测到 ufw 防火墙，正在配置..."
    ufw allow 445/tcp >/dev/null 2>&1 || true
    ufw allow 139/tcp >/dev/null 2>&1 || true
    ufw allow 137/udp >/dev/null 2>&1 || true
    ufw allow 138/udp >/dev/null 2>&1 || true
    success "ufw 防火墙规则已添加"
    return 0
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    info "检测到 firewalld 防火墙，正在配置..."
    firewall-cmd --permanent --add-service=samba >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=445/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=139/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=137/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=138/udp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    success "firewalld 防火墙规则已添加并重载"
    return 0
  fi

  if command -v iptables >/dev/null 2>&1; then
    info "检测到 iptables，尝试添加规则..."
    iptables -I INPUT -p tcp --dport 445 -j ACCEPT >/dev/null 2>&1 || true
    iptables -I INPUT -p tcp --dport 139 -j ACCEPT >/dev/null 2>&1 || true
    iptables -I INPUT -p udp --dport 137 -j ACCEPT >/dev/null 2>&1 || true
    iptables -I INPUT -p udp --dport 138 -j ACCEPT >/dev/null 2>&1 || true
    success "iptables 规则已添加（临时，重启后失效）"
    warn "如需永久保存，请使用 iptables-save 或配置持久化规则"
    return 0
  fi

  warn "未检测到常见的防火墙工具，请手动配置防火墙规则"
  return 1
}

check_smb_bind() {
  info "检查 Samba 监听地址..."
  local listening
  listening="$(netstat -tlnp 2>/dev/null | grep -E ':(445|139)' || ss -tlnp 2>/dev/null | grep -E ':(445|139)' || true)"
  if [[ -n "$listening" ]]; then
    success "Samba 正在监听以下地址："
    echo "$listening" | while IFS= read -r line; do
      printf "    %s\n" "$line"
    done
  else
    warn "未检测到 Samba 监听端口 445 或 139"
  fi
  
  info "检查 Samba 配置..."
  if [[ -r "$CONF" ]]; then
    if grep -qE "^\s*bind\s+interfaces\s+only\s*=\s*yes" "$CONF" 2>/dev/null; then
      warn "检测到 bind interfaces only = yes，可能限制外部访问"
      info "建议检查 interfaces 配置或移除该限制"
    fi
  fi
}

diagnose_smb() {
  print_box "SMB 连接诊断"
  
  info "1. 检查 Samba 服务状态..."
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    /etc/init.d/samba4 status 2>/dev/null || /etc/init.d/samba status 2>/dev/null || warn "无法获取服务状态"
  else
    systemctl status smbd --no-pager -l | head -n 5 || true
    systemctl status nmbd --no-pager -l | head -n 5 || true
  fi
  
  printf "\n"
  check_smb_bind
  
  printf "\n"
  info "2. 检查防火墙状态..."
  detect_firewall
  
  printf "\n"
  info "3. 获取服务器 IP 地址..."
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  if [[ -n "$ip" ]]; then
    success "服务器 IP: $ip"
    info "Windows 访问地址示例：\\\\$ip\\共享名"
  else
    warn "无法获取服务器 IP 地址"
  fi
  
  printf "\n"
  info "4. 测试端口连通性..."
  if command -v nc >/dev/null 2>&1 || command -v telnet >/dev/null 2>&1; then
    info "提示：可以在客户端使用以下命令测试端口："
    printf "    telnet %s 445\n" "${ip:-服务器IP}"
    printf "    或: nc -zv %s 445\n" "${ip:-服务器IP}"
  fi
  
  printf "\n"
  warn "如果仍然无法连接，请检查："
  printf "    1. VPS 云服务商的安全组/防火墙规则\n"
  printf "    2. Samba 配置文件中的 bind interfaces 设置\n"
  printf "    3. SELinux 策略（如适用）\n"
  printf "    4. 网络路由和 NAT 配置\n"
}

############################################
# Install Samba for different distros
############################################
install_samba_debian() {
  step "使用 apt 安装 Samba..."
  
  # 先尝试更新包列表，如果失败则检查 dpkg 问题
  local update_output
  update_output="$(apt update 2>&1)" || {
    if echo "$update_output" | grep -qi "dpkg was interrupted"; then
      warn "检测到 dpkg 被中断，正在修复..."
      if ! dpkg --configure -a 2>&1; then
        error "dpkg 修复失败，请手动运行: dpkg --configure -a"
        error "修复完成后，请重新运行安装"
        return 1
      fi
      success "dpkg 修复完成，重新更新包列表..."
      apt update >/dev/null 2>&1 || true
    elif echo "$update_output" | grep -qE "(NO_PUBKEY|unsigned|not signed)"; then
      warn "检测到仓库签名问题，跳过有问题的仓库继续..."
      apt-get update --allow-insecure-repositories 2>/dev/null || true
    else
      warn "apt update 失败，但继续尝试安装..."
    fi
  }
  
  # 执行安装
  local install_output
  install_output="$(DEBIAN_FRONTEND=noninteractive apt install -y samba samba-common-bin smbclient 2>&1)" || {
    error "Samba 安装失败，请检查错误信息"
    if echo "$install_output" | grep -qi "dpkg was interrupted"; then
      warn "检测到 dpkg 中断，正在尝试修复..."
      if ! dpkg --configure -a 2>&1; then
        error "dpkg 修复失败，请手动运行: dpkg --configure -a"
        error "修复完成后，请重新运行安装"
        return 1
      fi
      success "dpkg 修复完成，请重新运行安装选项"
      return 1
    fi
    echo "$install_output" | tail -n 10
    return 1
  }
  
  # 验证关键命令是否存在
  if ! command -v smbpasswd >/dev/null 2>&1; then
    error "smbpasswd 命令未找到，Samba 可能未正确安装"
    warn "尝试重新安装 samba-common-bin..."
    DEBIAN_FRONTEND=noninteractive apt install -y --reinstall samba-common-bin || return 1
  fi
  
  if ! command -v smbd >/dev/null 2>&1 && ! command -v samba >/dev/null 2>&1; then
    error "smbd 命令未找到，Samba 可能未正确安装"
    return 1
  fi
  
  systemctl enable --now smbd nmbd >/dev/null 2>&1 || true
  success "Samba 组件安装完成"
}

install_samba_rhel() {
  local pm="dnf"
  command -v dnf >/dev/null 2>&1 || pm="yum"
  step "使用 $pm 安装 Samba..."
  
  if ! $pm install -y samba samba-client samba-common samba-common-tools 2>&1; then
    error "Samba 安装失败，请检查错误信息"
    return 1
  fi
  
  # 验证关键命令是否存在
  if ! command -v smbpasswd >/dev/null 2>&1; then
    error "smbpasswd 命令未找到，Samba 可能未正确安装"
    warn "尝试重新安装 samba-common-tools..."
    $pm install -y --reinstall samba-common-tools || return 1
  fi
  
  if ! command -v smbd >/dev/null 2>&1 && ! command -v samba >/dev/null 2>&1; then
    error "smbd 命令未找到，Samba 可能未正确安装"
    return 1
  fi
  
  systemctl enable --now smb nmb >/dev/null 2>&1 || \
  systemctl enable --now smbd nmbd >/dev/null 2>&1 || true
  success "Samba 组件安装完成"
  return 0
}

install_samba_openwrt() {
  step "使用 opkg 安装 Samba4..."
  opkg update
  if ! opkg install samba4-server luci-app-samba4; then
    opkg install samba36-server luci-app-samba || true
  fi
  /etc/init.d/samba4 enable 2>/dev/null || /etc/init.d/samba enable 2>/dev/null || true
  /etc/init.d/samba4 start 2>/dev/null || /etc/init.d/samba start 2>/dev/null || true
  success "Samba 组件安装完成"
}

enable_autostart() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    /etc/init.d/samba4 enable 2>/dev/null || /etc/init.d/samba enable 2>/dev/null || true
  else
    systemctl enable smbd nmbd >/dev/null 2>&1 || systemctl enable smb nmb >/dev/null 2>&1 || true
  fi
  success "已设置 Samba 开机自启"
}

disable_autostart() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    /etc/init.d/samba4 disable 2>/dev/null || /etc/init.d/samba disable 2>/dev/null || true
  else
    systemctl disable smbd nmbd >/dev/null 2>&1 || systemctl disable smb nmb >/dev/null 2>&1 || true
  fi
  warn "已取消 Samba 开机自启"
}

start_smb() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    /etc/init.d/samba4 start 2>/dev/null || /etc/init.d/samba start 2>/dev/null || true
  else
    systemctl start smbd nmbd >/dev/null 2>&1 || systemctl start smb nmb >/dev/null 2>&1 || true
  fi
  success "Samba 服务已启动"
}

stop_smb() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    /etc/init.d/samba4 stop 2>/dev/null || /etc/init.d/samba stop 2>/dev/null || true
  else
    systemctl stop smbd nmbd >/dev/null 2>&1 || systemctl stop smb nmb >/dev/null 2>&1 || true
  fi
  warn "Samba 服务已停止"
}

restart_smb() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    /etc/init.d/samba4 restart 2>/dev/null || /etc/init.d/samba restart 2>/dev/null || true
  else
    systemctl restart smbd nmbd >/dev/null 2>&1 || systemctl restart smb nmb >/dev/null 2>&1 || true
  fi
  success "Samba 服务已重启"
}

show_status() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    /etc/init.d/samba4 status 2>/dev/null || /etc/init.d/samba status 2>/dev/null || true
  else
    systemctl status smbd --no-pager | sed -n '1,8p' || true
    systemctl status nmbd --no-pager | sed -n '1,8p' || true
  fi
}

ensure_samba_installed() {
  detect_os
  warn_old_version_if_needed

  if [[ "$IS_OPENWRT" == "yes" ]]; then
    if ! command -v smbd >/dev/null 2>&1 && ! command -v samba >/dev/null 2>&1; then
      install_samba_openwrt
    else
      echo "[*] Samba 已安装，跳过安装。"
    fi
    enable_autostart
    start_smb
    detect_firewall
    return
  fi

  if command -v smbd >/dev/null 2>&1 && command -v smbpasswd >/dev/null 2>&1; then
    step "Samba 已安装，跳过安装。"
  else
    case "$OS_ID" in
      debian|ubuntu|armbian)
        if ! install_samba_debian; then
          error "Samba 安装失败，请检查错误信息并重试"
          return 1
        fi ;;
      centos|rhel|rocky|almalinux|fedora)
        if ! install_samba_rhel; then
          error "Samba 安装失败，请检查错误信息并重试"
          return 1
        fi ;;
      *)
        if echo "$OS_LIKE" | grep -qiE "debian|ubuntu"; then
          if ! install_samba_debian; then
            error "Samba 安装失败，请检查错误信息并重试"
            return 1
          fi
        elif echo "$OS_LIKE" | grep -qiE "rhel|fedora|centos"; then
          if ! install_samba_rhel; then
            error "Samba 安装失败，请检查错误信息并重试"
            return 1
          fi
        else
          error "未识别系统发行版：ID=$OS_ID VER=$OS_VER LIKE=$OS_LIKE"
          warn "请升级系统或手动安装 Samba 后再运行本脚本。"
          return 1
        fi ;;
    esac
    
    # 最终验证安装是否成功
    if ! command -v smbpasswd >/dev/null 2>&1; then
      error "安装后验证失败：smbpasswd 命令未找到"
      warn "请手动安装: apt install samba-common-bin (Debian/Ubuntu) 或 yum install samba-common-tools (RHEL/CentOS)"
      return 1
    fi
  fi

  enable_autostart
  start_smb
  detect_firewall
  ensure_markers
}

############################################
# Debian/Ubuntu/CentOS conf helpers
############################################
backup_conf() {
  mkdir -p "$BACKUP_DIR"
  local ts; ts="$(date +%F_%H%M%S)"
  cp -a "$CONF" "$BACKUP_DIR/smb.conf.$ts.bak"
  info "已备份配置到 $BACKUP_DIR/smb.conf.$ts.bak"
}

validate_conf() {
  if testparm -s >/dev/null 2>&1; then
    success "配置校验通过"
  else
    error "配置校验失败，请检查 smb.conf"
    exit 1
  fi
}

reload_samba() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    restart_smb
  else
    systemctl restart smbd >/dev/null 2>&1 || systemctl restart samba >/dev/null 2>&1 || true
    systemctl restart nmbd >/dev/null 2>&1 || true
  fi
}

ensure_markers() {
  if [[ ! -r "$CONF" ]]; then
    mkdir -p /etc/samba
    touch "$CONF"
  fi
  if ! grep -qF "$MARK_BEGIN" "$CONF"; then
    echo -e "\n$MARK_BEGIN\n$MARK_END\n" >> "$CONF"
  fi
  
  # 确保允许外部访问
  if ! grep -qE "^\s*bind\s+interfaces\s+only" "$CONF" 2>/dev/null; then
    # 如果没有 bind interfaces only 配置，添加允许外部访问的配置
    if ! grep -qE "^\s*\[global\]" "$CONF" 2>/dev/null; then
      # 如果没有 [global] 段，在文件开头添加
      local tmp; tmp="$(mktemp)"
      echo "[global]" > "$tmp"
      echo "   bind interfaces only = no" >> "$tmp"
      echo "" >> "$tmp"
      cat "$CONF" >> "$tmp"
      mv "$tmp" "$CONF"
    else
      # 如果有 [global] 段，检查并添加配置
      if ! grep -qE "^\s*bind\s+interfaces\s+only" "$CONF" 2>/dev/null; then
        sed -i '/^\[global\]/a\   bind interfaces only = no' "$CONF" 2>/dev/null || true
      fi
    fi
  else
    # 如果存在但设置为 yes，改为 no
    sed -i 's/^\s*bind\s+interfaces\s+only\s*=\s*yes/bind interfaces only = no/i' "$CONF" 2>/dev/null || true
  fi
}

ensure_creds_db() {
  if [[ ! -f "$CREDS_DB" ]]; then
    touch "$CREDS_DB"
    chmod 600 "$CREDS_DB"
  fi
}

store_share_cred() {
  local name="$1"
  local user="$2"
  local pass="$3"
  ensure_creds_db
  local tmp; tmp="$(mktemp)"
  awk -F'|' -v target="$name" '{
    if ($1 != target) print
  }' "$CREDS_DB" > "$tmp"
  printf "%s|%s|%s\n" "$name" "$user" "$pass" >> "$tmp"
  mv "$tmp" "$CREDS_DB"
  chmod 600 "$CREDS_DB"
}

remove_share_cred() {
  [[ -f "$CREDS_DB" ]] || return
  local name="$1"
  local tmp; tmp="$(mktemp)"
  awk -F'|' -v target="$name" '{
    if ($1 != target) print
  }' "$CREDS_DB" > "$tmp"
  mv "$tmp" "$CREDS_DB"
  chmod 600 "$CREDS_DB"
}

get_share_password() {
  local name="$1"
  [[ -f "$CREDS_DB" ]] || return
  awk -F'|' -v target="$name" '$1==target {print $3; exit}' "$CREDS_DB"
}

get_conf_shares() {
  ensure_markers
  [[ ! -r "$CONF" ]] && return
  awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
    function trim(s){gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s}
    function flush(){
      if(name!=""){
        print name "|" path "|" ro "|" user
        name=""
        path=""
        ro="no"
        user="-"
      }
    }
    $0==begin {inblk=1; next}
    $0==end {flush(); inblk=0; next}
    inblk {
      if ($0 ~ /^\[.*\]/) {
        flush()
        name=$0
        gsub(/^\[|\]$/, "", name)
        name=trim(name)
        path=""
        ro="no"
        user="-"
      } else if ($0 ~ /^[[:space:]]*path[[:space:]]*=[[:space:]]*/) {
        split($0, arr, "=")
        path=trim(arr[2])
      } else if ($0 ~ /^[[:space:]]*read[[:space:]]+only[[:space:]]*=[[:space:]]*/) {
        split($0, arr, "=")
        ro=trim(arr[2])
      } else if ($0 ~ /^[[:space:]]*valid[[:space:]]+users[[:space:]]*=[[:space:]]*/) {
        split($0, arr, "=")
        user=trim(arr[2])
        if (user=="") user="-"
      }
    }
    END{flush()}
  ' "$CONF"
}

select_share_conf() {
  local -a _shares=()
  local share_output
  share_output="$(get_conf_shares)"
  if [[ -n "$share_output" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && _shares+=("$line")
    done <<<"$share_output"
  fi
  
  if ((${#_shares[@]}==0)); then
    warn "当前没有可用的共享。"
    return 1
  fi
  
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ip" ]] && ip="<未知IP>"
  
  print_box "当前已有共享列表（请选择要删除的共享）"
  printf "%-3s %-20s %-35s %-10s %-25s\n" "#" "共享名" "路径" "只读" "访问链接"
  printf "%s\n" "--------------------------------------------------------------------------------------------"
  local i=1
  for entry in "${_shares[@]}"; do
    IFS='|' read -r name path ro user <<<"$entry"
    [[ -z "$name" ]] && continue
    [[ -z "$path" ]] && path="-"
    [[ -z "$ro" ]] && ro="no"
    local link="\\\\$ip\\$name"
    printf "%-3s %-20s %-35s %-10s %-25s\n" "$i" "$name" "$path" "$ro" "$link"
    ((i++))
  done
  printf "\n"
  local choice
  read -rp "请输入要删除的共享编号: " choice
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || ((choice < 1 || choice > ${#_shares[@]})); then
    warn "编号无效，请重新选择。"
    return 1
  fi
  echo "${_shares[choice-1]}"
}

show_share_status() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  [[ -z "$ip" ]] && ip="<未知IP>"
  
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    local sections
    sections="$(uci -q show samba4 2>/dev/null | grep "=share" | cut -d. -f2 | cut -d= -f1 || true)"
    if [[ -z "$sections" ]]; then
      info "当前未配置任何共享。"
      return 0
    fi
    local -a links=()
    local count=0
    for s in $sections; do
      [[ -z "$s" ]] && continue
      local n; n="$(uci -q get samba4."$s".name 2>/dev/null || echo "")"
      if [[ -n "$n" ]]; then
        links+=("\\\\$ip\\$n")
        ((count++)) || true
      fi
    done
    if ((count > 0)); then
      info "当前共享($count): ${links[*]}"
    else
      info "当前未配置任何共享。"
    fi
    return 0
  else
    local -a _shares=()
    local share_output
    share_output="$(get_conf_shares)"
    if [[ -n "$share_output" ]]; then
      while IFS= read -r line; do
        [[ -n "$line" ]] && _shares+=("$line")
      done <<<"$share_output"
    fi
    
    if ((${#_shares[@]}==0)); then
      info "当前未配置任何共享。"
      return
    fi
    local -a links=()
    for entry in "${_shares[@]}"; do
      IFS='|' read -r name _ <<<"$entry"
      [[ -n "$name" ]] && links+=("\\\\$ip\\$name")
    done
    if ((${#links[@]} > 0)); then
      info "当前共享(${#links[@]}): ${links[*]}"
    else
      info "当前未配置任何共享。"
    fi
  fi
}

list_shares_conf() {
  local -a shares=()
  local share_output
  share_output="$(get_conf_shares)"
  if [[ -n "$share_output" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && shares+=("$line")
    done <<<"$share_output"
  fi
  
  if ((${#shares[@]}==0)); then
    print_box "当前 SMB 共享（脚本管理段）"
    warn "当前没有共享。"
    printf "\n"
    return
  fi
  
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ip" ]] && ip="<未知IP>"

  print_box "当前 SMB 共享（脚本管理段）"
  printf "%-3s %-15s %-28s %-10s %-15s %-25s\n" "#" "共享名" "路径" "只读" "用户" "访问链接"
  printf "%s\n" "------------------------------------------------------------------------------------------------"
  local idx=1
  for entry in "${shares[@]}"; do
    IFS='|' read -r name path ro user <<<"$entry"
    [[ -z "$name" ]] && continue
    [[ -z "$path" ]] && path="-"
    [[ -z "$ro" ]] && ro="no"
    [[ -z "$user" || "$user" == "-" ]] && user="(未指定)"
    local link="\\\\$ip\\$name"
    local passwd
    passwd="$(get_share_password "$name")"
    [[ -z "$passwd" ]] && passwd="(未记录)"
    printf "%-3s %-15s %-28s %-10s %-15s %-25s\n" "$idx" "$name" "$path" "$ro" "$user" "$link"
    printf "    %bSMB 用户名:%b %s  %bSMB 密码:%b %s\n" "${COLOR_INFO}" "${COLOR_RESET}" "$user" "${COLOR_INFO}" "${COLOR_RESET}" "$passwd"
    ((idx++))
  done
  printf "\n"
}

add_share_conf() {
  read -rp "共享名(英文/数字/下划线): " name
  [[ -z "$name" ]] && { warn "共享名不能为空"; return; }
  if grep -qE "^\[$name\]" "$CONF"; then warn "共享名已存在"; return; fi

  read -rp "要共享的路径(如 /data/share): " path
  [[ -d "$path" ]] || { warn "路径不存在"; return; }

  read -rp "Linux 系统用户名(用于SMB登录, 不存在会创建): " luser
  [[ -z "$luser" ]] && { warn "用户名不能为空"; return; }
  if ! id "$luser" >/dev/null 2>&1; then
    step "创建系统用户 $luser ..."
    useradd -m -s /usr/sbin/nologin "$luser"
  fi

  local smb_pass smb_pass_confirm
  while true; do
    read -rsp "设置 SMB 密码: " smb_pass; echo
    [[ -z "$smb_pass" ]] && { warn "密码不能为空"; continue; }
    read -rsp "再次确认密码: " smb_pass_confirm; echo
    if [[ "$smb_pass" != "$smb_pass_confirm" ]]; then
      warn "两次密码不一致，请重新输入。"
      continue
    fi
    break
  done
  if ! command -v smbpasswd >/dev/null 2>&1; then
    error "smbpasswd 命令未找到，请先安装 Samba"
    warn "运行选项 1 进行安装，或手动执行: apt install samba-common-bin"
    return 1
  fi
  
  if ! printf "%s\n%s\n" "$smb_pass" "$smb_pass" | smbpasswd -s -a "$luser" 2>/dev/null; then
    error "设置 SMB 密码失败"
    warn "请检查 Samba 服务是否正常运行"
    return 1
  fi

  read -rp "是否只读共享? (Y/N, 默认 N): " ro_yn
  ro_yn="${ro_yn:-N}"
  local ro="no"; [[ "$ro_yn" =~ ^[Yy]$ ]] && ro="yes"

  chown -R "$luser:$luser" "$path"
  chmod -R 0775 "$path"

  backup_conf
  ensure_markers

  local tmp; tmp="$(mktemp)"
  awk -v name="$name" -v path="$path" -v ro="$ro" -v users="$luser" \
      -v begin="$MARK_BEGIN" -v end="$MARK_END" '
    $0==begin {print; print ""; print_block=1; next}
    $0==end && print_block==1 {
        print "["name"]"
        print "   path = "path
        print "   browseable = yes"
        print "   writable = "(ro=="yes"?"no":"yes")
        print "   read only = "ro
        print "   guest ok = no"
        print "   valid users = "users
        print "   create mask = 0664"
        print "   directory mask = 0775"
        print "   inherit permissions = yes"
        print ""
        print; print_block=0; next
    }
    {print}
  ' "$CONF" > "$tmp"
  mv "$tmp" "$CONF"

  validate_conf
  reload_samba

  local ip; ip="$(hostname -I | awk '{print $1}')"
  store_share_cred "$name" "$luser" "$smb_pass"
  print_box "新增共享完成"
  success "共享名: $name"
  success "共享路径: $path"
  success "SMB 用户名: $luser"
  info "SMB 密码: $smb_pass"
  info "Windows 访问：\\\\$ip\\$name"
}

delete_share_conf() {
  # 先显示共享列表
  local -a _shares=()
  local share_output
  share_output="$(get_conf_shares)"
  if [[ -n "$share_output" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && _shares+=("$line")
    done <<<"$share_output"
  fi
  
  if ((${#_shares[@]}==0)); then
    warn "当前没有可用的共享。"
    return 1
  fi
  
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ip" ]] && ip="<未知IP>"
  
  print_box "当前已有共享列表（请选择要删除的共享）"
  printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "#" "共享名" "路径" "只读" "访问链接"
  printf "%s\n" "--------------------------------------------------------------------------------------------------------"
  local i=1
  for entry in "${_shares[@]}"; do
    IFS='|' read -r name path ro user <<<"$entry"
    [[ -z "$name" ]] && continue
    [[ -z "$path" ]] && path="-"
    [[ -z "$ro" ]] && ro="no"
    local link="\\\\$ip\\$name"
    printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "$i" "$name" "$path" "$ro" "$link"
    ((i++))
  done
  printf "\n"
  
  # 然后让用户选择
  local choice
  read -rp "请输入要删除的共享编号: " choice
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || ((choice < 1 || choice > ${#_shares[@]})); then
    warn "编号无效，操作已取消。"
    return 1
  fi
  
  local selection="${_shares[choice-1]}"
  IFS='|' read -r name _ <<<"$selection"
  [[ -z "$name" ]] && { warn "共享名不能为空"; return; }

  backup_conf
  local tmp; tmp="$(mktemp)"
  awk -v name="$name" -v begin="$MARK_BEGIN" -v end="$MARK_END" '
    BEGIN {skip=0; inblk=0}
    $0==begin {inblk=1; print; next}
    $0==end {inblk=0; skip=0; print; next}
    inblk==1 {
      if ($0 ~ /^\[.*\]/) {
        if ($0 ~ "^\\["name"\\]") {
          skip=1
        } else {
          skip=0
          print
        }
        next
      }
      if (skip==0) {
        print
      }
      next
    }
    {print}
  ' "$CONF" > "$tmp"
  mv "$tmp" "$CONF"

  validate_conf
  reload_samba
  success "共享 $name 已删除"
  remove_share_cred "$name"
  
  # 等待一下确保文件系统同步
  sleep 0.1
}

edit_share_conf() {
  local -a _shares=()
  local share_output
  share_output="$(get_conf_shares)"
  if [[ -n "$share_output" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && _shares+=("$line")
    done <<<"$share_output"
  fi
  
  if ((${#_shares[@]}==0)); then
    warn "当前没有可用的共享。"
    return 1
  fi
  
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ip" ]] && ip="<未知IP>"
  
  print_box "当前已有共享列表（请选择要修改的共享）"
  printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "#" "共享名" "路径" "只读" "访问链接"
  printf "%s\n" "--------------------------------------------------------------------------------------------------------"
  local i=1
  for entry in "${_shares[@]}"; do
    IFS='|' read -r name path ro user <<<"$entry"
    [[ -z "$name" ]] && continue
    [[ -z "$path" ]] && path="-"
    [[ -z "$ro" ]] && ro="no"
    local link="\\\\$ip\\$name"
    printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "$i" "$name" "$path" "$ro" "$link"
    ((i++))
  done
  printf "\n"
  local choice
  read -rp "请输入要修改的共享编号: " choice
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || ((choice < 1 || choice > ${#_shares[@]})); then
    warn "编号无效。"
    return 1
  fi
  
  local selection="${_shares[choice-1]}"
  IFS='|' read -r name _ <<<"$selection"

  read -rp "新的共享路径(留空则不改): " path
  if [[ -n "$path" && ! -d "$path" ]]; then warn "新路径不存在"; return; fi

  read -rp "是否只读? (Y/N, 留空不改): " ro_yn
  local ro=""
  if [[ -n "$ro_yn" ]]; then
    [[ "$ro_yn" =~ ^[Yy]$ ]] && ro="yes"
    [[ "$ro_yn" =~ ^[Nn]$ ]] && ro="no"
    [[ "$ro" == "" ]] && { warn "只读参数只能 Y/N"; return; }
  fi

  backup_conf
  local tmp; tmp="$(mktemp)"
  awk -v name="$name" -v newpath="$path" -v newro="$ro" '
    BEGIN{inblk=0}
    $0 ~ "^\\["name"\\]" {inblk=1; print; next}
    inblk==1 && $0 ~ "^\\[.*\\]" {inblk=0}
    inblk==1 {
      if (newpath!="" && $0 ~ "^[[:space:]]*path[[:space:]]*=") {
        print "   path = "newpath; next
      }
      if (newro!="" && $0 ~ "^[[:space:]]*read only[[:space:]]*=") {
        print "   read only = "newro; next
      }
      if (newro!="" && $0 ~ "^[[:space:]]*writable[[:space:]]*=") {
        print "   writable = "(newro=="yes"?"no":"yes"); next
      }
      print; next
    }
    {print}
  ' "$CONF" > "$tmp"
  mv "$tmp" "$CONF"

  validate_conf
  reload_samba
  success "共享 $name 已更新"
}

############################################
# OpenWrt UCI helpers (samba4)
############################################
uci_has() { uci -q show samba4 >/dev/null 2>&1; }

list_shares_openwrt() {
  print_box "OpenWrt 当前 SMB 共享（UCI）"
  uci -q show samba4 | grep "=share" || echo "(无 share 段)"
  printf "\n"
}

select_share_openwrt() {
  uci_has || { warn "OpenWrt 上 samba4 配置不存在。"; return 1; }
  local sections
  sections="$(uci -q show samba4 | grep "=share" | cut -d. -f2 | cut -d= -f1)"
  if [[ -z "$sections" ]]; then
    warn "当前没有共享。"
    return 1
  fi
  
  local ip
  ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ip" ]] && ip="<未知IP>"
  
  print_box "当前已有共享列表（请选择要删除的共享）"
  printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "#" "共享名" "路径" "只读" "访问链接"
  printf "%s\n" "--------------------------------------------------------------------------------------------------------"
  local idx=1
  local -a section_array=()
  for s in $sections; do
    section_array+=("$s")
    local n; n="$(uci -q get samba4."$s".name || echo "")"
    local p; p="$(uci -q get samba4."$s".path || echo "")"
    local ro; ro="$(uci -q get samba4."$s".read_only || echo "0")"
    [[ "$ro" == "1" ]] && ro="yes" || ro="no"
    [[ -z "$p" ]] && p="-"
    local link="\\\\$ip\\$n"
    printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "$idx" "$n" "$p" "$ro" "$link"
    ((idx++))
  done
  printf "\n"
  local choice
  read -rp "请输入要删除的共享编号: " choice
  local total=${#section_array[@]}
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || ((choice < 1 || choice > total)); then
    warn "编号无效，请重新选择。"
    return 1
  fi
  echo "${section_array[choice-1]}"
}

add_share_openwrt() {
  uci_has || { warn "OpenWrt 上 samba4 配置不存在，请先 init 安装。"; return; }

  read -rp "共享名(英文/数字/下划线): " name
  [[ -z "$name" ]] && { warn "共享名不能为空"; return; }

  read -rp "要共享的路径(如 /mnt/sda1/share): " path
  [[ -d "$path" ]] || { warn "路径不存在"; return; }

  read -rp "是否只读共享? (Y/N, 默认 N): " ro_yn
  ro_yn="${ro_yn:-N}"
  local ro="0"; [[ "$ro_yn" =~ ^[Yy]$ ]] && ro="1"

  local section
  section="$(uci add samba4 share)"
  uci set samba4."$section".name="$name"
  uci set samba4."$section".path="$path"
  uci set samba4."$section".read_only="$ro"
  uci set samba4."$section".guest_ok="no"
  uci commit samba4

  restart_smb

  local ip; ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  print_box "新增共享完成（OpenWrt）"
  success "共享名: $name"
  success "共享路径: $path"
  info "只读: $([[ "$ro" == "1" ]] && echo yes || echo no)"
  info "Windows 访问：\\\\$ip\\$name"
}

delete_share_openwrt() {
  uci_has || { warn "OpenWrt 上 samba4 配置不存在。"; return; }

  # 先显示共享列表
  local sections
  sections="$(uci -q show samba4 | grep "=share" | cut -d. -f2 | cut -d= -f1)"
  if [[ -z "$sections" ]]; then
    warn "当前没有共享。"
    return 1
  fi
  
  local ip
  ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  [[ -z "$ip" ]] && ip="<未知IP>"
  
  print_box "当前已有共享列表（请选择要删除的共享）"
  printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "#" "共享名" "路径" "只读" "访问链接"
  printf "%s\n" "--------------------------------------------------------------------------------------------------------"
  local idx=1
  local -a section_array=()
  for s in $sections; do
    section_array+=("$s")
    local n; n="$(uci -q get samba4."$s".name || echo "")"
    local p; p="$(uci -q get samba4."$s".path || echo "")"
    local ro; ro="$(uci -q get samba4."$s".read_only || echo "0")"
    [[ "$ro" == "1" ]] && ro="yes" || ro="no"
    [[ -z "$p" ]] && p="-"
    local link="\\\\$ip\\$n"
    printf "%-3s  %-18s  %-30s  %-8s  %-30s\n" "$idx" "$n" "$p" "$ro" "$link"
    ((idx++))
  done
  printf "\n"
  
  # 然后让用户选择
  local choice
  read -rp "请输入要删除的共享编号: " choice
  local total=${#section_array[@]}
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || ((choice < 1 || choice > total)); then
    warn "编号无效，操作已取消。"
    return 1
  fi
  
  local section="${section_array[choice-1]}"
  local name; name="$(uci -q get samba4."$section".name || echo "")"
  [[ -z "$name" ]] && { warn "共享名不能为空"; return; }
  
  uci delete samba4."$section"
  uci commit samba4
  restart_smb
  success "共享 $name 已删除（OpenWrt）"
  
  # 等待一下确保配置同步
  sleep 0.1
}

edit_share_openwrt() {
  uci_has || { warn "OpenWrt 上 samba4 配置不存在。"; return; }

  local target
  target="$(select_share_openwrt)" || return
  local name; name="$(uci -q get samba4."$target".name || echo "")"

  read -rp "新的共享路径(留空则不改): " path
  if [[ -n "$path" && ! -d "$path" ]]; then warn "新路径不存在"; return; fi

  read -rp "是否只读? (Y/N, 留空不改): " ro_yn
  if [[ -n "$path" ]]; then
    uci set samba4."$target".path="$path"
  fi
  if [[ -n "$ro_yn" ]]; then
    [[ "$ro_yn" =~ ^[Yy]$ ]] && uci set samba4."$target".read_only="1"
    [[ "$ro_yn" =~ ^[Nn]$ ]] && uci set samba4."$target".read_only="0"
  fi

  uci commit samba4
  restart_smb
  success "共享 $name 已更新（OpenWrt）"
}

############################################
# Shortcut + Guide
############################################
install_shortcut() {
  local self="$1"
  local target_path
  target_path="$(get_bin_path)"
  local bin_dir
  bin_dir="$(dirname "$target_path")"

  if [[ ! -d "$bin_dir" ]]; then
    mkdir -p "$bin_dir"
  fi

  if [[ "$self" != "$target_path" ]]; then
    cp -a "$self" "$target_path"
    chmod +x "$target_path"
    print_box "快捷命令安装成功"
    success "已安装到：$target_path"
    info "提示：以后可以直接输入 smb 来调出交互菜单"
    printf "    smb        # 进入交互菜单\n"
    printf "    smb init   # 初始化安装\n"
    printf "    smb add    # 添加共享\n"
    if [[ "$IS_OPENWRT" == "yes" ]]; then
      info "提示：如果命令未找到，请重新登录或执行：hash -r"
    fi
    printf "\n"
    show_brand
  fi
}

usage_guide() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"

  print_box "使用指南（超详细）"
  cat <<EOF
1) 进入菜单：smb
2) 初始化/安装：smb init
   - 自动检测系统并安装 samba/samba4
   - 默认开启自启 + 启动服务
   - 自动检测防火墙并提示
3) 新增共享：smb add
   - 共享名/路径/用户名/密码交互填写
4) 查看共享：smb list
5) 修改共享：smb edit
6) 删除共享：smb del
7) 服务操作：smb start|stop|restart|status
8) 自启设置：smb enable|disable 或菜单 10
9) Windows 访问：\\\\${ip}\\共享名 例：\\\\${ip}\\share
10) 防火墙端口：TCP 445/139, UDP 137/138
EOF
  printf "\n"
  show_brand
  printf "\n"
}

toggle_autostart_yn() {
  read -rp "是否停用开机自启? (Y/N, 默认 N): " yn
  yn="${yn:-N}"
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    disable_autostart
  else
    enable_autostart
  fi
}

############################################
# Unified wrappers for add/del/edit/list
############################################
list_shares() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    list_shares_openwrt
  else
    list_shares_conf
  fi
}

add_share() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    add_share_openwrt
  else
    add_share_conf
  fi
}

delete_share() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    delete_share_openwrt
  else
    delete_share_conf
  fi
}

edit_share() {
  if [[ "$IS_OPENWRT" == "yes" ]]; then
    edit_share_openwrt
  else
    edit_share_conf
  fi
}

############################################
# Menu
############################################
menu() {
  set +e  # 在菜单中禁用 -e，避免因错误退出
  while true; do
    show_brand || true
    printf "\n"
    print_box "SMB 一键管理（系统: $OS_ID / $OS_VER）" || true
    show_share_status || true
    printf "1) 安装/初始化 Samba（默认开机自启）\n"
    printf "2) 新增共享\n"
    printf "3) 删除共享\n"
    printf "4) 修改共享\n"
    printf "5) 查看共享\n"
    printf "6) 启动 SMB\n"
    printf "7) 停止 SMB\n"
    printf "8) 重启 SMB\n"
    printf "9) 查看服务状态\n"
    printf "10) 开机自启设置（是否停用? Y/N）\n"
    printf "11) 输出使用指南\n"
    printf "12) 配置防火墙（放行 SMB 端口）\n"
    printf "13) SMB 连接诊断\n"
    printf "0) 退出\n"
    read -rp "选择: " c || break
    case "$c" in
      1) ensure_samba_installed ;;
      2) ensure_samba_installed && add_share ;;
      3) delete_share ;;
      4) edit_share ;;
      5) list_shares ;;
      6) start_smb ;;
      7) stop_smb ;;
      8) restart_smb ;;
      9) show_status ;;
      10) toggle_autostart_yn ;;
      11) usage_guide ;;
      12) configure_firewall ;;
      13) diagnose_smb ;;
      0) break ;;
      *) echo "无效选项" ;;
    esac
  done
}

############################################
# Main
############################################
main() {
  setup_colors || true
  need_root || exit 1
  detect_os || true
  install_shortcut "$0" || true

  if [[ "${1:-}" == "" ]]; then
    menu || true
    exit 0
  fi

  case "${1:-}" in
    init) ensure_samba_installed; usage_guide ;;
    add) ensure_samba_installed && add_share ;;
    del) delete_share ;;
    edit) edit_share ;;
    list) list_shares ;;
    start) start_smb ;;
    stop) stop_smb ;;
    restart|reload) restart_smb ;;
    status) show_status ;;
    enable) enable_autostart ;;
    disable) disable_autostart ;;
    guide) usage_guide ;;
    *)
      echo "用法: $0 [init|add|del|edit|list|start|stop|restart|status|enable|disable|guide]"
      ;;
  esac
}

main "$@"
