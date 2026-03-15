#!/bin/sh

# --- 配置信息 ---
USER_ID="username"
# 确保密码用单引号
PASSWORD='password'

# Srun 参数
TEST_IP="baidu.com"
SRUN_IP="172.19.0.5"
AC_ID="17"
ENC_VER="srun_bx1"
N="200"
TYPE="1"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"

# --- 智能检测 C 程序路径 ---
if [ -n "$CRYPTO_BIN" ]; then
    SRUN_CRYPTO_EXEC="$CRYPTO_BIN"
elif [ -x "./build/srun_crypto" ]; then
    SRUN_CRYPTO_EXEC="./build/srun_crypto"
else
    SRUN_CRYPTO_EXEC="srun_crypto"
fi

is_connected() {
    ping -c 2 -W 2 "$TEST_IP" > /dev/null 2>&1
    return $?
}

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

login() {
    log_msg "网络未连接，开始执行登录流程..."
    log_msg "当前使用的加密程序路径: $SRUN_CRYPTO_EXEC"

    # 获取 IP (激进去除所有不可见字符)
    LOGIN_PAGE=$(curl -s -H "User-Agent: $UA" "http://$SRUN_IP/srun_portal_pc?ac_id=$AC_ID&theme=cucc")
    IP=$(echo "$LOGIN_PAGE" | sed -n 's/.*ip[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | tr -d '\r\n ')

    if [ -z "$IP" ]; then
        log_msg "错误: 无法从登录页面解析 IP。"
        return 1
    fi

    # 获取 token (激进去除所有不可见字符)
    CHALLENGE_URL="http://$SRUN_IP/cgi-bin/get_challenge?callback=jsonp1583251661367&username=${USER_ID}@cucc&ip=${IP}"
    CHALLENGE_RESP=$(curl -s -H "User-Agent: $UA" "$CHALLENGE_URL")
    TOKEN=$(echo "$CHALLENGE_RESP" | sed -n 's/.*"challenge":"\([^"]*\)".*/\1/p' | tr -d '\r\n ')

    if [ -z "$TOKEN" ]; then
        log_msg "错误: 无法解析 token。"
        return 1
    fi

    # 调用加密程序生成参数
    CRYPTO_OUT=$($SRUN_CRYPTO_EXEC "${USER_ID}@cucc" "$PASSWORD" "$IP" "$AC_ID" "$ENC_VER" "$TOKEN" "$N" "$TYPE")

    # 精确切割 C 程序的输出，严防不可见的 \r 回车符破坏 HTTP URL！
    ENCRYPTED_MD5=$(echo "$CRYPTO_OUT" | awk 'NR==1' | tr -d '\r\n ')
    ENCRYPTED_INFO=$(echo "$CRYPTO_OUT" | awk 'NR==2' | tr -d '\r\n ')
    ENCRYPTED_CHKSTR=$(echo "$CRYPTO_OUT" | awk 'NR==3' | tr -d '\r\n ')

    # 补齐官方 JS 悄悄发送的 os, name, double_stack 参数
    LOGIN_RESP=$(curl -s -G \
        -H "User-Agent: $UA" \
        --data-urlencode "callback=jsonp1583251661367" \
        --data-urlencode "action=login" \
        --data-urlencode "username=${USER_ID}@cucc" \
        --data-urlencode "password=${ENCRYPTED_MD5}" \
        --data-urlencode "os=Windows 10" \
        --data-urlencode "name=Windows" \
        --data-urlencode "double_stack=0" \
        --data-urlencode "ac_id=${AC_ID}" \
        --data-urlencode "ip=${IP}" \
        --data-urlencode "info=${ENCRYPTED_INFO}" \
        --data-urlencode "chksum=${ENCRYPTED_CHKSTR}" \
        --data-urlencode "n=${N}" \
        --data-urlencode "type=${TYPE}" \
        "http://$SRUN_IP/cgi-bin/srun_portal")

    log_msg "登录请求已发送，响应: $LOGIN_RESP"
}

if ! is_connected; then
    login
else
    exit 0
fi