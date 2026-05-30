#!/bin/bash
# =========================================================================
#            SUPER BOX - HIDE-UI CONSOLE MANAGEMENT MENU (RU)
#            Управление сервером Super Box / Hidekey
# =========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

SUPERBOX_DIR="/var/lib/super_box"
if [ -f "$SUPERBOX_DIR/python3" ]; then
    SUPERBOX_BIN="$SUPERBOX_DIR/python3"
else
    SUPERBOX_BIN="$SUPERBOX_DIR/target/release/super_box"
fi
SUPERBOX_LOG="/var/log/super_box.log"

restart_panel() {
    pkill -f "$SUPERBOX_DIR/python3" 2>/dev/null
    killall super_box 2>/dev/null
    sleep 1.2
    nohup bash -c "cd $SUPERBOX_DIR && $SUPERBOX_BIN server" > "$SUPERBOX_LOG" 2>&1 &
    sleep 2
}

get_panel_status() {
    if ps aux | grep -v grep | grep "$SUPERBOX_DIR/python3" | grep -q "server" || ps aux | grep -v grep | grep -q "super_box server"; then
        echo -e "${GREEN}● Работает${NC}"
    else
        echo -e "${RED}○ Остановлена${NC}"
    fi
}

get_public_ip() {
    curl -4 -s --max-time 4 api.ipify.org 2>/dev/null || curl -4 -s --max-time 4 ifconfig.me 2>/dev/null || echo "YOUR_VPS_IP"
}

get_secret_path() {
    local panel_secret_path=""
    if [ -f "$SUPERBOX_DIR/panel.conf" ]; then
        source "$SUPERBOX_DIR/panel.conf"
    fi
    echo "$panel_secret_path"
}

show_header() {
    clear
    local STATUS
    STATUS=$(get_panel_status)
    local PUBLIC_IP
    PUBLIC_IP=$(get_public_ip)
    
    local panel_port="8082"
    local panel_secret_path=""
    if [ -f "$SUPERBOX_DIR/panel.conf" ]; then
        source "$SUPERBOX_DIR/panel.conf"
    fi

    local PANEL_LINK
    if [ -z "$panel_secret_path" ]; then
        PANEL_LINK="https://${PUBLIC_IP}:${panel_port}/"
    else
        PANEL_LINK="https://${PUBLIC_IP}:${panel_port}/${panel_secret_path}/"
    fi

    echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}       ${BOLD}SUPER BOX — Hidekey Management Console${NC}          ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Статус: $STATUS"
    echo -e "${CYAN}║${NC}  Панель: ${YELLOW}${PANEL_LINK}${NC}"
    echo -e "${CYAN}║${NC}  Ядро  : ${MAGENTA}Hidekey v0.1.0 / RTP-стеганография${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════╣${NC}"
    echo ""
}

show_menu() {
    echo -e "  ${BOLD}Основные:${NC}"
    echo -e "    ${YELLOW}[1]${NC}  Просмотр логов панели"
    echo -e "    ${YELLOW}[2]${NC}  Перезапустить панель"
    echo -e "    ${YELLOW}[3]${NC}  Остановить панель"
    echo ""
    echo -e "  ${BOLD}Безопасность и доступ:${NC}"
    echo -e "    ${YELLOW}[4]${NC}  Сменить логин и пароль администратора"
    echo -e "    ${YELLOW}[5]${NC}  Изменить порт панели"
    echo -e "    ${YELLOW}[6]${NC}  ${BOLD}Настроить ЛАПШУ${NC} (секретный путь к панели)"
    echo -e "    ${YELLOW}[7]${NC}  Обновить TLS-сертификат панели"
    echo -e "    ${YELLOW}[8]${NC}  Показать реквизиты доступа к веб-панели (URL, логин, пароль)"
    echo ""
    echo -e "  ${BOLD}Оптимизация сети:${NC}"
    echo -e "    ${YELLOW}[9]${NC}  Включить ускорение TCP BBR"
    echo -e "    ${YELLOW}[10]${NC} Установить Cloudflare WARP (очистка репутации IP)"
    echo ""
    echo -e "  ${YELLOW}[0]${NC}  Выйти"
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────${NC}"
    echo -n "  Выберите действие [0-10]: "
}

# ── 1. Логи ──────────────────────────────────────────────────────────────────
action_logs() {
    clear
    echo -e "${YELLOW}=== Последние 50 строк логов Super Box ===${NC}"
    echo ""
    if [ -f "$SUPERBOX_LOG" ]; then
        tail -n 50 "$SUPERBOX_LOG" | sed \
            -e "s/ERROR/$(printf '\033[0;31m')ERROR$(printf '\033[0m')/g" \
            -e "s/INFO/$(printf '\033[0;32m')INFO$(printf '\033[0m')/g" \
            -e "s/WARN/$(printf '\033[1;33m')WARN$(printf '\033[0m')/g"
    else
        echo -e "${RED}Лог-файл не найден. Панель ещё не запускалась.${NC}"
    fi
    echo ""
    echo -n "Нажмите любую клавишу для возврата..."
    read -r -n 1
}

# ── 2. Перезапуск ─────────────────────────────────────────────────────────────
action_restart() {
    clear
    echo -e "${YELLOW}[*] Перезапуск панели Hide-UI...${NC}"
    restart_panel
    echo -e "${GREEN}✔ Панель успешно перезапущена!${NC}"
    sleep 2
}

# ── 3. Остановка ──────────────────────────────────────────────────────────────
action_stop() {
    clear
    echo -e "${YELLOW}[*] Остановка панели...${NC}"
    pkill -f "$SUPERBOX_DIR/python3" 2>/dev/null
    killall super_box 2>/dev/null
    sleep 1
    echo -e "${GREEN}✔ Панель остановлена.${NC}"
    sleep 2
}

# ── 4. Смена логина/пароля ────────────────────────────────────────────────────
action_change_credentials() {
    clear
    echo -e "${YELLOW}=== Смена учётных данных администратора ===${NC}"
    echo ""
    echo -n "  Новый логин [admin]: "
    read -r new_user
    [ -z "$new_user" ] && new_user="admin"

    echo -n "  Новый пароль [hidekey2026]: "
    read -r -s new_pass
    echo ""
    [ -z "$new_pass" ] && new_pass="hidekey2026"

    echo ""
    echo -e "[*] Временная остановка для записи в БД..."
    pkill -f "$SUPERBOX_DIR/python3" 2>/dev/null
    killall super_box 2>/dev/null
    sleep 1.2

    cd "$SUPERBOX_DIR" && "$SUPERBOX_BIN" set-admin "$new_user" "$new_pass"

    echo -e "[*] Запуск панели с новыми учётными данными..."
    nohup bash -c "cd $SUPERBOX_DIR && $SUPERBOX_BIN server" > "$SUPERBOX_LOG" 2>&1 &
    sleep 2

    echo -e "\n${GREEN}✔ Данные обновлены!${NC}"
    echo -e "   Логин  : ${BOLD}$new_user${NC}"
    echo -e "   Пароль : ${BOLD}$new_pass${NC}"
    sleep 3
}

# ── 5. Смена порта ────────────────────────────────────────────────────────────
action_change_port() {
    clear
    echo -e "${YELLOW}=== Изменение порта веб-панели ===${NC}"
    echo ""
    echo -n "  Новый порт [8082]: "
    read -r new_port
    [ -z "$new_port" ] && new_port="8082"

    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${RED}Ошибка: введите корректный номер порта (1-65535)${NC}"
        sleep 2
        return
    fi

    echo -e "\n[*] Временная остановка для записи в БД..."
    pkill -f "$SUPERBOX_DIR/python3" 2>/dev/null
    killall super_box 2>/dev/null
    sleep 1.2

    cd "$SUPERBOX_DIR" && "$SUPERBOX_BIN" set-port "$new_port"

    echo -e "[*] Запуск панели на новом порту..."
    nohup bash -c "cd $SUPERBOX_DIR && $SUPERBOX_BIN server" > "$SUPERBOX_LOG" 2>&1 &
    sleep 2

    PUBLIC_IP=$(get_public_ip)
    echo -e "\n${GREEN}✔ Порт изменён на $new_port!${NC}"
    echo -e "   Новый адрес: ${YELLOW}https://${PUBLIC_IP}:${new_port}${NC}"
    sleep 3
}

# ── 6. ЛАПША (секретный путь к панели) ───────────────────────────────────────
action_secret_path() {
    clear
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║     НАСТРОЙКА «ЛАПШИ» — СЕКРЕТНЫЙ ПУТЬ К ПАНЕЛИ     ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Что такое «лапша»?${NC}"
    echo -e "  Это секретный путь в URL, без которого панель управления"
    echo -e "  недоступна. Вместо неё отдаётся поддельная страница nginx."
    echo ""
    echo -e "  Без лапши:  ${RED}https://IP:8082/${NC}  →  открывает панель"
    echo -e "  С лапшой:   ${RED}https://IP:8082/${NC}  →  ${GREEN}404 nginx (обманка)${NC}"
    echo -e "              ${GREEN}https://IP:8082/СЕКРЕТ/${NC}  →  открывает панель"
    echo ""
    echo -e "  ${CYAN}──────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${YELLOW}[1]${NC} Сгенерировать случайный секретный путь"
    echo -e "  ${YELLOW}[2]${NC} Задать свой секретный путь вручную"
    echo -e "  ${YELLOW}[3]${NC} Отключить (открыть доступ без лапши)"
    echo -e "  ${YELLOW}[4]${NC} Показать текущий путь (если задан)"
    echo -e "  ${YELLOW}[0]${NC} Назад"
    echo ""
    echo -n "  Выбор [0-4]: "
    read -r sp_choice

    case $sp_choice in
        1)
            # Генерируем 20-символьный случайный путь
            RANDOM_PATH=$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 22)
            _set_secret_path "$RANDOM_PATH"
            ;;
        2)
            echo ""
            echo -n "  Введите секретный путь (без слешей, только латиница/цифры): "
            read -r custom_path
            # Убираем слеши
            custom_path="${custom_path//\//}"
            if [ -z "$custom_path" ]; then
                echo -e "${RED}Путь не может быть пустым!${NC}"
                sleep 2
                return
            fi
            _set_secret_path "$custom_path"
            ;;
        3)
            _set_secret_path ""
            echo -e "\n${GREEN}✔ Лапша отключена. Панель доступна без секретного пути.${NC}"
            sleep 3
            ;;
        4)
            echo ""
            # Читаем текущий путь из sled DB через set-secret-path запрос
            echo -e "[*] Чтение текущей конфигурации..."
            CURRENT_SP=$(cd "$SUPERBOX_DIR" && "$SUPERBOX_BIN" get-secret-path 2>/dev/null || echo "")
            PUBLIC_IP=$(get_public_ip)
            if [ -z "$CURRENT_SP" ]; then
                echo -e "  Текущий секретный путь: ${RED}не задан${NC}"
                echo -e "  Панель доступна на: ${YELLOW}https://${PUBLIC_IP}:8082/${NC}"
            else
                echo -e "  Текущий секретный путь: ${GREEN}/${CURRENT_SP}/${NC}"
                echo -e "  Панель доступна на: ${YELLOW}https://${PUBLIC_IP}:8082/${CURRENT_SP}/${NC}"
            fi
            echo ""
            echo -n "Нажмите любую клавишу..."
            read -r -n 1
            ;;
        0) return ;;
        *) echo -e "${RED}Неверный выбор.${NC}"; sleep 1.5 ;;
    esac
}

_set_secret_path() {
    local NEW_PATH="$1"
    echo ""
    echo -e "[*] Временная остановка для записи в БД..."
    pkill -f "$SUPERBOX_DIR/python3" 2>/dev/null
    killall super_box 2>/dev/null
    sleep 1.2

    # Записываем путь в sled DB через бинарник
    cd "$SUPERBOX_DIR" && "$SUPERBOX_BIN" set-secret-path "$NEW_PATH"

    echo -e "[*] Перезапуск панели..."
    nohup bash -c "cd $SUPERBOX_DIR && $SUPERBOX_BIN server" > "$SUPERBOX_LOG" 2>&1 &
    sleep 2

    PUBLIC_IP=$(get_public_ip)
    if [ -z "$NEW_PATH" ]; then
        echo -e "\n${GREEN}✔ Лапша отключена.${NC}"
        echo -e "   Адрес панели: ${YELLOW}https://${PUBLIC_IP}:8082/${NC}"
    else
        echo -e "\n${GREEN}✔ Секретный путь установлен!${NC}"
        echo -e "   Путь        : ${BOLD}/${NEW_PATH}/${NC}"
        echo -e "   Адрес панели: ${YELLOW}https://${PUBLIC_IP}:8082/${NEW_PATH}/${NC}"
        echo ""
        echo -e "   ${RED}⚠ СОХРАНИТЕ ЭТОТ АДРЕС — без него панель недоступна!${NC}"
    fi
    sleep 4
}

# ── 7. Обновить TLS-сертификат ────────────────────────────────────────────────
action_renew_cert() {
    clear
    echo -e "${YELLOW}=== Обновление TLS-сертификата панели ===${NC}"
    echo ""
    echo -e "  Панель работает на HTTPS с самоподписанным сертификатом."
    echo -e "  При первом запуске браузер покажет предупреждение — это нормально."
    echo -e "  Нажмите «Продолжить» / «Дополнительно» → «Перейти на сайт»."
    echo ""
    echo -e "[*] Удаление старого сертификата и генерация нового..."
    pkill -f "$SUPERBOX_DIR/python3" 2>/dev/null
    killall super_box 2>/dev/null
    sleep 1.2

    # Удаляем сохранённый сертификат из sled DB
    cd "$SUPERBOX_DIR" && "$SUPERBOX_BIN" reset-tls 2>/dev/null

    echo -e "[*] Перезапуск панели (новый сертификат генерируется при старте)..."
    nohup bash -c "cd $SUPERBOX_DIR && $SUPERBOX_BIN server" > "$SUPERBOX_LOG" 2>&1 &
    sleep 2

    echo -e "\n${GREEN}✔ Новый TLS-сертификат сгенерирован и применён!${NC}"
    echo -e "   Действителен: 10 лет (самоподписанный)"
    sleep 3
}

# ── 8. Показать реквизиты ─────────────────────────────────────────────────────
action_show_access_info() {
    clear
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║        РЕКВИЗИТЫ ДОСТУПА К ВЕБ-ПАНЕЛИ HIDE-UI        ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "[*] Считывание настроек из базы данных..."
    
    # 1. Получаем публичный IP
    local PUBLIC_IP
    PUBLIC_IP=$(get_public_ip)
    
    # 2. Получаем порт, секретный путь, логин и пароль из flat-файла panel.conf
    local panel_port="8082"
    local panel_secret_path=""
    local admin_user="admin"
    local admin_pass="hidekey2026"
    if [ -f "$SUPERBOX_DIR/panel.conf" ]; then
        source "$SUPERBOX_DIR/panel.conf"
    fi
    
    # Ссылка на панель
    local PANEL_LINK
    if [ -z "$panel_secret_path" ]; then
        PANEL_LINK="https://${PUBLIC_IP}:${panel_port}/"
    else
        PANEL_LINK="https://${PUBLIC_IP}:${panel_port}/${panel_secret_path}/"
    fi

    echo ""
    echo -e "  ${BOLD}Адрес панели:${NC}  ${GREEN}${PANEL_LINK}${NC}"
    echo -e "  ${BOLD}Порт панели :${NC}  ${CYAN}${panel_port}${NC}"
    if [ -n "$panel_secret_path" ]; then
        echo -e "  ${BOLD}Секретный путь:${NC} ${YELLOW}/${panel_secret_path}/${NC} (задан)"
    else
        echo -e "  ${BOLD}Секретный путь:${NC} ${RED}не задан${NC} (доступ по корню)"
    fi
    echo ""
    echo -e "  ${CYAN}──────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Имя пользователя:${NC} ${BOLD}${admin_user}${NC}"
    echo -e "  ${BOLD}Пароль          :${NC} ${BOLD}${admin_pass}${NC}"
    echo -e "  ${CYAN}──────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${YELLOW}⚠ Примечание:${NC} Панель работает через HTTPS с самоподписанным"
    echo -e "  сертификатом. При первом входе примите предупреждение"
    echo -e "  безопасности браузера (нажмите «Дополнительно» → «Продолжить»)."
    echo ""
    echo -n "Нажмите любую клавишу для возврата в меню..."
    read -r -n 1
}

# ── 8. BBR ────────────────────────────────────────────────────────────────────
action_enable_bbr() {
    clear
    echo -e "${YELLOW}=== Включение ускорения сети TCP BBR ===${NC}"
    echo ""

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        echo -e "${GREEN}✔ TCP BBR уже включён и работает!${NC}"
        echo -e "   $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null)"
    else
        echo -e "[*] Настройка параметров ядра sysctl..."
        # Удаляем старые строки (если есть) и добавляем новые
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

        sysctl -p >/dev/null 2>&1

        if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
            echo -e "\n${GREEN}✔ TCP BBR успешно активирован!${NC}"
            echo -e "   Алгоритм: bbr  |  Планировщик: fq"
        else
            echo -e "\n${RED}⚠ Ошибка: BBR не поддерживается ядром. Обновите ядро Linux до 4.9+${NC}"
        fi
    fi
    echo ""
    echo -n "Нажмите любую клавишу..."
    read -r -n 1
}

# ── 9. Cloudflare WARP ────────────────────────────────────────────────────────
action_install_warp() {
    clear
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║        УСТАНОВКА CLOUDFLARE WARP НА СЕРВЕР           ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  WARP направляет трафик через сеть Cloudflare, заменяя"
    echo -e "  «грязный» IP сервера на чистый IP Cloudflare."
    echo -e "  Это устраняет блокировки Google, YouTube, Telegram и т.д."
    echo ""

    if command -v warp-cli &>/dev/null; then
        echo -e "  ${GREEN}✔ Cloudflare WARP уже установлен!${NC}"
        echo ""
        WARP_STATUS=$(warp-cli status 2>/dev/null || echo "неизвестен")
        echo -e "  Статус: ${YELLOW}${WARP_STATUS}${NC}"
        echo ""
        echo -e "  ${YELLOW}[1]${NC} Подключить WARP"
        echo -e "  ${YELLOW}[2]${NC} Отключить WARP"
        echo -e "  ${YELLOW}[3]${NC} Показать статус"
        echo -e "  ${YELLOW}[0]${NC} Назад"
        echo ""
        echo -n "  Выбор: "
        read -r w_choice
        case $w_choice in
            1) warp-cli connect && echo -e "${GREEN}✔ WARP подключён!${NC}" ;;
            2) warp-cli disconnect && echo -e "${GREEN}✔ WARP отключён.${NC}" ;;
            3) warp-cli status ;;
            0) return ;;
        esac
        sleep 3
        return
    fi

    echo -n "  Начать установку warp-cli? [да/нет]: "
    read -r confirm
    if [[ "$confirm" != "да" && "$confirm" != "yes" && "$confirm" != "y" && "$confirm" != "д" ]]; then
        return
    fi

    echo ""
    echo -e "[*] Добавление репозитория Cloudflare..."
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | \
        gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] \
        https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | \
        tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null

    echo -e "[*] Обновление пакетов и установка..."
    apt-get update -q 2>/dev/null
    apt-get install -y cloudflare-warp 2>/dev/null

    if command -v warp-cli &>/dev/null; then
        echo -e "\n${GREEN}✔ Cloudflare WARP успешно установлен!${NC}"
        echo -e "[*] Регистрация..."
        warp-cli register 2>/dev/null
        echo -e "[*] Подключение..."
        warp-cli connect 2>/dev/null
        echo -e "${GREEN}✔ WARP активирован! Трафик идёт через Cloudflare.${NC}"
    else
        echo -e "\n${RED}⚠ Установка не удалась. Попробуйте вручную:${NC}"
        echo -e "   curl -fsSL https://pkg.cloudflareclient.com/install.sh | bash"
    fi
    sleep 4
}

# ── ГЛАВНЫЙ ЦИКЛ ──────────────────────────────────────────────────────────────
while true; do
    show_header
    show_menu
    read -r choice

    case $choice in
        1) action_logs ;;
        2) action_restart ;;
        3) action_stop ;;
        4) action_change_credentials ;;
        5) action_change_port ;;
        6) action_secret_path ;;
        7) action_renew_cert ;;
        8) action_show_access_info ;;
        9) action_enable_bbr ;;
        10) action_install_warp ;;
        0)
            clear
            echo -e "${GREEN}До свидания! Super Box / Hidekey всегда на страже.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Неверный выбор. Введите число от 0 до 10.${NC}"
            sleep 1.5
            ;;
    esac
done
