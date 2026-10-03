#!/usr/bin/env bash
# ==============================================================================
# DevProxy 1-Line Installer for Linux & macOS
# Run: curl -fsSL https://raw.githubusercontent.com/j46871417-ui/devproxy/main/install.sh | bash
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

printf "${CYAN}${BOLD}"
cat <<'EOF'
  _____              _____                     
 |  __ \            |  __ \                    
 | |  | | _____   __| |__) | __ _____  ___   _ 
 | |  | |/ _ \ \ / /|  ___/ '__/ _ \ \/ / | | |
 | |__| |  __/\ V / | |   | | | (_) >  <| |_| |
 |_____/ \___| \_/  |_|   |_|  \___/_/\_\\__, |
                                          __/ |
                                         |___/ 
EOF
printf "${NC}\n"
echo "Установка DevProxy CLI для Linux & macOS..."

# Determine installation directory
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"

    # Ensure ~/.local/bin is in PATH
    SHELL_RC=""
    if [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    fi

    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        if [ -n "$SHELL_RC" ]; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
            echo "Добавлен ~/.local/bin в PATH ($SHELL_RC)"
        fi
        export PATH="$HOME/.local/bin:$PATH"
    fi
fi

RAW_URL="https://raw.githubusercontent.com/j46871417-ui/devproxy/main/devproxy"
TARGET="$INSTALL_DIR/devproxy"

echo "Скачивание утилиты в $TARGET..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$RAW_URL" -o "$TARGET"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TARGET" "$RAW_URL"
else
    echo "Ошибка: требуется curl или wget для загрузки." >&2
    exit 1
fi

chmod +x "$TARGET"

printf "\n${GREEN}${BOLD}✓ DevProxy CLI успешно установлен в $TARGET!${NC}\n\n"
echo "Для запуска просто введите в терминале:"
printf "  ${CYAN}devproxy${NC}            - интерактивное меню\n"
printf "  ${CYAN}devproxy [ПРОКСИ]${NC}   - применить прокси сразу\n"
printf "  ${CYAN}devproxy --status${NC}   - проверить текущие настройки\n"
printf "  ${CYAN}devproxy --remove${NC}   - сбросить все прокси\n\n"

if [ "$INSTALL_DIR" = "$HOME/.local/bin" ] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    printf "${YELLOW}Примечание: Перезапустите терминал или выполните: source %s${NC}\n\n" "$SHELL_RC"
fi
