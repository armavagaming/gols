#!/bin/bash
set -e

# =========================================================
# Deploy PHP-версии Scoreboard App на Beget
# Домен: test2.artema7t.beget.tech
# =========================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${YELLOW}Домашняя директория: $HOME${NC}"

PUBLIC_HTML="$HOME/test2.artema7t.beget.tech/public_html"

echo -e "${YELLOW}Целевая папка: $PUBLIC_HTML${NC}"

if [ ! -d "$PUBLIC_HTML" ]; then
    echo -e "${RED}Папка $PUBLIC_HTML не найдена!${NC}"
    echo "Сначала создайте сайт в панели Beget."
    exit 1
fi

ARCHIVE_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE="$ARCHIVE_DIR/sboard-php-deploy.zip"
[ ! -f "$ARCHIVE" ] && ARCHIVE="$(pwd)/sboard-php-deploy.zip"
[ ! -f "$ARCHIVE" ] && ARCHIVE="$PUBLIC_HTML/sboard-php-deploy.zip"

if [ ! -f "$ARCHIVE" ]; then
    echo -e "${RED}Ошибка: sboard-php-deploy.zip не найден!${NC}"
    exit 1
fi

echo -e "${YELLOW}Распаковываю...${NC}"
unzip -o "$ARCHIVE" -d "$PUBLIC_HTML"

# Права на запись для загрузок и базы
chmod 755 "$PUBLIC_HTML/uploads" 2>/dev/null || true
touch "$PUBLIC_HTML/sboard.db" 2>/dev/null || true
chmod 644 "$PUBLIC_HTML/sboard.db" 2>/dev/null || true

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Деплой PHP-версии завершён!${NC}"
echo -e "${GREEN}  Сайт: http://test2.artema7t.beget.tech${NC}"
echo -e "${GREEN}  API:  http://test2.artema7t.beget.tech/api/plans${NC}"
echo -e "${GREEN}  Логин: admin@admin.com / admin${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "PHP версия не требует перезапуска — изменения применяются сразу."
