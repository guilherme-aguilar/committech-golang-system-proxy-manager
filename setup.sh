#!/bin/bash
# Arquivo: setup.sh

# --- CONFIGURAÇÃO ---
REPO_OWNER="guilherme-aguilar"
REPO_NAME="committech-golang-system-proxy-manager"
# --------------------

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}>>> Iniciando Instalador Committech Proxy Manager...${NC}"

# 1. Detectar a última versão (Release) via API do GitHub
echo "🔍 Buscando a versão mais recente..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo -e "${RED}Erro: Não foi possível encontrar nenhuma Release no GitHub.${NC}"
    echo "Certifique-se de que você rodou o './release.sh' e fez o upload do arquivo no GitHub."
    exit 1
fi

# Monta o nome do arquivo baseado no padrão do release.sh: proxy-manager-linux-v1.0.0.tar.gz
FILE_NAME="proxy-manager-linux-${LATEST_TAG}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$LATEST_TAG/$FILE_NAME"

echo -e "Versão detectada: ${GREEN}$LATEST_TAG${NC}"
echo -e "Arquivo alvo: $FILE_NAME"

# 2. Preparar ambiente temporário
TMP_DIR=$(mktemp -d)

# 3. Baixar o arquivo
echo "⬇️  Baixando..."
http_code=$(curl -sL -w "%{http_code}" -o "$TMP_DIR/$FILE_NAME" "$DOWNLOAD_URL")

if [ "$http_code" != "200" ]; then
    echo -e "${RED}Erro no download (HTTP $http_code).${NC}"
    echo "URL tentada: $DOWNLOAD_URL"
    echo "Verifique se você anexou o arquivo .tar.gz corretamente na Release do GitHub."
    rm -rf "$TMP_DIR"
    exit 1
fi

# 4. Extrair e Instalar
echo "📦 Extraindo..."
tar -xzf "$TMP_DIR/$FILE_NAME" -C "$TMP_DIR"

echo "🚀 Executando script de instalação..."
# Entra na pasta descompactada (o tar cria a pasta 'proxy-manager')
cd "$TMP_DIR/proxy-manager"

# Garante permissão e executa o install.sh interno
chmod +x install.sh
if ./install.sh; then
    echo -e "${GREEN}✅ Instalação da versão $LATEST_TAG concluída com sucesso!${NC}"
else
    echo -e "${RED}❌ Falha na execução do script de instalação local.${NC}"
    exit 1
fi

# 5. Limpeza
rm -rf "$TMP_DIR"