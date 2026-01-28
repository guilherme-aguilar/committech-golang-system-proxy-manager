#!/bin/bash
# Arquivo: setup.sh

# Configurações do Repositório
REPO_OWNER="guilherme-aguilar"
REPO_NAME="committech-golang-system-proxy-manager"
BIN_NAME="proxy-manager-linux.tar.gz"

# Cores
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> Iniciando Instalador Automático Committech...${NC}"

# 1. Detectar a última versão (Release) via API do GitHub
echo "Buscando versão mais recente..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Erro: Não foi possível encontrar uma release no GitHub."
    echo "Certifique-se de que você criou uma Release lá."
    exit 1
fi

echo -e "Versão detectada: ${GREEN}$LATEST_TAG${NC}"
DOWNLOAD_URL="https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$LATEST_TAG/$BIN_NAME"

# 2. Preparar ambiente temporário
TMP_DIR=$(mktemp -d)
echo "Diretório temporário: $TMP_DIR"

# 3. Baixar
echo "Baixando $DOWNLOAD_URL..."
if curl -L -o "$TMP_DIR/$BIN_NAME" "$DOWNLOAD_URL"; then
    echo "Download concluído."
else
    echo "Erro no download."
    exit 1
fi

# 4. Extrair e Instalar
echo "Extraindo..."
tar -xzf "$TMP_DIR/$BIN_NAME" -C "$TMP_DIR"

echo "Executando script de instalação interno..."
# Entra na pasta descompactada (ajuste o nome da pasta se seu tar criar uma subpasta)
cd "$TMP_DIR/proxy-manager"

# Garante permissão e executa
chmod +x install.sh
if sudo ./install.sh; then
    echo -e "${GREEN}Instalação Finalizada com Sucesso!${NC}"
else
    echo "Erro na execução do install.sh"
    exit 1
fi

# 5. Limpeza
rm -rf "$TMP_DIR"