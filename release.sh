#!/bin/bash

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 0. Verifica GitHub CLI
if ! command -v gh &> /dev/null; then
    echo -e "${RED}Erro: GitHub CLI ('gh') não instalado.${NC}"
    exit 1
fi

# 1. Validação
VERSION=$1
if [ -z "$VERSION" ]; then
    echo -e "${RED}Erro: Informe a versão (ex: ./release.sh v1.0.0)${NC}"
    exit 1
fi

# 2. Git Check
if [[ -n $(git status -s) ]]; then
    echo -e "${RED}Erro: Git sujo. Faça commit antes.${NC}"
    exit 1
fi

# Configs
BINARY_NAME="proxy-server"
DIST_DIR="dist/proxy-manager"
ARCHIVE_NAME="proxy-manager-linux-${VERSION}.tar.gz"

echo -e "${GREEN}>>> Iniciando Release: $VERSION${NC}"

echo "🧹 Limpando builds anteriores..."
rm -rf dist
mkdir -p $DIST_DIR

echo "🔨 Compilando..."
# old building 
# env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=${VERSION}" -o $DIST_DIR/$BINARY_NAME ./cmd/server
# CGO_ENABLED=0 garante um binário estático, sem dependências de bibliotecas C do Mac
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=${VERSION}" -o $DIST_DIR/$BINARY_NAME ./cmd/server

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Erro na compilação!${NC}"
    exit 1
fi

echo "📂 Copiando arquivos..."
cp -r assets $DIST_DIR/
cp server.toml $DIST_DIR/
cp scripts/install.sh $DIST_DIR/
cp setup.sh $DIST_DIR/
cp keygen.go $DIST_DIR/

if [ -d "certs" ]; then
    cp -r certs $DIST_DIR/
fi

echo "📦 Compactando..."
cd dist
tar -czvf $ARCHIVE_NAME proxy-manager/

# Remove a pasta descompactada temporária
rm -rf proxy-manager/

cd ..

FILE_TO_UPLOAD="dist/$ARCHIVE_NAME"

echo "🏷️  Git Tag..."
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    git tag -d "$VERSION"
fi
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION" --force

echo "🚀 Subindo para o GitHub..."
gh release create "$VERSION" "$FILE_TO_UPLOAD" \
    --title "Release $VERSION" \
    --notes "Release automática." \
    --latest

# --- LIMPEZA TOTAL AQUI ---
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ SUCESSO!${NC}"
    echo "O arquivo foi enviado para o GitHub."
    
    echo "🧹 Limpeza Final: Removendo arquivos locais..."
    rm -rf dist
    
    echo "✨ Tudo pronto e limpo."
else
    echo -e "${RED}❌ Erro no upload. O arquivo .tar.gz foi mantido em 'dist/' para análise.${NC}"
fi