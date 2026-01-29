#!/bin/bash

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 0. Verifica se o GitHub CLI (gh) está instalado
if ! command -v gh &> /dev/null; then
    echo -e "${RED}Erro: O GitHub CLI ('gh') não está instalado.${NC}"
    echo "Instale com: brew install gh"
    exit 1
fi

# 1. Validação de Argumento (Versão)
VERSION=$1
if [ -z "$VERSION" ]; then
    echo -e "${RED}Erro: Você precisa especificar a versão!${NC}"
    echo "Uso: ./release.sh v1.0.0"
    exit 1
fi

# 2. Validação do Git
echo "🔍 Verificando estado do Git..."
if [[ -n $(git status -s) ]]; then
    echo -e "${RED}Erro: O diretório de trabalho não está limpo.${NC}"
    echo "Por favor, faça commit ou stash das suas alterações antes de gerar uma release."
    exit 1
fi

# Configurações de Pastas
BINARY_NAME="proxy-server"
DIST_DIR="dist/proxy-manager"
ARCHIVE_NAME="proxy-manager-linux-${VERSION}.tar.gz"

echo -e "${GREEN}>>> Iniciando Release: $VERSION${NC}"

echo "🧹 Limpando builds anteriores..."
rm -rf dist
mkdir -p $DIST_DIR

echo "🔨 Compilando o servidor Go..."
env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=${VERSION}" -o $DIST_DIR/$BINARY_NAME ./cmd/server

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Erro na compilação!${NC}"
    exit 1
fi

echo "📂 Copiando Assets e Configurações..."
cp -r assets $DIST_DIR/
cp server.toml $DIST_DIR/
cp scripts/install.sh $DIST_DIR/
cp setup.sh $DIST_DIR/
cp keygen.go $DIST_DIR/

if [ -d "certs" ]; then
    echo "🔐 Incluindo certificados..."
    cp -r certs $DIST_DIR/
else
    echo -e "${YELLOW}⚠️  Pasta 'certs' não encontrada.${NC}"
fi

echo "📦 Compactando..."
cd dist
tar -czvf $ARCHIVE_NAME proxy-manager/
cd ..

# CAMINHO ABSOLUTO DO ARQUIVO PARA O GITHUB
FILE_TO_UPLOAD="dist/$ARCHIVE_NAME"

echo "🏷️  Criando Tag Git: $VERSION..."
# Se a tag já existir localmente, deleta e recria (útil se você errou algo e rodou de novo)
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    git tag -d "$VERSION"
fi
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION" --force

echo "🚀 Enviando Release para o GitHub..."

# AQUI ESTÁ A MÁGICA
# Cria a release no GitHub E sobe o arquivo .tar.gz
gh release create "$VERSION" "$FILE_TO_UPLOAD" \
    --title "Release $VERSION" \
    --notes "Release gerada automaticamente via script." \
    --latest

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ SUCESSO TOTAL!${NC}"
    echo "O arquivo $ARCHIVE_NAME foi enviado para o GitHub."
    echo "Confira em: https://github.com/SEU_USUARIO/SEU_REPO/releases"
else
    echo -e "${RED}❌ Erro ao subir para o GitHub via CLI.${NC}"
fi