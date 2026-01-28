#!/bin/bash

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

# Verifica se a tag já existe
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo -e "${RED}Erro: A tag '$VERSION' já existe no Git.${NC}"
    exit 1
fi

# Configurações de Pastas
BINARY_NAME="proxy-server"
DIST_DIR="dist/proxy-manager"
ARCHIVE_NAME="proxy-manager-linux-${VERSION}.tar.gz" # Nome com versão

echo -e "${GREEN}>>> Iniciando Release: $VERSION${NC}"

echo "🧹 Limpando builds anteriores..."
rm -rf dist
mkdir -p $DIST_DIR

echo "🔨 Compilando o servidor Go..."
# DICA PRO: Injetamos a versão dentro do binário usando -ldflags
env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=${VERSION}" -o $DIST_DIR/$BINARY_NAME ./cmd

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Erro na compilação!${NC}"
    exit 1
fi

echo "📂 Copiando Assets..."
cp assets/dashboard.html $DIST_DIR/
cp assets/server.toml $DIST_DIR/
cp scripts/install.sh $DIST_DIR/

# Certificados (Lógica de segurança mantida)
if [ -d "certs" ]; then
    echo "🔐 Incluindo certificados locais..."
    cp -r certs $DIST_DIR/
else
    echo -e "${YELLOW}⚠️  Pasta 'certs' não encontrada. O pacote irá sem certificados.${NC}"
fi

echo "📦 Compactando..."
cd dist
tar -czvf $ARCHIVE_NAME proxy-manager/
cd ..

echo "🏷️  Criando Tag Git: $VERSION..."
git tag -a "$VERSION" -m "Release $VERSION gerada automaticamente"

echo "🚀 Enviando Tag para o GitHub..."
git push origin "$VERSION"

echo ""
echo -e "${GREEN}✅ SUCESSO! Release $VERSION finalizada.${NC}"
echo "--------------------------------------------------------"
echo "Arquivo gerado: dist/$ARCHIVE_NAME"
echo "A tag Git foi enviada. Agora vá ao GitHub Releases e anexe o arquivo .tar.gz."
echo "--------------------------------------------------------"