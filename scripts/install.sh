#!/bin/bash

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

APP_NAME="proxy-server"
SERVICE_NAME="proxy-manager"
INSTALL_DIR="/opt/proxy-manager"
CERT_DIR="$INSTALL_DIR/certs"
ASSETS_DIR="$INSTALL_DIR/assets"
USER="proxyuser"

echo -e "${GREEN}>>> Iniciando Instalação do Proxy Manager Enterprise...${NC}"

# 0. Verificação de Root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Erro: Rode como root (sudo).${NC}"
    exit 1
fi

# 1. Validação de Arquivos do Pacote
# Agora verificamos se a pasta assets existe, e não o arquivo solto
if [[ ! -f "$APP_NAME" || ! -d "assets" ]]; then
    echo -e "${RED}Erro: Binário 'proxy-server' ou pasta 'assets' não encontrados.${NC}"
    echo "Certifique-se de estar rodando o script de dentro da pasta descompactada."
    exit 1
fi

# 2. Parar serviço antigo (se existir)
systemctl stop $SERVICE_NAME &>/dev/null

# 3. Criar usuário de sistema
if ! id "$USER" &>/dev/null; then 
    echo "👤 Criando usuário de serviço..."
    useradd -r -s /bin/false $USER
fi

# 4. Criar estrutura de pastas
echo "📂 Criando diretórios em $INSTALL_DIR..."
mkdir -p $INSTALL_DIR
mkdir -p $CERT_DIR
mkdir -p $ASSETS_DIR

# 5. Copiar Arquivos
echo "📦 Copiando arquivos..."
cp "$APP_NAME" "$INSTALL_DIR/"
cp "keygen.go" "$INSTALL_DIR/" 2>/dev/null # Copia o gerador se existir

# Copia a pasta assets recursivamente
cp -r assets/* "$ASSETS_DIR/"

# Configuração e Banco de Dados (Preserva se já existir no destino)
if [ ! -f "$INSTALL_DIR/server.toml" ]; then
    [ -f "server.toml" ] && cp "server.toml" "$INSTALL_DIR/"
fi

# Se houver um banco de dados no pacote (migração), copia. 
# Mas idealmente o banco fica lá e não é sobrescrito.
if [ -f "manager.db" ] && [ ! -f "$INSTALL_DIR/manager.db" ]; then
    cp "manager.db" "$INSTALL_DIR/"
fi

# 6. LÓGICA DE CERTIFICADOS
echo "🔐 Verificando certificados..."

# Caso 1: Já existem instalados?
if [[ -f "$CERT_DIR/ca.key" && -f "$CERT_DIR/server.crt" ]]; then
    echo "✅ Certificados existentes detectados em $CERT_DIR. Mantendo."

# Caso 2: Vieram no pacote de instalação?
elif [ -d "certs" ] && [ "$(ls -A certs)" ]; then
    echo "📂 Instalando certificados fornecidos no pacote..."
    cp -r certs/* "$CERT_DIR/"

# Caso 3: Não existem. Gerar novos.
else
    echo -e "${YELLOW}⚠️  Nenhum certificado encontrado.${NC}"
    
    # Tenta usar o Go instalado para gerar (Melhor opção)
    if command -v go &> /dev/null && [ -f "$INSTALL_DIR/keygen.go" ]; then
        echo "🔨 Usando Go para gerar certificados com SANs corretos..."
        cd "$INSTALL_DIR"
        go run keygen.go
        cd - > /dev/null
    else
        # Fallback para OpenSSL (Com patch para SAN IP:127.0.0.1)
        echo "🔒 Gerando Self-Signed via OpenSSL (Fallback)..."
        
        openssl genrsa -out "$CERT_DIR/ca.key" 2048
        openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
            -subj "/CN=ProxyManagerRootCA" -out "$CERT_DIR/ca.crt"
            
        openssl genrsa -out "$CERT_DIR/server.key" 2048
        openssl req -new -key "$CERT_DIR/server.key" \
            -subj "/CN=localhost" \
            -addext "subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1" \
            -out "$CERT_DIR/server.csr"
            
        openssl x509 -req -in "$CERT_DIR/server.csr" \
            -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
            -out "$CERT_DIR/server.crt" -days 3650 \
            -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1")
            
        rm -f "$CERT_DIR/"*.csr "$CERT_DIR/"*.srl
        echo "✅ Certificados de emergência gerados."
    fi
fi

# 7. Permissões
echo "🛡️  Ajustando permissões..."
chown -R $USER:$USER $INSTALL_DIR
chmod +x "$INSTALL_DIR/$APP_NAME"
# Pasta assets precisa ser legível
chmod -R 755 "$ASSETS_DIR"
# Pasta certs protegida
chmod 700 "$CERT_DIR"
chmod 600 "$CERT_DIR/"*.key 2>/dev/null

# 8. Configurar SystemD
echo "⚙️  Configurando serviço..."
cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=Proxy Manager Enterprise Server
After=network.target

[Service]
User=$USER
Group=$USER
# IMPORTANTE: O diretório de trabalho deve ser a raiz da instalação
# para que o Go encontre a pasta 'assets/'
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$APP_NAME
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

sleep 2

if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}>>> Instalação Concluída com Sucesso!${NC}"
    echo -e "Painel: http://SEU_IP:8083"
    
    # Mostra a senha inicial se o arquivo de log existir e for recente
    if [ -f "manager.db" ]; then
        echo "Nota: Banco de dados preservado. Use suas credenciais antigas."
    else
        echo "Verifique os logs para pegar a senha de admin inicial:"
        echo "Use: journalctl -u $SERVICE_NAME -n 20 --no-pager"
    fi
else
    echo -e "${RED}>>> Falha ao iniciar o serviço.${NC}"
    journalctl -u $SERVICE_NAME -n 20 --no-pager
    exit 1
fi