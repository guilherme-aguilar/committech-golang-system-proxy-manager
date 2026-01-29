#!/bin/bash

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

APP_NAME="proxy-server"
SERVICE_NAME="proxy-manager"
INSTALL_DIR="/opt/proxy-manager"
CERT_DIR="$INSTALL_DIR/certs"
ASSETS_DIR="$INSTALL_DIR/assets"
USER="proxyuser"

echo -e "${BLUE}>>> Iniciando Instalação do Proxy Manager Enterprise...${NC}"

# 0. Verificação de Root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Erro: Rode como root (sudo).${NC}"
    exit 1
fi

# 1. Validação do Pacote
if [[ ! -f "$APP_NAME" || ! -d "assets" ]]; then
    echo -e "${RED}Erro Crítico: Binário '$APP_NAME' ou pasta 'assets' ausentes.${NC}"
    echo "Rode este script de dentro da pasta descompactada."
    exit 1
fi

# 2. Parar serviço antigo
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "🛑 Parando serviço atual..."
    systemctl stop $SERVICE_NAME
fi

# 3. Criar usuário de sistema
if ! id "$USER" &>/dev/null; then 
    echo "👤 Criando usuário de serviço..."
    useradd -r -s /bin/false $USER
fi

# 4. Criar estrutura de pastas
echo "📂 Preparando diretórios em $INSTALL_DIR..."
mkdir -p $INSTALL_DIR
mkdir -p $CERT_DIR
mkdir -p $ASSETS_DIR

# 5. Copiar Arquivos Principais
echo "📦 Copiando binários e assets..."
cp -f "$APP_NAME" "$INSTALL_DIR/"
cp -f "keygen.go" "$INSTALL_DIR/" 2>/dev/null

# Copia assets recursivamente (sobrescreve html/css antigos para atualizar o painel)
cp -r assets/* "$ASSETS_DIR/"

# 6. CONFIGURAÇÃO (Lógica de Preservação + Referência)
echo "⚙️  Verificando configurações..."
if [ -f "$INSTALL_DIR/server.toml" ]; then
    echo -e "${YELLOW}   -> Configuração existente detectada. PRESERVANDO a atual.${NC}"
    echo "   -> A versão nova foi salva como 'server.toml.new' para consulta."
    # Copia o novo arquivo como .new para o admin comparar depois se quiser
    cp "server.toml" "$INSTALL_DIR/server.toml.new"
else
    echo -e "${GREEN}   -> Instalando configuração padrão.${NC}"
    cp "server.toml" "$INSTALL_DIR/"
fi

# 7. BANCO DE DADOS (Preservação)
if [ -f "$INSTALL_DIR/manager.db" ]; then
    echo "🗄️  Banco de dados existente. PRESERVANDO."
else
    if [ -f "manager.db" ]; then
        echo "🗄️  Instalando banco de dados inicial..."
        cp "manager.db" "$INSTALL_DIR/"
    fi
fi

# 8. LÓGICA DE CERTIFICADOS
echo "🔐 Verificando certificados..."

if [[ -f "$CERT_DIR/ca.key" && -f "$CERT_DIR/server.crt" ]]; then
    echo -e "${GREEN}✅ Certificados já existem. Mantendo.${NC}"

elif [ -d "certs" ] && [ "$(ls -A certs)" ]; then
    echo "📂 Instalando certificados do pacote..."
    cp -r certs/* "$CERT_DIR/"

else
    echo -e "${YELLOW}⚠️  Gerando novos certificados (Self-Signed)...${NC}"
    
    # Tenta usar o Go (Melhor opção para compatibilidade)
    if command -v go &> /dev/null && [ -f "$INSTALL_DIR/keygen.go" ]; then
        echo "🔨 Usando Go para gerar certificados com SANs..."
        curr=$(pwd)
        cd "$INSTALL_DIR"
        go run keygen.go >/dev/null 2>&1
        cd "$curr"
    else
        # Fallback OpenSSL
        echo "🔒 Usando OpenSSL..."
        openssl genrsa -out "$CERT_DIR/ca.key" 2048 2>/dev/null
        openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
            -subj "/CN=ProxyManagerCA" -out "$CERT_DIR/ca.crt" 2>/dev/null
            
        openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
        
        # Cria arquivo de config temporário para injetar SANs (IP 127.0.0.1)
        # Isso é vital para o Client Go não dar erro de certificado inválido
        SAN_CONF=$(mktemp)
        cat <<EOF > "$SAN_CONF"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = localhost
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
        openssl req -new -key "$CERT_DIR/server.key" \
            -config "$SAN_CONF" -out "$CERT_DIR/server.csr" 2>/dev/null
            
        openssl x509 -req -in "$CERT_DIR/server.csr" \
            -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
            -out "$CERT_DIR/server.crt" -days 3650 \
            -extensions v3_req -extfile "$SAN_CONF" 2>/dev/null
            
        rm -f "$CERT_DIR/"*.csr "$CERT_DIR/"*.srl "$SAN_CONF"
    fi
fi

# 9. Permissões
echo "🛡️  Ajustando permissões..."
chown -R $USER:$USER $INSTALL_DIR
chmod +x "$INSTALL_DIR/$APP_NAME"
chmod -R 755 "$ASSETS_DIR"
chmod 700 "$CERT_DIR"
chmod 600 "$CERT_DIR/"*.key 2>/dev/null

# 10. SystemD
echo "⚙️  Configurando serviço..."
cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=Proxy Manager Enterprise Server
After=network.target

[Service]
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$APP_NAME
Restart=always
RestartSec=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME >/dev/null
systemctl start $SERVICE_NAME

sleep 2

if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}>>> Instalação Concluída!${NC}"
    
    # Tenta ler a porta do arquivo de config real
    PORT=$(grep 'admin_port' "$INSTALL_DIR/server.toml" 2>/dev/null | cut -d '"' -f 2 | sed 's/://')
    [ -z "$PORT" ] && PORT="8083"

    echo -e "📡 Painel: http://SEU_IP:${PORT}"
    
    if [ ! -f "manager.db" ]; then
       echo "🔑 Senha inicial (verifique os logs):"
       echo "   journalctl -u $SERVICE_NAME -n 20 --no-pager"
    else
       echo "🔑 Use suas credenciais existentes."
    fi
else
    echo -e "${RED}>>> Falha ao iniciar serviço.${NC}"
    journalctl -u $SERVICE_NAME -n 20 --no-pager
    exit 1
fi