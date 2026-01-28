#!/bin/bash

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

APP_NAME="proxy-server"
SERVICE_NAME="proxy-manager"
INSTALL_DIR="/opt/proxy-manager"
CERT_DIR="$INSTALL_DIR/certs"
USER="proxyuser"

echo -e "${GREEN}>>> Iniciando Instalação do Proxy Manager Enterprise...${NC}"

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Erro: Rode como root (sudo).${NC}"
    exit 1
fi

# 1. Validação básica (não exige mais a pasta certs na origem)
if [[ ! -f "$APP_NAME" || ! -f "dashboard.html" ]]; then
    echo -e "${RED}Erro: Binário ou dashboard não encontrados no pacote.${NC}"
    exit 1
fi

# 2. Parar serviço
systemctl stop $SERVICE_NAME &>/dev/null

# 3. Criar usuário
if ! id "$USER" &>/dev/null; then useradd -r -s /bin/false $USER; fi

# 4. Criar pastas
mkdir -p $INSTALL_DIR
mkdir -p $CERT_DIR

# 5. Copiar Arquivos
cp "$APP_NAME" "$INSTALL_DIR/"
cp "dashboard.html" "$INSTALL_DIR/"
[ -f "server.toml" ] && cp "server.toml" "$INSTALL_DIR/"
[ -f "manager.db" ] && cp "manager.db" "$INSTALL_DIR/"

# ==============================================================================
# 6. LÓGICA DE CERTIFICADOS (O PULO DO GATO) 🔐
# ==============================================================================

# Se JÁ existem certificados lá (de uma instalação anterior), não mexe.
if [[ -f "$CERT_DIR/ca.key" && -f "$CERT_DIR/server.crt" ]]; then
    echo "✅ Certificados existentes detectados. Mantendo..."
else
    # Se vieram certificados no pacote .tar.gz (backup manual), usa eles
    if [ -d "certs" ]; then
        echo "📂 Instalando certificados fornecidos no pacote..."
        cp -r certs/* "$CERT_DIR/"
    else
        # SE NÃO TEM NADA, GERA AGORA!
        echo "🔒 Gerando novos certificados de segurança (Self-Signed)..."
        
        # A. Gera CA (Autoridade)
        openssl genrsa -out "$CERT_DIR/ca.key" 2048
        openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" -subj "/CN=ProxyManagerCA" -out "$CERT_DIR/ca.crt"

        # B. Gera Server Keypair
        openssl genrsa -out "$CERT_DIR/server.key" 2048
        openssl req -new -key "$CERT_DIR/server.key" -subj "/CN=localhost/OU=server" -out "$CERT_DIR/server.csr"
        openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt" -days 3650
        
        echo "✅ Certificados gerados com sucesso em $CERT_DIR"
    fi
fi

# Remove arquivos temporários de geração (CSR, SRL) para limpeza
rm -f "$CERT_DIR/"*.csr "$CERT_DIR/"*.srl

# ==============================================================================

# 7. Permissões
chown -R $USER:$USER $INSTALL_DIR
chmod +x "$INSTALL_DIR/$APP_NAME"
chmod 700 "$CERT_DIR"
chmod 600 "$CERT_DIR/"*.key # Chaves privadas legíveis apenas pelo root/dono

# 8. Serviço Systemd
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

# 9. Start
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}>>> Instalação Concluída! Serviço rodando.${NC}"
else
    echo -e "${RED}>>> Falha ao iniciar o serviço. Verifique: journalctl -u $SERVICE_NAME -n 50${NC}"
    exit 1
fi