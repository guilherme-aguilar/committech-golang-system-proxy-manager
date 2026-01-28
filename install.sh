#!/bin/bash

# Cores para logs
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configurações
APP_NAME="proxy-server"
SERVICE_NAME="proxy-manager"
INSTALL_DIR="/opt/proxy-manager"
USER="proxyuser"

echo -e "${GREEN}>>> Iniciando Instalação do Proxy Manager Enterprise...${NC}"

# 1. Verifica se é Root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Por favor, rode este script como root (sudo ./install.sh)${NC}"
    exit 1
fi

# 2. Verifica se os arquivos necessários existem na pasta atual
if [[ ! -f "$APP_NAME" || ! -f "dashboard.html" || ! -d "certs" ]]; then
    echo -e "${RED}Erro: Arquivos de instalação não encontrados!${NC}"
    echo "Certifique-se de que '$APP_NAME', 'dashboard.html' e a pasta 'certs/' estão aqui."
    exit 1
fi

# 3. Para o serviço se já estiver rodando
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "Parando serviço existente..."
    systemctl stop $SERVICE_NAME
fi

# 4. Cria usuário de sistema (sem login) se não existir
if ! id "$USER" &>/dev/null; then
    echo "Criando usuário de sistema: $USER"
    useradd -r -s /bin/false $USER
fi

# 5. Cria estrutura de diretórios
echo "Criando diretório em $INSTALL_DIR..."
mkdir -p $INSTALL_DIR

# 6. Copia os arquivos
echo "Copiando arquivos..."
cp "$APP_NAME" "$INSTALL_DIR/"
cp "dashboard.html" "$INSTALL_DIR/"
cp -r "certs" "$INSTALL_DIR/"

# Se existir server.toml, copia também (opcional)
if [ -f "server.toml" ]; then
    cp "server.toml" "$INSTALL_DIR/"
    echo "Configuração server.toml copiada."
fi

# Se existir manager.db, copia (para preservar dados), caso contrário não faz nada
if [ -f "manager.db" ]; then
    echo "Banco de dados existente encontrado. Copiando..."
    cp "manager.db" "$INSTALL_DIR/"
fi

# 7. Define Permissões (Segurança Crítica)
echo "Ajustando permissões..."
chown -R $USER:$USER $INSTALL_DIR
chmod +x "$INSTALL_DIR/$APP_NAME"
chmod 700 "$INSTALL_DIR/certs" # Apenas o usuário pode ler os certs

# 8. Cria o arquivo de serviço Systemd
echo "Criando arquivo de serviço..."
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

# 9. Ativa e Inicia
echo "Recarregando daemon e iniciando serviço..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

# 10. Status Final
if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}>>> SUCESSO! O Proxy Manager foi instalado e está rodando.${NC}"
    echo "---------------------------------------------------"
    echo "Comandos úteis:"
    echo "  Parar:     systemctl stop $SERVICE_NAME"
    echo "  Iniciar:   systemctl start $SERVICE_NAME"
    echo "  Reiniciar: systemctl restart $SERVICE_NAME"
    echo "  Status:    systemctl status $SERVICE_NAME"
    echo "  Ver Logs:  journalctl -u $SERVICE_NAME -f"
    echo "---------------------------------------------------"
else
    echo -e "${RED}>>> ERRO: O serviço falhou ao iniciar. Verifique os logs com: journalctl -u $SERVICE_NAME -n 50${NC}"
fi