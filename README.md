# Comandos Linux (Ubuntu)

Este repositório contém uma coleção de comandos Linux úteis, organizados por categorias relacionadas. Esses comandos podem ser úteis para administração de sistemas, desenvolvimento, segurança, entre outros.

## Índice

1. [Gerenciamento de Pacotes e Software](#gerenciamento-de-pacotes-e-software)
2. [Sistemas de Arquivos e Diretórios](#sistemas-de-arquivos-e-diretórios)
3. [Rede e Conectividade](#rede-e-conectividade)
4. [Controle de Processos](#controle-de-processos)
5. [Logs e Auditoria](#logs-e-auditoria)
6. [Segurança e Criptografia](#segurança-e-criptografia)
7. [Controle de Usuários e Grupos](#controle-de-usuários-e-grupos)
8. [Controle de Recursos e Desempenho](#controle-de-recursos-e-desempenho)
9. [Compilação de Código](#compilação-de-código)
10. [Backup e Restauração](#backup-e-restauração)
11. [Docker](#docker)
12. [Ferramentas de Desenvolvimento](#ferramentas-de-desenvolvimento)
13. [Compressão e Descompressão](#compressão-e-descompressão)
14. [Controle de Pacotes](#controle-de-pacotes)
15. [Controle de Energia](#controle-de-energia)
16. [Segurança de Rede](#segurança-de-rede)
17. [Ferramentas de Desenvolvimento (Continuação)](#ferramentas-de-desenvolvimento-continuação)
18. [Manipulação de Processos](#manipulação-de-processos)
19. [Monitoramento de Hardware](#monitoramento-de-hardware)
20. [Ferramentas de Rede Avançadas](#ferramentas-de-rede-avançadas)
21. [Logs e Auditoria (Continuação)](#logs-e-auditoria-continuação)
22. [Compilação de Código (Continuação)](#compilação-de-código-continuação)
23. [Controle de Recursos e Desempenho (Continuação)](#controle-de-recursos-e-desempenho-continuação)
24. [Comandos de Rede (Continuação)](#comandos-de-rede-continuação)
25. [Controle de Processos (Continuação)](#controle-de-processos-continuação)
26. [Controle de Recursos (Continuação)](#controle-de-recursos-continuação)
27. [Ambiente Gráfico](#ambiente-gráfico)
28. [Configuração do Shell](#configuração-do-shell)
29. [Logs e Auditoria (Continuação)](#logs-e-auditoria-continuação)

## Comandos Linux (Ubuntu)

### Gerenciamento de Pacotes e Software

- `apt-get update`: Atualiza a lista de pacotes disponíveis.
- `apt-get upgrade`: Atualiza os pacotes instalados.
- `apt-get install nome-do-pacote`: Instala um novo pacote.
- `apt-get remove nome-do-pacote`: Remove um pacote instalado.
- `dpkg -i nome-do-pacote.deb`: Instala um pacote DEB.
- `dpkg -l`: Lista todos os pacotes instalados.
- `apt search termo-de-busca`: Procura por pacotes disponíveis.

### Sistemas de Arquivos e Diretórios

- `ls`: Lista arquivos e diretórios.
- `cd nome-do-diretorio`: Muda para um diretório específico.
- `cp origem destino`: Copia arquivos e diretórios.
- `mv origem destino`: Move ou renomeia arquivos e diretórios.
- `rm nome-do-arquivo`: Remove um arquivo.
- `mkdir nome-do-diretorio`: Cria um novo diretório.
- `du -sh /caminho/do/diretorio`: Exibe o tamanho total de um diretório.

### Rede e Conectividade

- `ifconfig`: Exibe informações sobre interfaces de rede.
- `ping endereco-de-destino`: Envia pacotes ICMP para testar a conectividade.
- `traceroute endereco-de-destino`: Exibe a rota dos pacotes até um destino.
- `ss -tunap`: Mostra informações detalhadas sobre todas as conexões de rede.
- `ssh usuario@host`: Conecta-se a um servidor remoto via SSH.
- `scp arquivo.txt usuario@host:/caminho/do/destino/`: Copia um arquivo para um servidor remoto via SCP.
- `nmap -sS endereco-de-ip`: Realiza uma varredura de TCP SYN para descobrir portas abertas.

### Controle de Processos

- `ps`: Exibe informações sobre processos em execução.
- `kill PID`: Encerra um processo com base no ID do processo.
- `top`: Exibe uma lista interativa de processos em execução.
- `pgrep -u nome-do-usuario`: Lista IDs de processos associados a um usuário.
- `pstree`: Exibe uma árvore de processos.

### Logs e Auditoria

- `last`: Exibe histórico de logins no sistema.
- `journalctl -u nome-do-servico -n 50`: Mostra as últimas 50 entradas no log de um serviço.
- `auditd`: Inicia o serviço de auditoria para rastrear alterações no sistema.

### Segurança e Criptografia

- `gpg --gen-key`: Gera um novo par de chaves GPG.
- `passwd`: Permite a um usuário alterar sua senha.
- `openssl rand -hex 16`: Gera uma senha aleatória de 16 bytes em formato hexadecimal.

### Controle de Usuários e Grupos

- `sudo useradd -m -s /bin/bash nome-do-usuario`: Adiciona um novo usuário com diretório home.
- `sudo passwd -e nome-do-usuario`: Expira a senha de um usuário, forçando a mudança na próxima entrada.
- `sudo groupadd nome-do-grupo`: Adiciona um novo grupo.
- `sudo usermod -aG nome-do-grupo nome-do-usuario`: Adiciona um usuário a um grupo.

### Controle de Recursos e Desempenho

- `top`: Exibe informações sobre o uso de CPU e memória.
- `htop`: Visualizador de processos interativo.
- `ulimit -a`: Exibe e modifica limites de recursos do usuário.
- `nice -n valor comando`: Executa um comando com uma prioridade ajustada.

### Compilação de Código

- `gcc nome-do-arquivo.c -o nome-do-executavel`: Compila código-fonte C.
- `make`: Automatiza a compilação e instalação de programas.
- `valgrind nome-do-programa`: Executa um programa sob a ferramenta de análise de memória Valgrind.

### Backup e Restauração

- `rsync -avz origem/ destino/`: Sincroniza arquivos e diretórios de forma eficiente.
- `tar -cvpzf backup.tar.gz --directory=/ --exclude=backup.tar.gz --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run .`: Cria um backup completo do sistema.

### Docker

- `docker ps`: Lista containers em execução.
- `docker images`: Lista imagens disponíveis localmente.
- `docker-compose up -d`: Inicia serviços definidos no arquivo docker-compose.yml em segundo plano.

### Ferramentas de Desenvolvimento

- `make`: Automatiza a compilação e instalação de programas.
- `valgrind nome-do-programa`: Executa um programa sob a ferramenta de análise de memória Valgrind.
- `gdb nome-do-programa`: Inicia o depurador GNU.

### Compressão e Descompressão

- `tar -cvjf arquivo.tar.bz2 diretorio`: Cria um arquivo tar.bz2 de um diretório.
- `tar -xvjf arquivo.tar.bz2 -C destino`: Extrai um arquivo tar.bz2 para um diretório específico.
- `xz -9 nome-do-arquivo`: Compacta um arquivo com alta compressão usando o formato xz.

### Controle de Pacotes

- `apt show nome-do-pacote`: Exibe informações detalhadas sobre um pacote.
- `apt-get remove nome-do-pacote`: Remove um pacote instalado.
- `dpkg-reconfigure nome-do-pacote`: Reconfigura um pacote instalado.

### Controle de Energia

- `uptime`: Exibe o tempo de atividade do sistema.
- `pmset schedule sleep "MM/DD/YYYY HH:MM:SS"`: Agendamento do modo de suspensão em sistemas macOS.

### Segurança de Rede

- `nmap -sS endereco-de-ip`: Realiza uma varredura de TCP SYN para descobrir portas abertas.
- `sudo iptables -L -n`: Lista regras de firewall no Linux.
- `sudo fail2ban-client status`: Exibe o status do Fail2Ban.

### Ferramentas de Desenvolvimento (Continuação)

- `gcc nome-do-arquivo.c -o nome-do-executavel`: Compila código-fonte C.
- `make clean`: Remove arquivos gerados durante a compilação.
- `ldd nome-do-executavel`: Lista bibliotecas dinâmicas necessárias por um executável.

### Manipulação de Processos

- `pstree`: Exibe uma árvore de processos.
- `pgrep -u nome-do-usuario`: Lista IDs de processos associados a um usuário.
- `kill -s sinal PID`: Envia um sinal específico para um processo.

### Monitoramento de Hardware

- `sensors`: Exibe informações de sensores de temperatura.
- `lspci`: Lista todos os dispositivos PCI conectados.
- `lsusb`: Lista todos os dispositivos USB conectados.

### Ferramentas de Rede Avançadas

- `nload -u K`: Monitora o uso de banda em kilobits.
- `iperf -s`: Inicia um servidor de teste de velocidade de rede.
- `dig nome-do-domínio`: Obtém informações de DNS para um domínio.

### Logs e Auditoria

- `last`: Exibe histórico de logins no sistema.
- `journalctl -u nome-do-servico -n 50`: Mostra as últimas 50 entradas no log de um serviço.
- `auditd`: Inicia o serviço de auditoria para rastrear alterações no sistema.

### Compilação de Código

- `gcc nome-do-arquivo.c -o nome-do-executavel`: Compila código-fonte C.
- `make`: Automatiza a compilação e instalação de programas.
- `valgrind nome-do-programa`: Executa um programa sob a ferramenta de análise de memória Valgrind.

### Controle de Recursos e Desempenho 

- `top`: Exibe informações sobre o uso de CPU e memória.
- `htop`: Visualizador de processos interativo.
- `ulimit -a`: Exibe e modifica limites de recursos do usuário.
- `nice -n valor comando`: Executa um comando com uma prioridade ajustada.
- `iotop`: Monitora o uso de I/O por processos.

### Comandos de Rede 

- `traceroute endereco-de-destino`: Exibe a rota que os pacotes estão seguindo até um destino.
- `ss -tunap`: Mostra informações detalhadas sobre todas as conexões de rede.
- `tcpdump -i interface`: Captura e exibe pacotes transmitidos na rede.

### Controle de Processos 

- `killall -9 nome-do-processo`: Encerra todos os processos com o nome especificado.
- `renice -n prioridade -p PID`: Altera a prioridade de um processo em execução.
- `pmap PID`: Exibe o mapeamento de memória de um processo.

### Controle de Recursos 

- `ulimit -a`: Exibe e modifica limites de recursos do usuário.
- `nice -n valor comando`: Executa um comando com uma prioridade ajustada.
- `ionice -c classe -n prioridade comando`: Define a prioridade de I/O de um comando.

### Ambiente Gráfico

- `xdpyinfo`: Exibe informações sobre o servidor de exibição X.
- `xkill`: Mata um aplicativo clicando em sua janela.
- `gnome-system-monitor`: Interface gráfica para monitorar processos e recursos.

### Configuração do Shell

- `source ~/.bashrc`: Atualiza as configurações do Bash sem reiniciar.
- `echo $SHELL`: Exibe o shell atual em uso.
- `history`: Exibe o histórico de comandos.


Estes são exemplos de comandos Linux e podem ser adaptados conforme necessário para atender às suas necessidades específicas. Sinta-se à vontade para explorar e utilizar os comandos que melhor se adequam ao seu ambiente e objetivos.
