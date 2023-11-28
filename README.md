# Comandos Básicos do Linux (Ubuntu)

## Navegação no Sistema de Arquivos

- `pwd`: Exibe o diretório de trabalho atual.
  
- `ls`: Lista os arquivos no diretório atual.
  - `ls -l`: Lista detalhes dos arquivos.
  - `ls -a`: Mostra arquivos ocultos.
  - `ls -lh`: Lista detalhes legíveis por humanos.

- `cd nome-do-diretorio`: Navega para um diretório específico.

- `mkdir nome-do-diretorio`: Cria um novo diretório.

- `cp origem destino`: Copia arquivos ou diretórios.
  - `cp -r diretorio/ destino/`: Copia recursivamente.

- `mv origem destino`: Move ou renomeia arquivos ou diretórios.

- `rm arquivo`: Remove um arquivo.
  - `rm -r diretorio/`: Remove um diretório.

## Manipulação de Arquivos e Texto

- `cat nome-do-arquivo`: Exibe o conteúdo de um arquivo.
  
- `nano nome-do-arquivo`: Abre o editor de texto Nano.

- `echo "Texto" > nome-do-arquivo`: Cria um arquivo com o texto especificado.

- `grep "padrao" nome-do-arquivo`: Procura por padrões em um arquivo.

- `chmod permissões nome-do-arquivo`: Altera permissões de um arquivo.
  - Exemplo: `chmod +x script.sh` (concede permissão de execução).

## Gerenciamento de Pacotes

- `sudo apt update`: Atualiza a lista de pacotes disponíveis.

- `sudo apt upgrade`: Atualiza todos os pacotes instalados.

- `sudo apt install nome-do-pacote`: Instala um novo pacote.

- `sudo apt remove nome-do-pacote`: Remove um pacote.

## Processos e Sistema

- `ps`: Lista processos em execução.
  - `ps aux`: Mostra detalhes estendidos dos processos.

- `kill PID`: Encerra um processo pelo ID do processo.

- `df -h`: Exibe o espaço em disco disponível.

- `free -h`: Mostra a quantidade de memória livre e utilizada.

## Rede

- `ifconfig`: Exibe informações de configuração de rede.
  
- `ping endereco-de-ip`: Envia pacotes para testar a conectividade.

- `netstat -tuln`: Mostra portas abertas.

- `sudo lshw -C network`: Lista informações detalhadas sobre interfaces de rede.

Lembre-se de que alguns comandos podem exigir privilégios de superusuário (`sudo`).

## Visualização e Edição de Arquivos de Texto

- `cat nome-do-arquivo`: Exibe o conteúdo completo de um arquivo.

- `head nome-do-arquivo`: Exibe as primeiras linhas de um arquivo.

- `tail nome-do-arquivo`: Exibe as últimas linhas de um arquivo.

- `less nome-do-arquivo`: Permite rolar e navegar por um arquivo.

- `nano nome-do-arquivo`: Abre o editor de texto Nano para edição.

## Redes e Conectividade

- `ifconfig`: Exibe informações sobre interfaces de rede.

- `traceroute endereco-de-destino`: Mostra o caminho que os pacotes estão seguindo até um destino.

- `nslookup nome-de-dominio`: Realiza uma pesquisa de DNS.

- `wget URL`: Baixa um arquivo da Internet.

## Gerenciamento de Usuários e Permissões

- `sudo adduser nome-do-usuario`: Adiciona um novo usuário.

- `sudo usermod -aG grupo nome-do-usuario`: Adiciona um usuário a um grupo.

- `sudo passwd nome-do-usuario`: Define ou altera a senha de um usuário.

- `chmod permissões nome-do-arquivo`: Altera permissões de arquivo.
  - Exemplo: `chmod 755 script.sh` (concede permissões de leitura, escrita e execução para o proprietário e permissões de leitura e execução para outros).

## Logs e Monitoramento

- `tail -f /var/log/nome-do-log`: Monitora em tempo real um arquivo de log.

- `htop`: Exibe uma visão interativa do uso de recursos do sistema.

- `journalctl`: Exibe mensagens do sistema e logs do sistema.

- `uptime`: Mostra quanto tempo o sistema está ativo.

## Comandos Avançados

- `find diretorio -name "padrao"`: Procura por arquivos ou diretórios com base em um padrão.

- `grep -r "padrao" diretorio`: Procura recursivamente por um padrão em arquivos.

- `sed 's/antigo/novo/g' arquivo`: Substitui todas as ocorrências de uma string em um arquivo.

## Arquivos Compactados e Descompactados

- `tar -czvf arquivo.tar.gz diretorio`: Cria um arquivo tar.gz de um diretório.

- `tar -xzvf arquivo.tar.gz`: Extrai um arquivo tar.gz.

- `zip -r arquivo.zip diretorio`: Cria um arquivo zip de um diretório.

- `unzip arquivo.zip`: Extrai um arquivo zip.

## Controle de Processos

- `ps aux | grep processo`: Exibe informações detalhadas sobre um processo específico.

- `kill -9 PID`: Força a terminação de um processo.

- `top`: Exibe uma lista interativa de processos em execução.

## Variáveis de Ambiente

- `echo $NOME_DA_VARIAVEL`: Exibe o valor de uma variável de ambiente.

- `export NOME_DA_VARIAVEL="valor"`: Define ou altera o valor de uma variável de ambiente.

## Monitoramento de Recursos

- `df -h`: Exibe o espaço em disco disponível.

- `du -h`: Mostra o espaço utilizado por cada diretório.

- `free -h`: Exibe informações sobre o uso da memória.

## Trabalhando com Serviços

- `sudo systemctl start nome-do-servico`: Inicia um serviço.

- `sudo systemctl stop nome-do-servico`: Para um serviço.

- `sudo systemctl restart nome-do-servico`: Reinicia um serviço.

## Executando Comandos Agendados

- `crontab -e`: Edita a tabela cron para agendar tarefas.

- Exemplo de linha cron: `30 2 * * * comando` (executa o comando todos os dias às 2h30).

# Comandos Linux (Ubuntu) - Continuação

## Controle de Usuários e Grupos

- `whoami`: Exibe o nome do usuário atual.

- `id nome-do-usuario`: Mostra informações sobre um usuário, incluindo grupos aos quais pertence.

- `groups`: Exibe os grupos aos quais o usuário atual pertence.

- `sudo deluser nome-do-usuario`: Remove um usuário.

- `sudo delgroup nome-do-grupo`: Remove um grupo.

## Informações do Sistema

- `uname -a`: Exibe informações do kernel e do sistema operacional.

- `lsb_release -a`: Mostra informações sobre a distribuição Linux.

- `hostname`: Exibe o nome do host do sistema.

## Manipulação de Processos

- `pgrep nome-do-processo`: Retorna IDs de processo com base no nome.

- `pkill nome-do-processo`: Encerra processos com base no nome.

- `nohup comando &`: Executa um comando que continua a rodar mesmo após o logout.

## Manipulação de Redes

- `netstat -tulpn`: Lista todas as portas abertas e os processos associados.

- `ip addr show`: Mostra informações detalhadas sobre interfaces de rede.

- `iptables`: Ferramenta para configuração do firewall.

## Trabalhando com Diretórios

- `rmdir nome-do-diretorio`: Remove um diretório vazio.

- `tree nome-do-diretorio`: Exibe a estrutura de diretórios em forma de árvore.

- `find . -type f -name "padrao"`: Procura por arquivos com base em um padrão a partir do diretório atual.

## Monitoramento de Recursos

- `iotop`: Exibe informações sobre a utilização de I/O por processos.

- `vmstat`: Exibe informações sobre a atividade do sistema, incluindo memória virtual.

- `sar`: Coleta, relata e salva informações sobre a atividade do sistema.

## Backup e Restauração

- `tar -cvzf backup.tar.gz diretorio`: Cria um arquivo de backup compactado.

- `tar -xvzf backup.tar.gz -C destino`: Restaura um backup compactado.

- `rsync -av origem/ destino/`: Sincroniza arquivos entre origem e destino.

## Manipulação de Texto

- `awk 'padrao {ação}' nome-do-arquivo`: Processa e filtra texto com base em padrões.

- `sed 's/antigo/novo/g' nome-do-arquivo`: Substitui todas as ocorrências de uma string em um arquivo.

- `tr 'A-Z' 'a-z' < nome-do-arquivo`: Converte texto para minúsculas.

## Verificação de Integridade de Arquivos

- `md5sum nome-do-arquivo`: Gera um hash MD5 para verificar a integridade de um arquivo.

- `sha256sum nome-do-arquivo`: Gera um hash SHA-256 para verificar a integridade de um arquivo.

## Informações de Hardware

- `lshw`: Exibe informações detalhadas sobre o hardware do sistema.

- `lscpu`: Exibe informações sobre a CPU.

- `lsblk`: Lista informações sobre dispositivos de bloco.

## Compressão e Descompressão

- `gzip nome-do-arquivo`: Comprime um arquivo e renomeia para "nome-do-arquivo.gz".

- `gunzip nome-do-arquivo.gz`: Descomprime um arquivo gzip.

## Agendamento de Tarefas

- `at`: Executa comandos em um momento específico no futuro.
  - Exemplo: `echo "comando" | at 2:30 PM`

- `cron`: Programador de tarefas agendadas.
  - Edite a tabela cron com `crontab -e`.

## Processamento de Texto e Arquivos

- `sort nome-do-arquivo`: Ordena linhas de um arquivo.

- `uniq nome-do-arquivo`: Remove linhas duplicadas de um arquivo.

- `cut -d delimitador -f campos nome-do-arquivo`: Corta campos específicos de um arquivo delimitado.

- `wc nome-do-arquivo`: Conta linhas, palavras e caracteres em um arquivo.

## Controle de Processos

- `jobs`: Lista processos em segundo plano.

- `fg %numero-do-trabalho`: Traz um trabalho para o primeiro plano.

- `bg %numero-do-trabalho`: Envia um trabalho para segundo plano.

## Monitoramento de Redes

- `iftop`: Exibe o uso de banda em tempo real.

- `nload`: Mostra a largura de banda utilizada por interface.

- `tcpdump`: Captura e exibe pacotes transmitidos na rede.

## Trabalhando com Pacotes

- `dpkg -i nome-do-pacote.deb`: Instala um pacote DEB.

- `dpkg -l`: Lista todos os pacotes instalados.

- `apt search termo-de-busca`: Procura por pacotes disponíveis para instalação.

## Segurança e Criptografia

- `gpg --gen-key`: Gera um novo par de chaves GPG.

- `gpg --encrypt -r destinatario nome-do-arquivo`: Criptografa um arquivo para um destinatário.

- `gpg --decrypt nome-do-arquivo.gpg`: Descriptografa um arquivo criptografado.

- `passwd`: Permite a um usuário alterar sua senha.

- `openssl rand -hex 16`: Gera uma senha aleatória de 16 bytes em formato hexadecimal.

## Verificação de Integridade e Assinaturas

- `sha1sum nome-do-arquivo`: Gera um hash SHA-1 para verificar a integridade de um arquivo.

- `md5sum -c nome-do-arquivo.md5`: Verifica um arquivo com base em um hash MD5 fornecido.

- `gpg --verify nome-do-arquivo.asc nome-do-arquivo`: Verifica a assinatura GPG de um arquivo.

## Personalização do Ambiente Shell

- `.bashrc` e `.bash_profile`: Arquivos de configuração do Bash para personalizar o ambiente.

- `alias nome-do-alias='comando'`: Cria um alias para um comando.

- `export VARIAVEL="valor"`: Define uma variável de ambiente temporária.

## Manipulação de Imagens

- `convert nome-da-imagem.jpg nome-da-imagem.png`: Converte formatos de imagem com o ImageMagick.

- `mogrify -resize 800x600 nome-da-imagem.jpg`: Redimensiona uma imagem.

- `exiftool nome-da-imagem.jpg`: Exibe informações Exif de uma imagem.

## Trabalhando com Arquivos Compactados

- `xz nome-do-arquivo`: Compacta um arquivo usando o formato xz.

- `xz -d nome-do-arquivo.xz`: Descompacta um arquivo compactado com xz.

- `tar -cvJf arquivo.tar.xz diretorio`: Cria um arquivo tar.xz de um diretório.

## Controle de Processos Avançado

- `ps auxf`: Exibe a árvore de processos.

- `killall nome-do-processo`: Encerra todos os processos com o mesmo nome.

- `renice -n valor -p PID`: Altera a prioridade de um processo em execução.

## Conexões de Rede

- `ss`: Exibe estatísticas de socket, como conexões TCP.

- `lsof -i`: Lista todos os arquivos abertos relacionados a conexões de rede.

- `arp`: Exibe e manipula tabelas ARP.

## Trabalhando com Data e Hora

- `date`: Exibe a data e hora atuais.

- `cal`: Exibe um calendário do mês.

- `timedatectl`: Mostra e configura a configuração de data e hora do sistema.

## Sincronização de Arquivos e Diretórios

- `rsync -avz origem/ destino/`: Sincroniza arquivos e diretórios de forma eficiente.

- `rsync -avz --delete origem/ destino/`: Sincroniza e exclui arquivos no destino que não existem na origem.

## Trabalhando com Permissões Estendidas

- `getfacl nome-do-arquivo`: Exibe as permissões estendidas (ACL) de um arquivo.

- `setfacl -m u:nome-do-usuario:rw nome-do-arquivo`: Adiciona permissões específicas para um usuário.

## Configuração de Rede Avançada

- `ip route show`: Exibe a tabela de roteamento.

- `ip link set nome-da-interface up/down`: Ativa ou desativa uma interface de rede.

- `nmcli device wifi list`: Lista redes Wi-Fi disponíveis.

## Manipulação de Strings e Texto

- `sed -i 's/antigo/novo/g' nome-do-arquivo`: Substitui todas as ocorrências de uma string em um arquivo, editando-o in-place.

- `awk '{print $1}' nome-do-arquivo`: Exibe a primeira coluna de um arquivo de texto.

## Controle de Volume e Áudio

- `alsamixer`: Interface interativa para controlar configurações de áudio no ALSA.

- `pactl list sinks`: Lista dispositivos de saída de áudio.

- `amixer set Master 50%`: Define o volume do mestre para 50%.

## Trabalhando com Variáveis de Ambiente Globalmente

- Edite o arquivo `/etc/environment` para definir variáveis de ambiente globalmente.

- Exemplo: `NOME_DA_VARIAVEL="valor"`

# Comandos Linux (Ubuntu) - Continuação

## Manipulação de Partições e Discos

- `fdisk -l`: Lista as partições no sistema.

- `parted /dev/sdX`: Entra no modo interativo do Parted para gerenciar partições.

- `mkfs -t tipo-de-sistema-de-arquivos /dev/sdXY`: Formata uma partição com um sistema de arquivos específico.

- `mount /dev/sdXY /caminho/do/ponto-de-montagem`: Monta uma partição em um diretório específico.

## Backup e Restauração do Sistema

- `tar -cvpzf backup.tar.gz --directory=/ --exclude=backup.tar.gz --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run .`: Cria um backup completo do sistema, excluindo diretórios desnecessários.

- `dd if=/dev/sdX of=imagem-do-disco.img bs=4M`: Cria uma imagem do disco.

- `dd if=imagem-do-disco.img of=/dev/sdX bs=4M`: Restaura uma imagem do disco.

## Monitoramento e Análise de Desempenho

- `iotop`: Monitora o uso de I/O por processos.

- `strace comando`: Rastreia a execução de sistema de um comando.

- `perf top`: Exibe uma visão geral de eventos de desempenho.

## Configuração do Ambiente Gráfico

- `xrandr`: Configura a resolução e orientação do monitor.

- `gnome-control-center`: Abre o painel de controle do GNOME.

- `xkill`: Mata um aplicativo clicando em sua janela.

## Trabalhando com Logs

- `journalctl -xe`: Exibe mensagens do sistema, útil para diagnósticos.

- `dmesg`: Exibe o buffer do kernel, mostrando mensagens do sistema.

- `logrotate`: Gerencia a rotação de logs no sistema.

## Manipulação de Data e Hora

- `timedatectl set-time 'YYYY-MM-DD HH:MM:SS'`: Define a data e hora do sistema.

- `date -d 'next Friday'`: Exibe a data do próximo sexta-feira.

## Manipulação de Pacotes

- `dpkg-query -l`: Lista todos os pacotes instalados.

- `dpkg -S nome-do-arquivo`: Encontra a origem de um arquivo de pacote instalado.

- `apt list --upgradable`: Lista os pacotes que podem ser atualizados.

## Automação de Tarefas

- `cron`: Agendador de tarefas automatizadas.

- `watch comando`: Executa repetidamente um comando para monitoramento em tempo real.

- `crontab -l`: Exibe a tabela cron do usuário.

## Virtualização

- `virt-manager`: Interface gráfica para gerenciamento de máquinas virtuais.

- `virsh list`: Lista máquinas virtuais em execução.

- `qemu-img create -f qcow2 imagem.qcow2 10G`: Cria uma imagem de disco para máquina virtual.

## Controle de Acesso a Arquivos

- `chmod g+s nome-do-diretorio`: Define a configuração de conjunto-gid em um diretório.

- `chown nome-do-usuario:nome-do-grupo nome-do-arquivo`: Altera o proprietário e grupo de um arquivo.

- `find /caminho -name "padrao" -exec comando {} \;`: Executa um comando em cada arquivo correspondente ao padrão.

## Ajustes de Desempenho

- `sysctl -a`: Exibe e modifica parâmetros do kernel em tempo de execução.

- `nice -n valor comando`: Executa um comando com uma prioridade ajustada.

- `echo 1 > /proc/sys/vm/drop_caches`: Limpa a cache de página do kernel.

## Segurança do Sistema

- `ufw`: Ferramenta de firewall simples para gerenciar iptables.

- `fail2ban-client status`: Exibe o status do Fail2Ban.

- `openssl s_client -connect host:porta`: Verifica informações de certificado SSL.

## Comandos de Rede

- `curl -I URL`: Exibe apenas os cabeçalhos HTTP de uma URL.

- `iptraf-ng`: Monitora o tráfego de rede em tempo real.

- `nmap endereco-de-ip`: Realiza varredura de portas em um host.

## Trabalhando com Pacotes Debian

- `apt-file search nome-do-arquivo`: Encontra pacotes que contêm um arquivo específico.

- `apt-get autoremove`: Remove pacotes órfãos (não utilizados) no sistema.

- `apt-get source nome-do-pacote`: Baixa o código-fonte de um pacote.

## Backup Remoto

- `rsync -avz -e ssh origem/ usuario@host:/caminho/do/destino/`: Sincroniza localmente com um diretório remoto usando SSH.

- `scp nome-do-arquivo usuario@host:/caminho/do/destino/`: Copia um arquivo para um servidor remoto usando SSH.

## Monitoramento de Recursos

- `htop`: Visualizador de processos interativo.

- `nload`: Monitora o uso de largura de banda por interface.

- `atop`: Exibe estatísticas detalhadas sobre recursos do sistema.

## Serviços e Portas

- `sudo netstat -tulpn`: Lista serviços e portas em uso.

- `sudo lsof -i :numero-da-porta`: Mostra o processo que está usando uma porta específica.

- `sudo ufw allow numero-da-porta`: Abre uma porta no firewall UFW.

## Redefinir Senha do Usuário

- `passwd nome-do-usuario`: Permite alterar a senha de um usuário.

- `sudo passwd -e nome-do-usuario`: Desabilita uma conta de usuário após a próxima expiração da senha.

## Controle de Recursos

- `ulimit -a`: Exibe limites de recursos do shell.

- `nice comando`: Executa um comando com uma prioridade ajustada.

- `ionice -c prioridade comando`: Define a prioridade de E/S para um comando.

## Controle de Usuários e Grupos

- `sudo useradd -m -s /bin/bash nome-do-usuario`: Adiciona um novo usuário com diretório home.

- `sudo passwd -e nome-do-usuario`: Expira a senha de um usuário, forçando a mudança na próxima entrada.

- `sudo groupadd nome-do-grupo`: Adiciona um novo grupo.

- `sudo usermod -aG nome-do-grupo nome-do-usuario`: Adiciona um usuário a um grupo.

## Comandos de Texto e Processamento de Dados

- `grep -i "padrao" nome-do-arquivo`: Procura por um padrão no arquivo, ignorando maiúsculas e minúsculas.

- `awk '{print NF}' nome-do-arquivo`: Imprime o número de campos em cada linha de um arquivo.

- `cut -d: -f1 /etc/passwd`: Extrai o primeiro campo de um arquivo de texto usando um delimitador.

## Gerenciamento de Energia

- `sudo shutdown -h now`: Desliga o sistema imediatamente.

- `sudo shutdown -r now`: Reinicia o sistema imediatamente.

- `sudo pm-suspend`: Coloca o sistema em modo de suspensão.

## Configuração de Rede

- `ifup nome-da-interface`: Ativa uma interface de rede.

- `ifdown nome-da-interface`: Desativa uma interface de rede.

- `nmcli connection show`: Lista as conexões de rede.

## Comandos de Sistema

- `uname -r`: Exibe a versão do kernel.

- `lsmod`: Lista os módulos do kernel carregados.

- `dmesg | grep -i erro`: Procura por mensagens de erro no buffer do kernel.

## Sistema de Arquivos

- `du -sh /caminho/do/diretorio`: Exibe o tamanho total de um diretório.

- `df -h`: Mostra o uso de espaço em disco em todas as partições.

- `fdupes -r /caminho/do/diretorio`: Encontra e exibe arquivos duplicados.

## Acesso Remoto

- `ssh usuario@host`: Conecta-se a um servidor remoto via SSH.

- `scp arquivo.txt usuario@host:/caminho/do/destino/`: Copia um arquivo para um servidor remoto via SCP.

- `rsync -avz -e ssh origem/ usuario@host:/caminho/do/destino/`: Sincroniza localmente com um diretório remoto usando SSH.

## Serviços e Processos

- `systemctl status nome-do-servico`: Exibe o status de um serviço.

- `journalctl -u nome-do-servico`: Exibe logs específicos de um serviço.

- `ps -aux | grep processo`: Lista processos com base em um nome.

## Docker

- `docker ps`: Lista containers em execução.

- `docker images`: Lista imagens disponíveis localmente.

- `docker-compose up -d`: Inicia serviços definidos no arquivo docker-compose.yml em segundo plano.

## Git

- `git branch -a`: Lista todas as branches, incluindo remotes.

- `git log --oneline --graph --decorate --all`: Exibe o histórico de commits de forma gráfica.

- `git diff HEAD`: Mostra as alterações não commitadas.

## Comandos de Rede

- `traceroute endereco-de-destino`: Exibe a rota que os pacotes estão seguindo até um destino.

- `ss -tunap`: Mostra informações detalhadas sobre todas as conexões de rede.

- `tcpdump -i interface`: Captura e exibe pacotes transmitidos na rede.

## Controle de Processos

- `killall -9 nome-do-processo`: Encerra todos os processos com o nome especificado.

- `renice -n prioridade -p PID`: Altera a prioridade de um processo em execução.

- `pmap PID`: Exibe o mapeamento de memória de um processo.

## Controle de Recursos

- `ulimit -a`: Exibe e modifica limites de recursos do usuário.

- `nice -n valor comando`: Executa um comando com uma prioridade ajustada.

- `ionice -c classe -n prioridade comando`: Define a prioridade de I/O de um comando.

## Ambiente Gráfico

- `xdpyinfo`: Exibe informações sobre o servidor de exibição X.

- `xkill`: Mata um aplicativo clicando em sua janela.

- `gnome-system-monitor`: Interface gráfica para monitorar processos e recursos.

## Configuração do Shell

- `source ~/.bashrc`: Atualiza as configurações do Bash sem reiniciar.

- `echo $SHELL`: Exibe o shell atual em uso.

- `history`: Exibe o histórico de comandos.

# Comandos Linux (Ubuntu) - Continuação

## Compressão e Descompressão

- `tar -cvjf arquivo.tar.bz2 diretorio`: Cria um arquivo tar.bz2 de um diretório.

- `tar -xvjf arquivo.tar.bz2 -C destino`: Extrai um arquivo tar.bz2 para um diretório específico.

- `xz -9 nome-do-arquivo`: Compacta um arquivo com alta compressão usando o formato xz.

## Controle de Pacotes

- `apt show nome-do-pacote`: Exibe informações detalhadas sobre um pacote.

- `apt-get remove nome-do-pacote`: Remove um pacote instalado.

- `dpkg-reconfigure nome-do-pacote`: Reconfigura um pacote instalado.

## Controle de Energia

- `uptime`: Exibe o tempo de atividade do sistema.

- `pmset schedule sleep "MM/DD/YYYY HH:MM:SS"`: Agendamento do modo de suspensão em sistemas macOS.

## Segurança de Rede

- `nmap -sS endereco-de-ip`: Realiza uma varredura de TCP SYN para descobrir portas abertas.

- `sudo iptables -L -n`: Lista regras de firewall no Linux.

- `sudo fail2ban-client status`: Exibe o status do Fail2Ban.

## Ferramentas de Desenvolvimento

- `make`: Automatiza a compilação e instalação de programas.

- `valgrind nome-do-programa`: Executa um programa sob a ferramenta de análise de memória Valgrind.

- `gdb nome-do-programa`: Inicia o depurador GNU.


## Logs e Auditoria

- `last`: Exibe histórico de logins no sistema.

- `journalctl -u nome-do-servico -n 50`: Mostra as últimas 50 entradas no log de um serviço.

- `auditd`: Inicia o serviço de auditoria para rastrear alterações no sistema.

## Compilação de Código

- `gcc nome-do-arquivo.c -o nome-do-executavel`: Compila código-fonte C.

- `make clean`: Remove arquivos gerados durante a compilação.

- `ldd nome-do-executavel`: Lista bibliotecas dinâmicas necessárias por um executável.

## Manipulação de Processos

- `pstree`: Exibe uma árvore de processos.

- `pgrep -u nome-do-usuario`: Lista IDs de processos associados a um usuário.

- `kill -s sinal PID`: Envia um sinal específico para um processo.

## Monitoramento de Hardware

- `sensors`: Exibe informações de sensores de temperatura.

- `lspci`: Lista todos os dispositivos PCI conectados.

- `lsusb`: Lista todos os dispositivos USB conectados.

## Ferramentas de Rede Avançadas

- `nload -u K`: Monitora o uso de banda em kilobits.

- `iperf -s`: Inicia um servidor de teste de velocidade de rede.

- `dig nome-do-domínio`: Obtém informações de DNS para um domínio.

