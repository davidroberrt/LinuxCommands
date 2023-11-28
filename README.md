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

## Gerenciamento de Pacotes e Software

- `apt-get update`: Atualiza a lista de pacotes disponíveis.
- `apt-get upgrade`: Atualiza os pacotes instalados.
- `apt-get install nome-do-pacote`: Instala um novo pacote.
- `apt-get remove nome-do-pacote`: Remove um pacote instalado.
- `dpkg -i nome-do-pacote.deb`: Instala um pacote DEB.
- `dpkg -l`: Lista todos os pacotes instalados.
- `apt search termo-de-busca`: Procura por pacotes disponíveis.

## Sistemas de Arquivos e Diretórios

- `ls`: Lista arquivos e diretórios.
- `cd nome-do-diretorio`: Muda para um diretório específico.
- `cp origem destino`: Copia arquivos e diretórios.
- `mv origem destino`: Move ou renomeia arquivos e diretórios.
- `rm nome-do-arquivo`: Remove um arquivo.
- `mkdir nome-do-diretorio`: Cria um novo diretório.
- `du -sh /caminho/do/diretorio`: Exibe o tamanho total de um diretório.

## Rede e Conectividade

- `ifconfig`: Exibe informações sobre interfaces de rede.
- `ping endereco-de-destino`: Envia pacotes ICMP para testar a conectividade.
- `traceroute endereco-de-destino`: Exibe a rota dos pacotes até um destino.
- `ss -tunap`: Mostra informações detalhadas sobre todas as conexões de rede.
- `ssh usuario@host`: Conecta-se a um servidor remoto via SSH.
- `scp arquivo.txt usuario@host:/caminho/do/destino/`: Copia um arquivo para um servidor remoto via SCP.
- `nmap -sS endereco-de-ip`: Realiza uma varredura de TCP SYN para descobrir portas abertas.

## Controle de Processos

- `ps`: Exibe informações sobre processos em execução.
- `kill PID`: Encerra um processo com base no ID do processo.
- `top`: Exibe uma lista interativa de processos em execução.
- `pgrep -u nome-do-usuario`: Lista IDs de processos associados a um usuário.
- `pstree`: Exibe uma árvore de processos.

## Logs e Auditoria

- `last`: Exibe histórico de logins no sistema.
- `journalctl -u nome-do-servico -n 50`: Mostra as últimas 50 entradas no log de um serviço.
- `auditd`: Inicia o serviço de auditoria para rastrear alterações no sistema.

## Segurança e Criptografia

- `gpg --gen-key`: Gera um novo par de chaves GPG.
- `passwd`: Permite a um usuário alterar sua senha.
- `openssl rand -hex 16`: Gera uma senha aleatória de 16 bytes em formato hexadecimal.

## Controle de Usuários e Grupos

- `sudo useradd -m -s /bin/bash nome-do-usuario`: Adiciona um novo usuário com diretório home.
- `sudo passwd -e nome-do-usuario`: Expira a senha de um usuário, forçando a mudança na próxima entrada.
- `sudo groupadd nome-do-grupo`: Adiciona um novo grupo.
- `sudo usermod -aG nome-do-grupo nome-do-usuario`: Adiciona um usuário a um grupo.

## Controle de Recursos e Desempenho

- `top`: Exibe informações sobre o uso de CPU e memória.
- `htop`: Visualizador de processos interativo.
- `ulimit -a`: Exibe e modifica limites de recursos do usuário.
- `nice -n valor comando`: Executa um comando com uma prioridade ajustada.
- `iotop`: Monitora o uso de I/O por processos.

## Compilação de Código

- `gcc nome-do-arquivo.c -o nome-do-executavel`: Compila código-fonte C.
- `make`: Automatiza a compilação e instalação de programas.
- `valgrind nome-do-programa`: Executa um programa sob a ferramenta de análise de memória Valgrind.

## Backup e Restauração

- `rsync -avz origem/ destino/`: Sincroniza arquivos e diretórios de forma eficiente.
- `tar -cvpzf backup.tar.gz --directory=/ --exclude=backup.tar.gz --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run .`: Cria
