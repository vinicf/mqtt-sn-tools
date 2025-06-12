# Ferramentas MQTT-SN

Baseado no projeto original: [MQTT-SN](https://github.com/njh/mqtt-sn-tools)

Estamos a utilizar este projeto para testar o protocolo MQTT-SN em ambientes com perdas e latência. O cenário de testes envolve dois contentores Docker: um atua como servidor MQTT e o outro como cliente MQTT-SN.

Para simular perdas de pacotes entre os contentores, estamos a usar a ferramenta `tc` em Linux.

## Imagem


## Scripts

### `run_all.sh`

Este script executa testes para todos os níveis de QoS (0, 1 e -1) sob diferentes taxas de perda: 0%, 0.1%, 1%, 5%, 10% e 25%.

Comandos de execução:

```bash
./docker-compose up -d
./run_all.sh
```

---

## Funcionalidades Suportadas

* QoS 0, 1 e -1
* Pings de keep-alive
* Publicação de mensagens retidas
* Publicação de mensagens vazias
* Subscrição por tópico nomeado
* Sessões limpas e persistentes
* Geração manual e automática de client ID
* Visualização do nome do tópico em subscrições com wildcards
* Suporte a IDs de tópicos pré-definidos e nomes de tópicos curtos
* Encapsulamento de forwarder conforme a especificação MQTT-SN v1.2

---

## Limitações

* Tamanho máximo dos pacotes: 255 bytes
* Não suporta Last Will and Testament
* Sem suporte para QoS 2
* Não reenvia automaticamente pacotes perdidos
* Não suporta descoberta automática de gateways

---

## Compilação

Executar `make` num sistema compatível com POSIX.

---

## Publicação

**Uso:**

```bash
mqtt-sn-pub [opções] -t <tópico> -m <mensagem>
```

**Opções principais:**

* `-d` Aumenta o nível de debug (pode ser usado várias vezes)
* `-f <ficheiro>` Envia conteúdo do ficheiro como payload
* `-h <host>` Servidor MQTT-SN (por omissão: `127.0.0.1`)
* `-i <clientid>` ID do cliente (por omissão: `mqtt-sn-tools-<pid>`)
* `-k <segundos>` Keep-alive (por omissão: 10)
* `-p <porto>` Porto de rede (por omissão: 1883)
* `-q <qos>` QoS (0, 1 ou -1; por omissão: 0)
* `-r` Mensagem deve ser retida
* `-s` Lê mensagem completa do STDIN
* `-t <tópico>` Nome do tópico MQTT-SN para publicação
* `-T <idTópico>` ID pré-definido de tópico
* `--fe` Ativa o encapsulamento por forwarder (MQTT-SN v1.2)
* `--wlnid` ID do nó wireless (por omissão: PID do processo)
* `--cport <porto>` Porto de origem dos pacotes (automático se 0 ou não especificado)

---

## Subscrição

**Uso:**

```bash
mqtt-sn-sub [opções] -t <tópico>
```

**Opções principais:**

* `-1` Sai após receber uma única mensagem
* `-c` Desativa sessão limpa (mantém subscrições e mensagens pendentes após desconexão)
* `-d` Aumenta o nível de debug
* `-h <host>` Servidor MQTT-SN (por omissão: `127.0.0.1`)
* `-i <clientid>` ID do cliente (por omissão: `mqtt-sn-tools-<pid>`)
* `-k <segundos>` Keep-alive (por omissão: 10)
* `-e <segundos>` Tempo de espera ao desligar (por omissão: 0)
* `-p <porto>` Porto de rede (por omissão: 1883)
* `-q <qos>` QoS para subscrição (0 ou 1; por omissão: 0)
* `-t <tópico>` Nome do tópico a subscrever (pode repetir-se)
* `-T <idTópico>` ID pré-definido de tópico (pode repetir-se)
* `--fe` Ativa o encapsulamento por forwarder
* `--wlnid` ID do nó wireless (por omissão: PID do processo)
* `-v` Mostra mensagens com nome do tópico
* `-V` Mostra mensagens com hora e nome do tópico
* `--cport <porto>` Porto de origem dos pacotes

---

## Captura de Pacotes (Dumping)

Mostra os pacotes MQTT-SN recebidos num porto especificado. Útil para monitorizar mensagens QoS -1.

**Uso:**

```bash
mqtt-sn-dump [opções] -p <porto>
```

**Opções:**

* `-a` Mostra todos os tipos de pacotes
* `-d` Aumenta o nível de debug
* `-p <porto>` Porto de escuta (por omissão: 1883)
* `-v` Mostra mensagens com nome do tópico

---

## Ponte para Porta Série (Serial Bridge)

Permite retransmitir pacotes a partir de um dispositivo remoto via porta série, convertendo-os em pacotes UDP enviados para o broker ou gateway MQTT-SN.

**Uso:**

```bash
mqtt-sn-serial-bridge [opções] <dispositivo>
```

**Opções:**

* `-b <baud>` Taxa de baud (por omissão: 9600)
* `-d` Aumenta o nível de debug
* `-dd` Debug estendido (mostra pacotes em hexadecimal)
* `-h <host>` Servidor MQTT-SN (por omissão: `127.0.0.1`)
* `-p <porto>` Porto de rede (por omissão: 1883)
* `--fe` Ativa encapsulamento por forwarder
* `--cport <porto>` Porto de origem dos pacotes

---

## Licença

MQTT-SN Tools está licenciado sob a [Licença MIT].

[Licença MIT]: http://opensource.org/licenses/MIT

---

Se precisares de integrar esta documentação com imagens, diagramas ou exemplos específicos de comandos de teste com `tc`, também posso ajudar!
