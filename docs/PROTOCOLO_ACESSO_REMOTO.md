# Protocolo de Orquestração - Acesso Remoto (Agente Admin)

Este documento descreve como o **Agente Admin** (Windows) deve se comunicar com o Servidor Central para realizar o suporte remoto.

## 1. Conexão WebSocket
O Agente Admin deve se conectar ao hub de sinalização:
`ws://172.20.120.10/socket.io/?EIO=4&transport=websocket`

## 2. Registro de Sessão
Imediatamente após conectar, o Agente Admin deve se registrar:

**Evento:** `register`
**Payload:**
```json
{
  "type": "admin",
  "id": "ID_DO_TECNICO",
  "token": "ADMIN-REMOTE-CTRL-2026"
}
```

## 3. Fluxo de Handshake (WebRTC)

### 3.1. Solicitar Acesso
Para iniciar o suporte em uma máquina específica:

**Evento:** `request_access`
**Payload:**
```json
{
  "target_mac": "00:15:5D:74:85:97",
  "session_type": "control"
}
```
*O servidor notificará o Agente Alvo via evento `incoming_connection`.*

### 3.2. Troca de Sinais (Signaling)
Toda a negociação WebRTC (SDP offer/answer e ICE candidates) deve ser enviada via relay:

**Evento:** `relay_signal`
**Payload:**
```json
{
  "target_mac": "00:15:5D:74:85:97",
  "meta": "sdp", 
  "data": { ... webrtc_info ... }
}
```
*O Agente Admin deve escutar o evento `signal` para receber as respostas do Agente Alvo.*

## 4. Recepção de Stream (Fallback)
Caso o WebRTC (P2P) falhe devido a firewalls agressivos, o Agente Alvo enviará pacotes binários via servidor.

**Escutar Evento:** `stream_data`
**Data:** Chunk binário (bytes) do frame de vídeo/áudio.

## 5. Auditoria REST (Obrigatório)
Antes de abrir a interface de vídeo, o Agente Admin deve registrar o início da sessão para fins de auditoria:

**POST** `/api/v1/remote/sessions/start`
**Headers:** `X-Admin-Token: ADMIN-REMOTE-CTRL-2026`
**Body:**
```json
{
  "mac_address": "...",
  "admin_id": "..."
}
```
*Guarde o `session_id` retornado para encerrar a sessão depois.*

**POST** `/api/v1/remote/sessions/stop`
**Body:** `{"session_id": "..."}`
