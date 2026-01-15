# 🔑 Guia de Configuração - API Keys do TrueNAS

## Para Usuários Finais

### Como Gerar Sua API Key

1. **Acesse o TrueNAS**
   - Abra o navegador e acesse: `http://172.20.120.23` (ou o IP do seu TrueNAS)
   - Faça login com suas credenciais normais

2. **Navegue até API Keys**
   - Clique no ícone do usuário (canto superior direito)
   - Selecione **"API Keys"** no menu dropdown
   
3. **Gere sua Chave**
   - Clique no botão **"Add"**
   - Nome: `Intranet` (ou qualquer nome que você queira)
   - Clique em **"Add"** novamente para confirmar

4. **⚠️ IMPORTANTE - Copie a Chave**
   - A chave será exibida **APENAS UMA VEZ**
   - Copie toda a chave (começa com `1-`)
   - Cole em um local seguro (gerenciador de senhas recomendado)
   - Se perder a chave, será necessário gerar uma nova

5. **Use na Intranet**
   - Acesse: `http://172.20.120.31:5000`
   - Digite seu **usuário** do TrueNAS
   - Cole sua **API Key** no segundo campo
   - Clique em **Entrar**

### Exemplo de API Key

```
1-Xw0SclrH91uzjOi56qnaEpt9urv9DL2guwboAbstKVipoJ2iBWNR7NlsoJeANgAq
```

### Troubleshooting

**Erro: "API Key inválida ou expirada"**
- Verifique se copiou a chave completa
- Certifique-se de que a chave não foi revogada no TrueNAS
- Gere uma nova chave se necessário

**Erro: "API Key não pertence a este usuário"**
- Você está usando uma API Key de outro usuário
- Cada usuário deve gerar sua própria API Key
- Verifique se está usando o username correto

**Erro: "TrueNAS inacessível"**
- Verifique a conexão de rede
- Confirme que o TrueNAS está online
- Teste acessando a interface web do TrueNAS

## Para Administradores

### Gerenciamento de API Keys

**Visualizar todas as API Keys:**
1. TrueNAS Web UI → **Credentials** → **Local Users**
2. Clique no usuário desejado
3. Selecione **"User API Keys"**

**Revogar uma API Key:**
1. Acesse as API Keys do usuário (conforme acima)
2. Clique no ícone de lixeira ao lado da chave
3. Confirme a revogação

**Segurança:**
- API Keys têm os mesmos privilégios que o usuário
- Não são afetadas por 2FA (se configurado)
- Revogações são imediatas
- Recomenda-se rotação periódica (trocar a cada 90 dias)

### Configuração da Aplicação

A aplicação já está configurada para usar API Keys. O arquivo `.env` contém a API Key admin para operações internas (listar shares, etc).

Usuários individuais usam suas próprias API Keys para login.

## Alternativa: Importar API Keys em Lote

Se você tem muitos usuários, pode criar um script para gerar API Keys:

```bash
# Conectar ao TrueNAS via shell SSH
ssh root@172.20.120.23

# Criar API Key para um usuário
midclt call api_key.create '{"name":"Intranet-joao"}'
```

Isso retornará a API Key que você pode distribuir ao usuário.

## Benefícios das API Keys

✅ **Segurança**: Não expõe senhas de usuários
✅ **Controle**: Pode revogar acessos sem alterar senhas
✅ **Auditoria**: Cada key é rastreável
✅ **Compatibilidade**: Método oficial do TrueNAS Scale 25.10+

---

**Documentação oficial TrueNAS:**
https://www.truenas.com/docs/ scale/25.10/api/
