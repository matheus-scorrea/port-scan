# Portas

Ferramenta local para mapear as portas TCP de um único IP e indicar onde a interface web respondeu.

Use no roteador da sua própria rede. Informe um endereço por vez. Faixas de rede, como `192.168.0.0/24`, não são aceitas.

## Requisitos

Python 3.10 ou superior. O app usa apenas a biblioteca padrão.

## Windows

Dê dois cliques em `iniciar.bat` e deixe a janela aberta. Na instalação do Python, marque **Add python.exe to PATH**. O navegador abre em `http://127.0.0.1:8765`.

## Linux

```bash
python3 app.py
```

Abra `http://127.0.0.1:8765`. Feche o terminal para encerrar.

## Uso

1. Informe o IP do roteador.
2. Escolha **Todas**, **Comuns** ou **Faixa**.
3. Clique em **Mapear**.

A página lista as portas abertas e destaca as que respondem como página web, com o link para abrir.
