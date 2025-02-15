# Usar uma imagem base do Python
FROM python:3.11-slim

# Definir o diretório de trabalho no container
WORKDIR /app

# Copiar os arquivos necessários para o container
COPY . .

# Instalar as dependências
RUN pip install --no-cache-dir -r requirements.txt

# Comando para iniciar o script
CMD ["python", "repository.py"]