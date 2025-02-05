################ .NET 8 ################

# Imagem inicial - .NET 8 - onde trabalharemos na constru��o da imagem da APP
# Espec�fica o nome da imagem e o apelido "build-env" dado a ela durante a execu��o do Dockerfile
# Detalhe: A imagem do .NET 8 inclui todas as ferramentas necess�rias para compilar e publicar a aplica��o
# � classificada como Fase de Constru��o, pois � usada por fases em sequencia
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env

# Cria/Define o diret�rio /app que ser� utilizado dentro da fase de constru��o da imagem .NET 8 que ser� criado. 
# Todas as instru��es referente a fase de constru��o (.net 8) seguintes ser�o executadas dentro deste diret�rio /app
# Apesar da imagem ser .NET 8, a imagem do .NET 8 � executada dentro de uma distro Linux.
# TODA IMAGEM DOCKER � EXECUTADA DENTRO DE UM SISTEMA OPERACIONAL
WORKDIR /app

# Layout do comando - COPY [diretorio-dockerfile] [diretorio-workdir]
# Copia todos os arquivos com extens�o .csproj dentro da pasta do Dockerfile (j� que executaremos o comando neste arquivo no final) para a
# pasta WORKDIR que definimos acima -> /app <- dentro da fase de constru��o que ser� criado com imagem .NET 8
# � passado ./ pois � o path relativo a pasta /app que j� estaremos situado
COPY *.csproj ./

# Ap�s a c�pia do *.csproj para a pasta /app na fase de constru��o criada, � executado o comando abaixo para instala��o dos pacotes que est�o declarados no arquivo *.csproj
# Detalhe: O comando .NET � capaz de baixar as depend�ncias de class libraries referenciadas pelo projeto que estamos buildando
RUN dotnet restore


# Copia tudo do diret�rio onde est� localizado o Dockerfile (.) para o diret�rio de trabalho WORKDIR (/app)
# Tamb�m podemos usar "COPY . ." Por�m, o uso de "/" deixa mais expl�cito que estamos apontando pro diret�rio de trabalho na fase de constru��o criada
COPY . ./

# Ap�s a c�pia do projeto para a fase de constru��o e com suas depend�ncias baixadas � feito o deploy do projeto
# Usando a configura��o (-c) Release e apontando para os arquivos que ser�o gerados o diret�rio de output (-o) "out"
RUN dotnet publish -c Release -o out


################ ASP.NET CORE 8 ################

# Imagem do ASP.NET 8: � uma imagem mais leve, otimizada apenas para executar aplica��es ASP.NET.
# N�o inclui ferramentas de compila��o, o que resulta em uma imagem menor e mais seguro para a produ��o.
FROM mcr.microsoft.com/dotnet/aspnet:8.0

# Cria/Define o diret�rio /app que ser� utilizado dentro da imagem ASP.NET 8 que ser� criado. 
# Todas as instru��es referente a essa Fase de Execu��o seguintes ser�o executadas dentro deste diret�rio /app
# FASE DE EXECU��O => ULTIMA CAMADA DO DOCKERFILE
# Apesar da imagem ser .NET 8, a imagem do .NET 8 � executada dentro de uma distro Linux.
# TODA IMAGEM DOCKER � EXECUTADA DENTRO DE UM SISTEMA OPERACIONAL
WORKDIR /app

# Copia a pasta "/app/out" da fase de constru��o "build-env" criada a partir da imagem do .NET 8 para a pasta "/app" dessa fase de Execu��o (Asp.Net 8)
COPY --from=build-env /app/out ./

# Define o comando que ser� executado quando o cont�iner for executado
# No caso, executa o comando "dotnet CSharp.NET.JwtAuth.BasicAuth.dll" para o runtime do .NET 8 executar a aplica��o
ENTRYPOINT ["dotnet", "CSharp.NET.JwtAuth.BasicAuth.dll"]


