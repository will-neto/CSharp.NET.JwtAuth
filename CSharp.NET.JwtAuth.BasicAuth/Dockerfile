################ .NET 8 ################

# Imagem inicial - .NET 8 - onde trabalharemos na construção da imagem da APP
# Específica o nome da imagem e o apelido "build-env" dado a ela durante a execução do Dockerfile
# Detalhe: A imagem do .NET 8 inclui todas as ferramentas necessárias para compilar e publicar a aplicação
# É classificada como Fase de Construção, pois é usada por fases em sequencia
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env

# Cria/Define o diretório /app que será utilizado dentro da fase de construção da imagem .NET 8 que será criado. 
# Todas as instruções referente a fase de construção (.net 8) seguintes serão executadas dentro deste diretório /app
# Apesar da imagem ser .NET 8, a imagem do .NET 8 é executada dentro de uma distro Linux.
# TODA IMAGEM DOCKER É EXECUTADA DENTRO DE UM SISTEMA OPERACIONAL
WORKDIR /app

# Layout do comando - COPY [diretorio-dockerfile] [diretorio-workdir]
# Copia todos os arquivos com extensão .csproj dentro da pasta do Dockerfile (já que executaremos o comando neste arquivo no final) para a
# pasta WORKDIR que definimos acima -> /app <- dentro da fase de construção que será criado com imagem .NET 8
# É passado ./ pois é o path relativo a pasta /app que já estaremos situado
COPY *.csproj ./

# Após a cópia do *.csproj para a pasta /app na fase de construção criada, é executado o comando abaixo para instalação dos pacotes que estão declarados no arquivo *.csproj
# Detalhe: O comando .NET é capaz de baixar as dependências de class libraries referenciadas pelo projeto que estamos buildando
RUN dotnet restore


# Copia tudo do diretório onde está localizado o Dockerfile (.) para o diretório de trabalho WORKDIR (/app)
# Também podemos usar "COPY . ." Porém, o uso de "/" deixa mais explícito que estamos apontando pro diretório de trabalho na fase de construção criada
COPY . ./

# Após a cópia do projeto para a fase de construção e com suas dependências baixadas é feito o deploy do projeto
# Usando a configuração (-c) Release e apontando para os arquivos que serão gerados o diretório de output (-o) "out"
RUN dotnet publish -c Release -o out


################ ASP.NET CORE 8 ################

# Imagem do ASP.NET 8: É uma imagem mais leve, otimizada apenas para executar aplicações ASP.NET.
# Não inclui ferramentas de compilação, o que resulta em uma imagem menor e mais seguro para a produção.
FROM mcr.microsoft.com/dotnet/aspnet:8.0

# Cria/Define o diretório /app que será utilizado dentro da imagem ASP.NET 8 que será criado. 
# Todas as instruções referente a essa Fase de Execução seguintes serão executadas dentro deste diretório /app
# FASE DE EXECUÇÃO => ULTIMA CAMADA DO DOCKERFILE
# Apesar da imagem ser .NET 8, a imagem do .NET 8 é executada dentro de uma distro Linux.
# TODA IMAGEM DOCKER É EXECUTADA DENTRO DE UM SISTEMA OPERACIONAL
WORKDIR /app

# Copia a pasta "/app/out" da fase de construção "build-env" criada a partir da imagem do .NET 8 para a pasta "/app" dessa fase de Execução (Asp.Net 8)
COPY --from=build-env /app/out ./

# Define o comando que será executado quando o contêiner for executado
# No caso, executa o comando "dotnet CSharp.NET.JwtAuth.BasicAuth.dll" para o runtime do .NET 8 executar a aplicação
ENTRYPOINT ["dotnet", "CSharp.NET.JwtAuth.BasicAuth.dll"]


