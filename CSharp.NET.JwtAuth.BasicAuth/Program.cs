using CSharp.NET.JwtAuth.BasicAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace CSharp.NET.JwtAuth.BasicAuth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            Services(builder);

            App(builder);

        }

        private static void Services(WebApplicationBuilder builder)
        {
            // Inclusao do servico Token Service por DI
            builder.Services.AddScoped<ITokenService, TokenService>();

            // Inclusao de servicos basicos para funcionamento da API

            builder.Services.AddControllers();

            // Inclusao do Cors (para permitir chamada aos Endpoints da API atraves de outros dominios)
            builder.Services.AddCors();

            /*
                AddAuthetication
                Método responsável por definir o Schema de autenticação
                Registra os manipuladores de autenticação que serão utilizados pelos Middlewares de Autenticação
             
             */

            var appSecretKey = builder.Configuration.GetSection("JwtSettings")["SecretKey"];

            if (string.IsNullOrEmpty(appSecretKey)) throw new ArgumentNullException(nameof(appSecretKey));

            var jwtSymetricKey = new SymmetricSecurityKey(
                         Encoding.UTF8.GetBytes(appSecretKey)        /*  Usar UTF8 se sua chave possuir acentos
                        Encoding.ASCII.GetBytes(appSecretKey)           Caso nao possua, utilizar ASCII         */
                         );

            builder.Services.AddAuthentication(x =>
            {
                // Define o esquema de autenticação padrão quando usado o [Authorize] em alguma controller ou action
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;

                /* Quando uma solicitação não autenticada é feita a um recurso que requer, utiliza o esquema especificado
                para entender como deve ser tratado.

                Geralmente para JWT o mesmo esquema JWT é passado tanto para Autenticação e Challenge. Porém, é possível especificar como Challenge uma 
                autenticação via Cookie. Assim, é possível solicitar o redirecionamento para uma página de login com autenticação via Cookie caso 
                acessem via interface Web. Porém, isso implicaria na necessidade de incluir a autenticação via Cookie também.

                Outro ponto interessante é que se você possuir apenas um esquema de autenticação configurado, não é necessário atribuir valor ao 
                DefaultChallengeScheme, pois este entenderá que deve ser o usado o único existente, que no nosso caso, o JWT.

                */
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            // Configura o Asp.Net Core para utilizar o esquema de autenticação JWT
            // Através do método é possível incluir as configurações para validação da assinatura JWT

            .AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,    // Se True verifica se a Assinatura do Token foi feita através da chave-simétrica (secret) definida pela aplicação Servidor (IssuerSigningKey)
                    ValidateIssuer = true,              // Se True verifica se o Emissor do Token está correto
                    ValidateAudience = true,            // Se True verifica se o Público (Usuário/Entidade) do Token está Correto


                    // Verificação das Claims caso as chaves acima sejam "True"
                    IssuerSigningKey = jwtSymetricKey,  // A chave-simétrica usada para geração dos tokens e vaidação via ValidateIssuerSigningKey se true
                    ValidAudience = "Publico_Geral",    // O Audience (Público) válido. Deve ser passado o mesmo Audience gerado no Token
                    ValidIssuer = "CSharp.NET.JwtAuth",  // O Issuer (Emissor) válido. Deve ser passado o mesmo Issuer gerado no Token

                    // É possível também passar uma lista de secret keys, audiences, issuers válidas
                    /*
                    IssuerSigningKeys = new[] { new SymmetricSecurityKey(new byte[0]), new SymmetricSecurityKey(new byte[0]) },
                    ValidAudiences = new[] { "audience1", "audience2" },
                    ValidIssuers = new[] { "issuer1", "issuer2" },
                    */
                };
            });
            // Validação Customizada da Assinatura caso necessario receber Tokens que nao foram emitidos por outros emissores (issuers)
            //.AddJwtBearer(x => {
            //     x.RequireHttpsMetadata = false;
            //     x.TokenValidationParameters = new TokenValidationParameters
            //     {
            //         ValidateIssuer = false,
            //         ValidateAudience = false,
            //         ValidateIssuerSigningKey = false,
            //          // Validador Customizado caso necessidade de validacao customizada
            //         SignatureValidator = (token, parameters) =>
            //         {
            //             var jwt = new JsonWebToken(token);
                        
            //             if (parameters.ValidateIssuer && parameters.ValidIssuer != jwt.Issuer)
            //                 return null;

            //              // Validar Audience e IssuerSigningKey caso necessario

            //             return jwt;
            //         },
            //     };
            //});

        }

        private static void App(WebApplicationBuilder builder)
        {
            var app = builder.Build();

            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();

            /*
                UseAuthentication
                É usado para adicionar no Middleware de autenticação à pipeline de requisições
                Permite verificar durante a requisição as credenciais de autenticação. O tipo de credencial de autenticação (seja JWT, Cookies, etc) é determinado
                através do Esquema (Schema) que é definido na aplicação. No nosso caso, definiremos o Schema JWT, porém, é possível a definição de múltiplos Schemas
                que nos permite decidir se queremos utilizar um, dois ou todos os esquemas de autenticação numa mesma controller ou action.
             
             */

            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllers();

            app.Run();
        }


    }
}
