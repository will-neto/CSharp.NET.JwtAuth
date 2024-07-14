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
                M�todo respons�vel por definir o Schema de autentica��o
                Registra os manipuladores de autentica��o que ser�o utilizados pelos Middlewares de Autentica��o
             
             */

            var appSecretKey = builder.Configuration.GetSection("JwtSettings")["SecretKey"];

            if (string.IsNullOrEmpty(appSecretKey)) throw new ArgumentNullException(nameof(appSecretKey));

            var jwtSymetricKey = new SymmetricSecurityKey(
                         Encoding.UTF8.GetBytes(appSecretKey)        /*  Usar UTF8 se sua chave possuir acentos
                        Encoding.ASCII.GetBytes(appSecretKey)           Caso nao possua, utilizar ASCII         */
                         );

            builder.Services.AddAuthentication(x =>
            {
                // Define o esquema de autentica��o padr�o quando usado o [Authorize] em alguma controller ou action
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;

                /* Quando uma solicita��o n�o autenticada � feita a um recurso que requer, utiliza o esquema especificado
                para entender como deve ser tratado.

                Geralmente para JWT o mesmo esquema JWT � passado tanto para Autentica��o e Challenge. Por�m, � poss�vel especificar como Challenge uma 
                autentica��o via Cookie. Assim, � poss�vel solicitar o redirecionamento para uma p�gina de login com autentica��o via Cookie caso 
                acessem via interface Web. Por�m, isso implicaria na necessidade de incluir a autentica��o via Cookie tamb�m.

                Outro ponto interessante � que se voc� possuir apenas um esquema de autentica��o configurado, n�o � necess�rio atribuir valor ao 
                DefaultChallengeScheme, pois este entender� que deve ser o usado o �nico existente, que no nosso caso, o JWT.

                */
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            // Configura o Asp.Net Core para utilizar o esquema de autentica��o JWT
            // Atrav�s do m�todo � poss�vel incluir as configura��es para valida��o da assinatura JWT

            .AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,    // Se True verifica se a Assinatura do Token foi feita atrav�s da chave-sim�trica (secret) definida pela aplica��o Servidor (IssuerSigningKey)
                    ValidateIssuer = true,              // Se True verifica se o Emissor do Token est� correto
                    ValidateAudience = true,            // Se True verifica se o P�blico (Usu�rio/Entidade) do Token est� Correto


                    // Verifica��o das Claims caso as chaves acima sejam "True"
                    IssuerSigningKey = jwtSymetricKey,  // A chave-sim�trica usada para gera��o dos tokens e vaida��o via ValidateIssuerSigningKey se true
                    ValidAudience = "Publico_Geral",    // O Audience (P�blico) v�lido. Deve ser passado o mesmo Audience gerado no Token
                    ValidIssuer = "CSharp.NET.JwtAuth",  // O Issuer (Emissor) v�lido. Deve ser passado o mesmo Issuer gerado no Token

                    // � poss�vel tamb�m passar uma lista de secret keys, audiences, issuers v�lidas
                    /*
                    IssuerSigningKeys = new[] { new SymmetricSecurityKey(new byte[0]), new SymmetricSecurityKey(new byte[0]) },
                    ValidAudiences = new[] { "audience1", "audience2" },
                    ValidIssuers = new[] { "issuer1", "issuer2" },
                    */
                };
            });
            // Valida��o Customizada da Assinatura caso necessario receber Tokens que nao foram emitidos por outros emissores (issuers)
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
                � usado para adicionar no Middleware de autentica��o � pipeline de requisi��es
                Permite verificar durante a requisi��o as credenciais de autentica��o. O tipo de credencial de autentica��o (seja JWT, Cookies, etc) � determinado
                atrav�s do Esquema (Schema) que � definido na aplica��o. No nosso caso, definiremos o Schema JWT, por�m, � poss�vel a defini��o de m�ltiplos Schemas
                que nos permite decidir se queremos utilizar um, dois ou todos os esquemas de autentica��o numa mesma controller ou action.
             
             */

            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllers();

            app.Run();
        }


    }
}
