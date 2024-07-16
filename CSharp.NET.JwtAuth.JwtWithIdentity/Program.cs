using CSharp.NET.JwtAuth.JwtWithIdentity.Service;

namespace CSharp.NET.JwtAuth.JwtWithIdentity
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
            // Add services to the container.

            builder.Services.AddScoped<ITokenService, TokenService>();

            builder.Services.AddControllers();

            builder.Services.AddAuthentication().AddBearerToken();
        }

        private static void App(WebApplicationBuilder builder)
        {
            // Configure the HTTP request pipeline.

            var app = builder.Build();

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
