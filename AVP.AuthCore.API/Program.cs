using System.Text;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Localization;
using Microsoft.AspNetCore.Localization;
using Serilog;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.Services;
using AVP.AuthCore.Persistence;
using AVP.AuthCore.Persistence.Entities;
using AVP.AuthCore.Infrastructure.Logging;

namespace AVP.AuthCore.API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Ќастройка Serilog
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(new ConfigurationBuilder()
                    .AddJsonFile("appsettings.json")
                    .Build())
                .Enrich.FromLogContext()
                .CreateLogger();

            try
            {
                Log.Information("Starting up the app...");
                var builder = WebApplication.CreateBuilder(args);

                builder.Host.UseSerilog(); // <-- подключение Serilog

                // Add services to the container.

                builder.Services.AddControllers();
                // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
                builder.Services.AddEndpointsApiExplorer();
                builder.Services.AddSwaggerGen(options =>
                {
                    options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
                    {
                        Name = "Authorization",
                        Type = SecuritySchemeType.Http,
                        Scheme = "Bearer",
                        BearerFormat = "JWT",
                        In = ParameterLocation.Header,
                        Description = "¬ведите токен JWT в формате: Bearer {токен}"
                    });

                    options.AddSecurityRequirement(new OpenApiSecurityRequirement
                    {
                        {
                            new OpenApiSecurityScheme
                            {
                                Reference = new OpenApiReference
                                {
                                    Type = ReferenceType.SecurityScheme,
                                    Id = "Bearer"
                                }
                            },
                            Array.Empty<string>()
                        }
                    });
                });

                builder.Services.AddAuthorization();
                builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            // указывает, будет ли валидироватьс€ издатель при валидации токена
                            ValidateIssuer = true,
                            // строка, представл€юща€ издател€
                            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
                            // будет ли валидироватьс€ потребитель токена
                            ValidateAudience = true,
                            // установка потребител€ токена
                            ValidAudience = builder.Configuration["JwtSettings:Audience"],
                            // будет ли валидироватьс€ врем€ существовани€
                            ValidateLifetime = true,
                            // валидаци€ ключа безопасности
                            ValidateIssuerSigningKey = true,
                            // установка ключа безопасности
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Key"]))
                        };
                    });

                builder.Services.AddLocalization(options => options.ResourcesPath = string.Empty);

                // конфигураци€ Ѕƒ
                builder.Services.AddDbContext<AuthDbContext>(options =>
                    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

                builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                    .AddEntityFrameworkStores<AuthDbContext>()
                    .AddDefaultTokenProviders();

                // Register IAuthService with its implementation
                builder.Services.AddScoped<IAuthService, AuthService>();
                builder.Services.AddScoped<ITokenService, TokenService>();

                // Ќастраиваем локализацию дл€ использовани€ ресурсов из другого проекта
                builder.Services.AddSingleton<IStringLocalizerFactory, ResourceManagerStringLocalizerFactory>();
                builder.Services.AddSingleton<IStringLocalizer>(provider =>
                {
                    var factory = provider.GetRequiredService<IStringLocalizerFactory>();
                    return factory.Create("ErrorMessages", "AVP.AuthCore.Application");
                });

                var app = builder.Build();

                var supportedCultures = new[]
                {
                    new CultureInfo("en"),
                    new CultureInfo("ru")
                };
                app.UseRequestLocalization(new RequestLocalizationOptions
                {
                    DefaultRequestCulture = new RequestCulture("en"),
                    SupportedCultures = supportedCultures,
                    SupportedUICultures = supportedCultures
                });

                // Configure the HTTP request pipeline.
                if (app.Environment.IsDevelopment())
                {
                    app.UseSwagger();
                    app.UseSwaggerUI();
                }

                app.UseHttpsRedirection();

                // добавл€ем middleware дл€ логировани€ исключений
                app.UseMiddleware<ExceptionLoggingMiddleware>();
                // добавл€ет логирование HTTP-запросов
                app.UseSerilogRequestLogging();

                app.UseAuthentication();
                app.UseAuthorization();

                app.MapControllers();

                app.Run();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Application start-up failed");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }
    }
}
