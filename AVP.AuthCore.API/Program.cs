using System.Text;
using System.Globalization;
using AVP.AuthCore.Application.DTOs;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Localization;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using FluentValidation;
using FluentValidation.AspNetCore;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.Services;
using AVP.AuthCore.Application.Validation;
using AVP.AuthCore.Persistence;
using AVP.AuthCore.Persistence.Entities;
using AVP.AuthCore.Infrastructure.Logging;
using AVP.AuthCore.Application.Common.Settings;
using Microsoft.Extensions.Options;
using AVP.AuthCore.Infrastructure.HostedServices;

namespace AVP.AuthCore.API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Инициализация логирования до запуска приложения
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

                // Перезагрузка данных при изменении файла настроек
                builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .AddEnvironmentVariables();

                builder.Host.UseSerilog(); // Подключение Serilog

                // Регистрация сервисов
                builder.Services
                    .AddOptions<JwtSettings>()
                    .Bind(builder.Configuration.GetSection("JwtSettings"))
                    .ValidateDataAnnotations()
                    .ValidateOnStart();

                builder.Services
                    .AddOptions<IdentitySettings>()
                    .Bind(builder.Configuration.GetSection("Identity"))
                    .ValidateDataAnnotations()
                    .ValidateOnStart();

                // Регистрируем настройки как сервисы
                builder.Services.AddScoped<JwtSettings>(sp => sp.GetRequiredService<IOptions<JwtSettings>>().Value);
                builder.Services.AddScoped<IdentitySettings>(sp => sp.GetRequiredService<IOptions<IdentitySettings>>().Value);

                // Регистрируем сервисы
                builder.Services.AddScoped<IAuthService, AuthService>();
                builder.Services.AddScoped<ITokenService, TokenService>();

                builder.Services.AddControllers();
                builder.Services.AddLocalization(options => options.ResourcesPath = string.Empty);

                // Настройка FluentValidation
                ValidatorOptions.Global.LanguageManager = new FluentValidation.Resources.LanguageManager
                {
                    Culture = new CultureInfo("ru")
                };

                builder.Services
                    .AddFluentValidationAutoValidation()
                    .AddFluentValidationClientsideAdapters();
                builder.Services
                    .AddValidatorsFromAssemblyContaining<LoginRequestValidator>()
                    .AddValidatorsFromAssemblyContaining<RefreshRequestValidator>()
                    .AddValidatorsFromAssemblyContaining<RegisterRequestValidator>();

                // Настройка модели ошибки в API
                builder.Services.Configure<ApiBehaviorOptions>(options =>
                {
                    options.InvalidModelStateResponseFactory = context =>
                    {
                        var errors = context.ModelState
                            .Where(e => e.Value?.Errors.Count > 0)
                            .ToDictionary(
                                kvp => kvp.Key,
                                kvp => kvp.Value!.Errors.Select(err => err.ErrorMessage).ToArray()
                            );

                        var problemDetails = new ValidationProblemDetails(errors)
                        {
                            Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                            Title = "Bad Request",
                            Status = StatusCodes.Status400BadRequest,
                            Instance = context.HttpContext.Request.Path,
                            Extensions =
                        {
                            // Добавляем traceId
                            ["traceId"] = context.HttpContext.TraceIdentifier
                        }
                        };

                        return new BadRequestObjectResult(problemDetails);
                    };
                });

                // Настройка Swagger
                builder.Services.AddEndpointsApiExplorer();
                builder.Services.AddSwaggerGen(options =>
                {
                    options.SwaggerDoc("v1", new OpenApiInfo { Title = "AVP.AuthCore", Version = "v1" });

                    // Проверка существования XML-файлов для документации
                    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
                    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                    if (File.Exists(xmlPath))
                    {
                        options.IncludeXmlComments(xmlPath);
                    }

                    // Подключение документации DTO
                    xmlFile = $"{typeof(LoginRequest).Assembly.GetName().Name}.xml";
                    xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                    if (File.Exists(xmlPath))
                    {
                        options.IncludeXmlComments(xmlPath);
                    }

                    options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
                    {
                        Name = "Authorization",
                        Type = SecuritySchemeType.Http,
                        Scheme = "Bearer",
                        BearerFormat = "JWT",
                        In = ParameterLocation.Header,
                        Description = "Введите токен JWT в формате: Bearer {токен}"
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
                        new List<string>()
                    }
                });
                });

                // Настройка авторизации и аутентификации
                builder.Services.AddAuthorization();
                builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
                            ValidateAudience = true,
                            ValidAudience = builder.Configuration["JwtSettings:Audience"],
                            ValidateLifetime = true,
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Key"]!))
                        };
                    });

                // Конфигурация базы данных
                builder.Services.AddDbContext<AuthDbContext>(options =>
                    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

                builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                    .AddEntityFrameworkStores<AuthDbContext>()
                    .AddDefaultTokenProviders();

                // Локализация
                builder.Services.AddSingleton<IStringLocalizerFactory, ResourceManagerStringLocalizerFactory>();
                builder.Services.AddSingleton<IStringLocalizer>(provider =>
                {
                    var factory = provider.GetRequiredService<IStringLocalizerFactory>();
                    return factory.Create("ErrorMessages", "AVP.AuthCore.Application");
                });

                // автоочистка RefreshToken 
                builder.Services.AddHostedService<RefreshTokenCleanupService>();

                var app = builder.Build();

                // Локализация
                var supportedCultures = new[] { new CultureInfo("en"), new CultureInfo("ru") };
                app.UseRequestLocalization(new RequestLocalizationOptions
                {
                    DefaultRequestCulture = new RequestCulture("en"),
                    SupportedCultures = supportedCultures,
                    SupportedUICultures = supportedCultures
                });

                // Конфигурация pipeline
                if (app.Environment.IsDevelopment())
                {
                    app.UseSwagger();
                    app.UseSwaggerUI();
                }

                app.UseHttpsRedirection();

                // Middleware для логирования ошибок
                app.UseMiddleware<ExceptionLoggingMiddleware>();
                // Логирование HTTP-запросов
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
