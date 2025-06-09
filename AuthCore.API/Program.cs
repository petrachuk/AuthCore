using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using FluentValidation;
using FluentValidation.AspNetCore;
using AuthCore.Abstractions.Interfaces;
using AuthCore.Application.Common.Settings;
using AuthCore.Application.DTOs;
using AuthCore.Application.Interfaces;
using AuthCore.Application.Services;
using AuthCore.Application.Validation;
using AuthCore.Infrastructure.HostedServices;
using AuthCore.Infrastructure.Logging;
using AuthCore.Persistence;
using AuthCore.Persistence.Entities;
using AuthCore.Persistence.Stores;

namespace AuthCore.API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Получаем имя окружения
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";

            // Собираем конфигурацию один раз
            var configurationBuilder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{environment}.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables();

            var configuration = configurationBuilder.Build();

            // Инициализация логирования до запуска приложения
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                .Enrich.FromLogContext()
                .CreateLogger();

            try
            {
                Log.Information("Starting up the app...");
                var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, EnvironmentName = environment });

                // Очищаем и копируем источники из уже собранного builder
                builder.Configuration.Sources.Clear();
                foreach (var source in configurationBuilder.Sources)
                {
                    builder.Configuration.Sources.Add(source);
                }

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

                // Настройка авторизации и аутентификации
                builder.Services.AddAuthentication(options =>
                    {
                        // Используем JWT везде по умолчанию
                        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                    })
                    .AddJwtBearer(options =>
                    {
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidateAudience = true,
                            ValidateLifetime = true,
                            ValidateIssuerSigningKey = true,
                            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
                            ValidAudience = builder.Configuration["JwtSettings:Audience"],
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Key"]!))
                        };
                    });
                builder.Services.AddAuthorization();

                builder.Services.AddControllers();
                builder.Services.AddLocalization(options => options.ResourcesPath = string.Empty);

                // Настройка FluentValidation
                CultureInfo.DefaultThreadCurrentCulture = new CultureInfo("en-US");
                CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");

                builder.Services
                    .AddFluentValidationAutoValidation()
                    .AddFluentValidationClientsideAdapters();
                builder.Services
                    .AddValidatorsFromAssemblyContaining<LoginRequestValidator>()
                    .AddValidatorsFromAssemblyContaining<RefreshRequestValidator>()
                    .AddValidatorsFromAssemblyContaining<RegisterRequestValidator>();

                // Console.WriteLine($"Thread.CurrentUICulture: {Thread.CurrentThread.CurrentUICulture}");
                // Console.WriteLine($"First error: {errors.FirstOrDefault().Value?.FirstOrDefault()}");

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

                // отключение лишних форматтеров
                builder.Services.Configure<MvcOptions>(options =>
                {
                    // Убираем поддержку text/plain (строковый форматтер)
                    var stringFormatter = options.OutputFormatters
                        .OfType<Microsoft.AspNetCore.Mvc.Formatters.StringOutputFormatter>()
                        .FirstOrDefault();

                    if (stringFormatter is not null)
                    {
                        options.OutputFormatters.Remove(stringFormatter);
                    }

                    // Настраиваем JSON входной форматтер (только application/json)
                    var jsonInputFormatter = options.InputFormatters
                        .OfType<Microsoft.AspNetCore.Mvc.Formatters.SystemTextJsonInputFormatter>()
                        .FirstOrDefault();

                    if (jsonInputFormatter is not null)
                    {
                        jsonInputFormatter.SupportedMediaTypes.Clear();
                        jsonInputFormatter.SupportedMediaTypes.Add("application/json");
                    }
                });

                // Настройка Swagger
                builder.Services.AddEndpointsApiExplorer();
                builder.Services.AddSwaggerGen(options =>
                {
                    options.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthCore", Version = "v1" });

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

                // Конфигурация базы данных
                if (!builder.Environment.IsEnvironment("Test"))
                {
                    builder.Services.AddDbContext<AuthDbContext>(options =>
                        options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));
                }

                builder.Services.AddIdentityCore<ApplicationUser>(options =>
                    {
                        options.Password.RequireDigit = true;
                        options.Password.RequiredLength = 10;
                        options.Password.RequireNonAlphanumeric = false;
                        options.Password.RequireUppercase = true;
                        options.Password.RequireLowercase = true;
                        // Настройки блокировок, email-подтверждения и т.д. при необходимости
                    })
                    .AddRoles<IdentityRole>()
                    .AddEntityFrameworkStores<AuthDbContext>()
                    .AddSignInManager()
                    .AddDefaultTokenProviders();

                var redisConnectionString = builder.Configuration.GetSection("Redis:ConnectionString").Value;
                
                if (string.IsNullOrWhiteSpace(redisConnectionString) || builder.Environment.IsEnvironment("Test"))
                {
                    builder.Services.AddScoped<IRefreshTokenStore, DbRefreshTokenStore>();
                    builder.Services.AddHostedService<RefreshTokenCleanupService>();
                }
                else
                {
                    builder.Services.AddStackExchangeRedisCache(options =>
                    {
                        options.Configuration = redisConnectionString;
                    });
                    builder.Services.AddScoped<IRefreshTokenStore, RedisRefreshTokenStore>();
                }

                var app = builder.Build();

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
