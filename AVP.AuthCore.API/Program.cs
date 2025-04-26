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

namespace AVP.AuthCore.API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Настройка Serilog
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

                builder.Host.UseSerilog(); // подключение Serilog

                // Add services to the container.

                builder.Services.AddControllers();

                builder.Services.AddLocalization(options => options.ResourcesPath = string.Empty);

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

                // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
                builder.Services.AddEndpointsApiExplorer();
                builder.Services.AddSwaggerGen(options =>
                {
                    options.SwaggerDoc("v1", new OpenApiInfo { Title = "AVP.AuthCore", Version = "v1" });

                    // Документация на основе комментариев из XML
                    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
                    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                    options.IncludeXmlComments(xmlPath);

                    // Подключаем XML-документацию сборки с DTO:
                    xmlFile = $"{typeof(LoginRequest).Assembly.GetName().Name}.xml";
                    xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                    options.IncludeXmlComments(xmlPath);

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
                            []
                        }
                    });
                });

                builder.Services.AddAuthorization();
                builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            // указывает, будет ли валидироваться издатель при валидации токена
                            ValidateIssuer = true,
                            // строка, представляющая издателя
                            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
                            // будет ли валидироваться потребитель токена
                            ValidateAudience = true,
                            // установка потребителя токена
                            ValidAudience = builder.Configuration["JwtSettings:Audience"],
                            // будет ли валидироваться время существования
                            ValidateLifetime = true,
                            // валидация ключа безопасности
                            ValidateIssuerSigningKey = true,
                            // установка ключа безопасности
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Key"]!))
                        };
                    });

                // конфигурация БД
                builder.Services.AddDbContext<AuthDbContext>(options =>
                    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

                builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                    .AddEntityFrameworkStores<AuthDbContext>()
                    .AddDefaultTokenProviders();

                // Register IAuthService with its implementation
                builder.Services.AddScoped<IAuthService, AuthService>();
                builder.Services.AddScoped<ITokenService, TokenService>();

                // Настраиваем локализацию для использования ресурсов из другого проекта
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

                // добавляем middleware для логирования исключений
                app.UseMiddleware<ExceptionLoggingMiddleware>();
                // добавляет логирование HTTP-запросов
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
