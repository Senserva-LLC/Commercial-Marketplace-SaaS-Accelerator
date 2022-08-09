// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See LICENSE file in the project root for license information.
namespace Microsoft.Marketplace.SaasKit.Client
{
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication.OpenIdConnect;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.Marketplace.SaaS.SDK.Services.Contracts;
    using Microsoft.Marketplace.SaaS.SDK.Services.Services;
    using Microsoft.Marketplace.SaaS.SDK.Services.Utilities;
    using Microsoft.Marketplace.SaasKit.Client.DataAccess.Context;
    using Microsoft.Marketplace.SaasKit.Client.DataAccess.Contracts;
    using Microsoft.Marketplace.SaasKit.Client.DataAccess.Services;
    using Microsoft.Marketplace.SaaS.SDK.Services.Configurations;
    using Microsoft.Marketplace.SaaS.SDK.Services.WebHook;
    using global::Azure.Identity;
    using Microsoft.Marketplace.SaaS;
    using Microsoft.AspNetCore.Authentication;
    using System.IdentityModel.Tokens.Jwt;
    using Azure.Security.KeyVault.Secrets;
    using Azure.Core;
    using System;

    /// <summary>
    /// Defines the <see cref="Startup" />.
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Startup"/> class.
        /// </summary>
        /// <param name="configuration">The configuration<see cref="IConfiguration"/>.</param>
        public Startup(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }

        /// <summary>
        /// Gets the Configuration.
        /// </summary>
        public IConfiguration Configuration { get; }

        /// <summary>
        /// The ConfigureServices.
        /// </summary>
        /// <param name="services">The services<see cref="IServiceCollection"/>.</param>
        public void ConfigureServices(IServiceCollection services)
        {
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder
                    .AddConsole();
            });

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            SecretClientOptions options = new SecretClientOptions()
            {
                Retry =
                {
                    Delay = TimeSpan.FromSeconds(1),
                    MaxDelay = TimeSpan.FromSeconds(16),
                    MaxRetries = 5,
                    Mode = RetryMode.Exponential,
                }
            };

            var client = new SecretClient(new Uri("https://saastestvault.vault.azure.net/"), new DefaultAzureCredential(), options);

            KeyVaultSecret clientId = client.GetSecret("clientid");
            KeyVaultSecret tenantId = client.GetSecret("tenantid");
            KeyVaultSecret saasAppUrl = client.GetSecret("saasappurl");
            KeyVaultSecret defaultConnection = client.GetSecret("defaultconnection");

            var config = new SaaSApiClientConfiguration()
            {
                AdAuthenticationEndPoint = this.Configuration["SaaSApiConfiguration:AdAuthenticationEndPoint"],
                ClientId = clientId.Value,
                ClientSecret = this.Configuration["SaaSApiConfiguration:ClientSecret"],
                MTClientId = clientId.Value,
                FulFillmentAPIBaseURL = this.Configuration["SaaSApiConfiguration:FulFillmentAPIBaseURL"],
                FulFillmentAPIVersion = this.Configuration["SaaSApiConfiguration:FulFillmentAPIVersion"],
                GrantType = this.Configuration["SaaSApiConfiguration:GrantType"],
                Resource = this.Configuration["SaaSApiConfiguration:Resource"],
                SaaSAppUrl = saasAppUrl.Value,
                SignedOutRedirectUri = this.Configuration["SaaSApiConfiguration:SignedOutRedirectUri"],
                TenantId = tenantId.Value,
            };

            var creds = new ClientSecretCredential(config.TenantId.ToString(), config.ClientId.ToString(), config.ClientSecret);

            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = OpenIdConnectDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie()
                .AddOpenIdConnect(options =>
                {
                    options.Authority = $"{config.AdAuthenticationEndPoint}/common/v2.0";
                    options.ClientId = config.MTClientId;
                    options.ResponseType = OpenIdConnectResponseType.IdToken;
                    options.CallbackPath = "/Home/Index";
                    options.SignedOutRedirectUri = config.SignedOutRedirectUri;
                    options.TokenValidationParameters.NameClaimType = ClaimConstants.CLAIM_NAME; //This does not seem to take effect on User.Identity. See Note in CustomClaimsTransformation.cs
                    options.TokenValidationParameters.ValidateIssuer = false;
                });
            services
               .AddTransient<IClaimsTransformation, CustomClaimsTransformation>();

            services
                .AddSingleton<IFulfillmentApiService>(new FulfillmentApiService(new MarketplaceSaaSClient(creds), config, new FulfillmentApiClientLogger()))
                .AddSingleton<SaaSApiClientConfiguration>(config)
                ;

            services
                .AddDbContext<SaasKitContext>(options => options.UseSqlServer(defaultConnection.Value));

            InitializeRepositoryServices(services);

            services.AddMvc(option => option.EnableEndpointRouting = false);
        }

        /// <summary>
        /// The Configure.
        /// </summary>
        /// <param name="app">The app<see cref="IApplicationBuilder" />.</param>
        /// <param name="env">The env<see cref="IWebHostEnvironment" />.</param>
        /// <param name="loggerFactory">The loggerFactory<see cref="ILoggerFactory" />.</param>
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private static void InitializeRepositoryServices(IServiceCollection services)
        {
            services.AddScoped<ISubscriptionsRepository, SubscriptionsRepository>();
            services.AddScoped<IPlansRepository, PlansRepository>();
            services.AddScoped<IUsersRepository, UsersRepository>();
            services.AddScoped<ISubscriptionLogRepository, SubscriptionLogRepository>();
            services.AddScoped<IApplicationLogRepository, ApplicationLogRepository>();
            services.AddScoped<IWebhookProcessor, WebhookProcessor>();
            services.AddScoped<IWebhookHandler, WebHookHandler>();
            services.AddScoped<IApplicationConfigRepository, ApplicationConfigRepository>();
            services.AddScoped<IEmailTemplateRepository, EmailTemplateRepository>();
            services.AddScoped<IOffersRepository, OffersRepository>();
            services.AddScoped<IOfferAttributesRepository, OfferAttributesRepository>();
            services.AddScoped<IPlanEventsMappingRepository, PlanEventsMappingRepository>();
            services.AddScoped<IEventsRepository, EventsRepository>();
            services.AddScoped<IEmailService, SMTPEmailService>();
        }
    }
}
