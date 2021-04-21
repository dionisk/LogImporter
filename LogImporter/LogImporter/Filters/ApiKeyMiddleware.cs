using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace SecuringWebApiUsingApiKey.Middleware
{
    public class ApiKeyMiddleware
    {
        private readonly RequestDelegate _next;
        readonly string[] ApiKeys = { "ApiKey1", "ApiKey2" };
        readonly string extractedApiKey;
        public ApiKeyMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            bool IsValidKeyName = false;
            IConfiguration appSettings;
            string apiKey = null;           
            foreach (string key in ApiKeys)
            {
                if (context.Request.Headers.TryGetValue(key, out var extractedApiKey))
                {
                    IsValidKeyName = true;
                    appSettings = context.RequestServices.GetRequiredService<IConfiguration>();
                    apiKey = appSettings.GetValue<string>(key);
                    break;
                }                
            }

            if (!IsValidKeyName)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Api Key was not provided. (Using ApiKeyMiddleware) ");
                return;
            }       

            if (!apiKey.Equals(extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized client. (Using ApiKeyMiddleware)");
                return;
            }

            await _next(context);
        }
    }
}
