using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie")
    .AddOAuth("keycloak", o =>
    {
        o.SignInScheme = "cookie";
        o.SaveTokens = true;

        o.ClientId = "myclient";
        o.ClientSecret = "3wnVohjTySMXJGqJGDicO40dDTasGYjv";

        o.AuthorizationEndpoint = "http://localhost:8080/realms/myrealm/protocol/openid-connect/auth";
        o.TokenEndpoint = "http://localhost:8080/realms/myrealm/protocol/openid-connect/token";
        o.UserInformationEndpoint = "http://localhost:8080/realms/myrealm/protocol/openid-connect/userinfo";

        o.CallbackPath = "/oauth/keycloak-cb";

        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.Scope.Add("email");

        o.ClaimActions.MapJsonKey("sub", "sub");
        o.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
        o.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        o.ClaimActions.MapJsonKey("preferred_username", "preferred_username");

        o.Events.OnCreatingTicket = async ctx =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
            using var result = await ctx.Backchannel.SendAsync(request);

            var user = await result.Content.ReadFromJsonAsync<JsonElement>();
            ctx.RunClaimActions(user);
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Unauthorized");
app.MapGet("/info", (HttpContext ctx) => ctx.User.Claims.Select(claim => new { claim.Type, claim.Value }).ToList())
    .RequireAuthorization();

app.MapGet("/kc-login", () => Results.Challenge(new AuthenticationProperties
{
    RedirectUri = "http://localhost:5000/"
}, authenticationSchemes: ["keycloak"])).AllowAnonymous();

app.Run();