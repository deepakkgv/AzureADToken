using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Text;
using VCA.Sparky.Authentication.Models;

namespace VCA.Sparky.Authentication.Controllers
{
    [ApiController]
    [Route("OAuth")]
    public class AzureAdTokenGenerator : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AzureAdTokenGenerator(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("Token")]
        public async Task<ActionResult> Login(
            [FromHeader(Name = "Authorization")] string authorizationHeader = "",
            [FromForm] string grantType = "password")
        {
            // Check if the authorization header is present and has a valid format
            if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Basic "))
            {
                return Unauthorized("Invalid Authorization header");
            }

            // Extract the username and password from the authorization header
            var loginCredentials = ExtractBasicAuthCredentials(authorizationHeader);

            // Check if the username or password is empty
            if (string.IsNullOrEmpty(loginCredentials.username) || string.IsNullOrEmpty(loginCredentials.password))
            {
                return Unauthorized("Username or password is empty");
            }

            var responseToken = await GetTokenAsync(authorizationHeader, "password");

            if (responseToken != null)
            {
                // Extract the new access token from the response
                return Content(responseToken, "application/json");
            }

            return NotFound("User not found");
        }

        [AllowAnonymous]
        [HttpPost("RefreshToken")]
        public async Task<ActionResult> RefreshToken([FromForm] string refresh_token)
        {
            var responseToken = await GetTokenAsync(refresh_token, "refresh_token");

            if (responseToken != null)
            {
                // Extract the new access token from the response
                return Content(responseToken, "application/json");
            }

            return Unauthorized("Invalid refresh token");
        }

        private async Task<string> GetTokenAsync(string token, string grantType)
        {
            var endpoint = _configuration["AzureAd:Endpoint"];
            var clientId = _configuration["AzureAd:ClientId"];
            var resource = _configuration["AzureAd:Resource"];

            using (var httpClient = new HttpClient())
            {
                TokenRequestBase? requestParams = null;

                if (grantType == "password")
                {
                    var credentials = ExtractBasicAuthCredentials(token);
                    requestParams = new PasswordTokenRequest
                    {
                        grant_type = grantType,
                        client_id = clientId,
                        resource = resource,
                        username = credentials.username ?? string.Empty,
                        password = credentials.password ?? string.Empty
                    };
                }
                else if (grantType == "refresh_token")
                {
                    requestParams = new RefreshTokenRequest
                    {
                        grant_type = grantType,
                        client_id = clientId,
                        resource = resource,
                        refresh_token = token
                    };
                }

                var tokenEndpoint = endpoint;
                var requestData = requestParams?.GetType().GetProperties()
                    .ToDictionary(prop => prop.Name, prop => prop.GetValue(requestParams)?.ToString() ?? string.Empty)
                    ?? new Dictionary<string, string>();

                var requestContent = new FormUrlEncodedContent(requestData);

                var response = await httpClient.PostAsync(tokenEndpoint, requestContent);
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var responseObject = JObject.Parse(responseContent);
                    // Remove properties from the JSON object
                    responseObject.Remove("scope");
                    responseObject.Remove("ext_expires_in");
                    responseObject.Remove("expires_on");
                    responseObject.Remove("not_before");
                    responseObject.Remove("resource");
                    return responseObject.ToString();
                }

                var errorResponseContent = await response.Content.ReadAsStringAsync();
                return errorResponseContent;
            }
        }

        private LoginCredentials ExtractBasicAuthCredentials(string authorizationHeader)
        {
            if (string.IsNullOrEmpty(authorizationHeader))
                return new LoginCredentials();

            var encodedCredentials = authorizationHeader.Replace("Basic ", "");
            var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            var credentials = decodedCredentials.Split(':');

            if (credentials.Length != 2)
                return new LoginCredentials();

            var username = credentials[0];
            var password = credentials[1];

            return new LoginCredentials
            {
                username = username,
                password = password
            };
        }
    }
    
}
