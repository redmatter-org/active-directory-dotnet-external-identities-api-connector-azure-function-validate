using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Linq;

namespace Sample.ExternalIdentities
{
    public static class SignInRoles
    {
        [FunctionName("SignInRoles")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            // Check HTTP basic authorization
            if (!Authorize(req, log))
            {
                log.LogWarning("HTTP basic authentication validation failed.");
                return (ActionResult)new UnauthorizedResult();
            }

            // Get the request body
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);

            // If input data is null, show block page
            if (data == null)
            {
                // Print out the request body
                log.LogInformation("Request body missing.");
            }

            // Print out the request body
            log.LogInformation("Request body: " + requestBody);

            // Get the current user language 
            string language = (data.ui_locales == null || data.ui_locales.ToString() == "") ? "default" : data.ui_locales.ToString();
            log.LogInformation($"Current language: {language}");

            // Input validation passed successfully, return `Allow` response.
            // TO DO: Configure the claims you want to return
            return (ActionResult)new OkObjectResult(new ResponseContent() { 
                jobTitle = "This value return by the API Connector",
                // You can also return custom claims using extension properties.
                extension_Roles = "my custom claim response for" + data.objectId
            });
        }

        private static bool Authorize(HttpRequest req, ILogger log)
        {
            // Get the environment's credentials 
            string username = System.Environment.GetEnvironmentVariable("BASIC_AUTH_USERNAME", EnvironmentVariableTarget.Process);
            string password = System.Environment.GetEnvironmentVariable("BASIC_AUTH_PASSWORD", EnvironmentVariableTarget.Process);

            // Returns authorized if the username is empty or not exists.
            if (string.IsNullOrEmpty(username))
            {
                log.LogInformation("HTTP basic authentication is not set.");
                return true;
            }

            // Check if the HTTP Authorization header exist
            if (!req.Headers.ContainsKey("Authorization"))
            {
                log.LogWarning("Missing HTTP basic authentication header.");
                return false;
            }

            // Read the authorization header
            var auth = req.Headers["Authorization"].ToString();

            // Ensure the type of the authorization header id `Basic`
            if (!auth.StartsWith("Basic "))
            {
                log.LogWarning("HTTP basic authentication header must start with 'Basic '.");
                return false;
            }

            // Get the the HTTP basinc authorization credentials
            var cred = System.Text.UTF8Encoding.UTF8.GetString(Convert.FromBase64String(auth.Substring(6))).Split(':');

            // Evaluate the credentials and return the result
            return (cred[0] == username && cred[1] == password);
        }
    }
}
