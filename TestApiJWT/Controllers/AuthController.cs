using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestApiJWT.Models;
using TestApiJWT.Services;

namespace TestApiJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> RegisterAsync([FromBody]RegisterModel model)
        {
            //Check the model coming from the body validity
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            //Check result of the registeration
            var result = await _authService.RegisterAsync(model);
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            //return Ok(new {token = result.Token, expiresOn = result.ExpiresOn});
            return Ok(result);
        }

        [HttpPost("Token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            //Check the model coming from the body validity
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            //Check result of the GetToken Method
            var result = await _authService.GetTokenAsync(model);
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }
    }
}
