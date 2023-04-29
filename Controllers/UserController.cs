namespace JWT_Test_me.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly string refreshTokenName = "refToken";
        public UserController(IAuthService _authService)
        {
            this._authService =  _authService;
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.RegisterAsync(model);
            if (!result.IsAuthenticated)
                return BadRequest(result._message);
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
            return Ok(result);
        }
        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.GetTokenAsync(model);
            if (!result.IsAuthenticated)
                return BadRequest(result._message);
            SetRefreshTokenInCookie(result.RefreshToken , result.RefreshTokenExpiration);
            return Ok(result);
        }
        [HttpPost("addRole")]
        public async Task<IActionResult> addRoleAsync([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.AddRoleAsync(model);
            if (!String.IsNullOrEmpty(result))
                return BadRequest(result);
            return Ok(model);
        }
        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = GetRefreshTokenInCookie();
            var result = await _authService.RefreshTokenAsync(refreshToken);
            if(!result.IsAuthenticated)
                return BadRequest(result);
            SetRefreshTokenInCookie(result.RefreshToken , result.RefreshTokenExpiration);
            return Ok(result);
        }
        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken dto)
        {
            var refreshToken = dto.Token ?? GetRefreshTokenInCookie();
            if(String.IsNullOrEmpty(refreshToken)) 
                return BadRequest("Token is required!");
            var result = await _authService.RevokeTokenAsync(refreshToken);
            if(!result)
                return BadRequest("Token is invalid!");
            return Ok(result);
        }
        
        private void SetRefreshTokenInCookie(string refreshToken , DateTime expired)
        {
            var CookiesOption = new CookieOptions
            {
                HttpOnly = true,
                Expires = expired.ToLocalTime()
            };
            Response.Cookies.Append(refreshTokenName , refreshToken , CookiesOption);
        }
        private string? GetRefreshTokenInCookie()
        {
            return Request.Cookies[refreshTokenName];
        }
    }
}