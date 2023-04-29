namespace JWT_Test_me.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;
        protected readonly IMapper _mapper ;
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, 
            IOptions<JWT> jwt , IMapper mapper)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
            _mapper = mapper;
        }
        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { _message = "Email is already registered!" };
            if (await _userManager.FindByNameAsync(model.Username) is not null)
                return new AuthModel { _message = "Username is already registered!" };
            var user = _mapper.Map<ApplicationUser>(model);
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors) errors += $"{error.Description},";
                return new AuthModel { _message = errors };
            }
            await _userManager.AddToRoleAsync(user, "User");
            var jwtSecurityToken = await CreateJwtToken(user);
            if(jwtSecurityToken is null) return new AuthModel { _message = "You did not add JWT props in your appSettings file!" };
            var refreshToken = GenerateRefreshToken();
            user.RefreshTokens?.Add(refreshToken);
            await _userManager.UpdateAsync(user);
            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpiresOn
            };
        }
        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user is null || ! await _userManager.CheckPasswordAsync(user , model.Password))
                return new AuthModel { _message = "Email or Password is not correct!" };
            var jwtSecurityToken = await CreateJwtToken(user);
            if(jwtSecurityToken is null)
                return new AuthModel { _message = "You did not add JWT props in your appSettings file!" };
            var Role = await _userManager.GetRolesAsync(user);
            RefreshToken refreshToken;
            if(user.RefreshTokens.Any(t => t.IsActive))
                 refreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
            else
            {
                refreshToken = GenerateRefreshToken();
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);
            }
            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = Role.ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpiresOn
            };
        }
        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if(user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid user Id or Role";
            if(await _userManager.IsInRoleAsync(user , model.Role))
                return "User already assigned to this role !";

            var result = await _userManager.AddToRoleAsync(user , model.Role);
            return !result.Succeeded ? "Something went wrong !" : string.Empty;
        }
        public async Task<AuthModel> RefreshTokenAsync(string token)
        {
            var user = await _userManager.Users.SingleOrDefaultAsync(
                u => u.RefreshTokens.Any(t => t.Token == token));
            if(user is null)
                return new AuthModel { _message = "Invalid Token"};
            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if(!refreshToken.IsActive)
                return new AuthModel{ _message = "Inactive Token"};
            refreshToken.RevokedOn = _DateTime._now;
            var newRefreshToken = GenerateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            await _userManager.UpdateAsync(user);
            var Role = await _userManager.GetRolesAsync(user);
            var new_jwt = await CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = new_jwt.ValidTo,
                IsAuthenticated = true,
                Roles = Role.ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(new_jwt),
                Username = user.UserName,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpiresOn
            };
        }
        public async Task<bool> RevokeTokenAsync(string token)
        {
            var user = await _userManager.Users.SingleOrDefaultAsync(
                u => u.RefreshTokens.Any(t => t.Token == token));
            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if(user is null || !refreshToken.IsActive) return false;
            refreshToken.RevokedOn = _DateTime._now;
            await _userManager.UpdateAsync(user);
            return true;
        }
        
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();
            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }.Union(userClaims).Union(roleClaims);
            if(_jwt.Key is null) return null;
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: _DateTime._now.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }
        public RefreshToken GenerateRefreshToken()
        {
            var random = new byte[32];
            using var generate = new RNGCryptoServiceProvider();
            generate.GetBytes(random);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(random) ,
                CreatedOn = _DateTime._now,
                ExpiresOn = _DateTime._now.AddDays(10),
            };
        }
    }
}