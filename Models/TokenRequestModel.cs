namespace JWT_Test_me.Models
{
    public class TokenRequestModel
    {
        [Required , StringLength(128) , EmailAddress]
        public string Email { get; set; }

        [Required , StringLength(256)]
        public string Password { get; set; }
    }
}