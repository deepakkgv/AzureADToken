namespace VCA.Sparky.Authentication.Models
{
    public abstract class TokenRequestBase
    {
        public string? grant_type { get; set; }
        public string? client_id { get; set; }
        public string? resource { get; set; }
    }

    public class PasswordTokenRequest : TokenRequestBase
    {
        public string? username { get; set; }
        public string? password { get; set; }
    }

    public class RefreshTokenRequest : TokenRequestBase
    {
        public string? refresh_token { get; set; }
    }
}
