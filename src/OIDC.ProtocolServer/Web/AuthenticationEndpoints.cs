namespace JGUZDV.OIDC.ProtocolServer.Web
{
    public partial class Endpoints
    {
        public static class Authentication
        {
            public static IResult Challenge() => Results.Challenge();

            public static IResult SignOut() => Results.SignOut();
        }
    }
}
