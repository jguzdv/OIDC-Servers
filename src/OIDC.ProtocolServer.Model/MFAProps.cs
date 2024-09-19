namespace JGUZDV.OIDC.ProtocolServer.Model
{
    public class MFAProps
    {
        public bool Required { get; set; }
        public TimeSpan? MaxAge { get; set; }
    }
}