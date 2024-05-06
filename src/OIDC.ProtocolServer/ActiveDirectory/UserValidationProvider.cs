
using System.Security.Claims;

using JGUZDV.ActiveDirectory;

namespace JGUZDV.OIDC.ProtocolServer.ActiveDirectory
{
    public class UserValidationProvider
    {
        private readonly DirectoryEntryProvider _directoryEntryProvider;
        private readonly IPropertyReader _propertyReader;

        public UserValidationProvider(
            DirectoryEntryProvider directoryEntryProvider,
            IPropertyReader propertyReader)
        {
            _directoryEntryProvider = directoryEntryProvider;
            _propertyReader = propertyReader;
        }

        public DateTimeOffset? LastPasswordChange(ClaimsPrincipal subject)
        {
            var userEntry = _directoryEntryProvider.GetUserEntryFromPrincipal(subject, "pwdLastSet");
            var lastChange = _propertyReader.ReadLongAsDateTime(userEntry.Properties, "pwdLastSet");

            return lastChange;
        }

        public bool IsUserActive(ClaimsPrincipal subject)
        {
            const int UF_ACCOUNTDISABLE = 0x0002;

            var userEntry = _directoryEntryProvider.GetUserEntryFromPrincipal(subject, "userAccountControl");
            var userAccountControl = _propertyReader.ReadInt(userEntry.Properties, "userAccountControl");

            return (userAccountControl & UF_ACCOUNTDISABLE) != UF_ACCOUNTDISABLE;
        }
    }
}
