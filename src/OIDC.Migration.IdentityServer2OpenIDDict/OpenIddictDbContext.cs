using Microsoft.EntityFrameworkCore;

namespace OIDC.Migration.IdentityServer2OpenIDDict
{
    internal class OpenIddictDbContext : DbContext
    {
        public OpenIddictDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}
