using Microsoft.EntityFrameworkCore;

namespace JGUZDV.OIDC.ProtocolServer.Model;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    { }
}
