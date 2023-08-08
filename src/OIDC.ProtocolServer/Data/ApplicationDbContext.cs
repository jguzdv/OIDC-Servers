using Microsoft.EntityFrameworkCore;

namespace JGUZDV.OIDC.ProtocolServer.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    { }
}
