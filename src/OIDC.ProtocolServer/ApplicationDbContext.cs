using Microsoft.EntityFrameworkCore;

namespace JGUZDV.OIDC.ProtocolServer;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) 
        : base(options)
    { }
}
