using Microsoft.EntityFrameworkCore;

namespace JGUZDV.OIDC.AttributeProxy;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }
}
