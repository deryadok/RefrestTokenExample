using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using RefreshTokenExample.Entities;

namespace RefreshTokenExample.Helpers
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options) : base(options)
        {

        }

        public DbSet<User> Users { get; set; }
    }

    public class UserFactory : IDesignTimeDbContextFactory<UserDbContext>
    {
        public UserDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<UserDbContext>();
            optionsBuilder.UseSqlServer("Server=.;Database=RefreshTokenDB;Trusted_Connection=True;");

            return new UserDbContext(optionsBuilder.Options);
        }
    }
}
