using Microsoft.EntityFrameworkCore;
using DemoProjectWithJWTAuth.Models;


namespace DemoProjectWithJWTAuth.Context

{
    public class AppDB : DbContext
    {
        public AppDB(DbContextOptions<AppDB> options) : base(options)
        {
        }
        public DbSet<Users> Users { get; set; } = null!;
    }
}