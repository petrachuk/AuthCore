using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AuthCore.Persistence.Entities;

namespace AuthCore.Persistence.Configurations
{
    public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
    {
        public void Configure(EntityTypeBuilder<RefreshToken> builder)
        {
            builder.ToTable("RefreshTokens");

            builder.HasKey(rt => rt.Id);

            builder.Property(rt => rt.Token)
                .IsRequired()
                .HasMaxLength(88);

            builder.Property(rt => rt.Expires)
                .IsRequired();

            builder.HasIndex(rt => rt.Token)
                .IsUnique();

            builder.HasIndex(rt => rt.Expires);

            builder.Property(rt => rt.UserId)
                .IsRequired()
                .HasMaxLength(36);

            builder.HasOne(rt => rt.User)
                .WithMany(u => u.RefreshTokens) // может быть несколько токенов. навигационное свойство в IdentityUser
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
