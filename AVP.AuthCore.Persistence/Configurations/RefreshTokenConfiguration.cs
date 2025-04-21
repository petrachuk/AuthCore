using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AVP.AuthCore.Persistence.Entities;

namespace AVP.AuthCore.Persistence.Configurations
{
    public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
    {
        public void Configure(EntityTypeBuilder<RefreshToken> builder)
        {
            builder.ToTable("RefreshTokens");

            builder.HasKey(rt => rt.Id);

            builder.Property(rt => rt.Token)
                .IsRequired()
                .HasMaxLength(512);

            builder.Property(rt => rt.Expires)
                .IsRequired();

            builder.Property(rt => rt.Revoked)
                .IsRequired();

            builder.Property(rt => rt.UserId)
                .IsRequired();

            builder.HasOne(rt => rt.User)
                .WithMany(u => u.RefreshTokens) // может быть несколько токенов. навигационное свойство в IdentityUser
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
