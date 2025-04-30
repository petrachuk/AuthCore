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
                .HasMaxLength(88);

            builder.Property(rt => rt.Revoked)
                .IsRequired()
                .HasDefaultValue(false);

            builder.Property(rt => rt.Expires)
                .IsRequired();

            builder.Property(rt => rt.ReplacedByToken)
                .HasMaxLength(88);

            builder.HasIndex(rt => rt.Token)
                .IsUnique();

            builder.HasIndex(rt => rt.Expires);

            builder.HasIndex(rt => rt.Revoked);

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
