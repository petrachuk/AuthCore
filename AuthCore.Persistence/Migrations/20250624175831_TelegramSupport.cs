using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthCore.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TelegramSupport : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "TelegramId",
                table: "AspNetUsers",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WhatsAppId",
                table: "AspNetUsers",
                type: "character varying(25)",
                maxLength: 25,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TelegramId",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "WhatsAppId",
                table: "AspNetUsers");
        }
    }
}
