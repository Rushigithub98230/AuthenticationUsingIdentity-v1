using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace AuthenticationUsingIdentity.Api.Migrations
{
    /// <inheritdoc />
    public partial class Roleseeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "0a84dd9b-baf2-430e-8fa8-a5ed21a3cd60", "3", "HR", "HR" },
                    { "c688ecb7-a434-496a-82bb-4471fe629d1d", "2", "User", "User" },
                    { "ee5b404f-bb63-4a90-b66f-2fa42b3c61ce", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "0a84dd9b-baf2-430e-8fa8-a5ed21a3cd60");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c688ecb7-a434-496a-82bb-4471fe629d1d");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "ee5b404f-bb63-4a90-b66f-2fa42b3c61ce");
        }
    }
}
