using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace AuthenticationUsingIdentity.Data.Migrations
{
    /// <inheritdoc />
    public partial class thirdmigration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "4abc78b2-1734-40b1-a164-6a91f19eb9c1");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "8bbc29c8-396c-4e31-aae4-a51b10848ebf");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e6028346-524c-4989-9f8c-1859ae9ef8db");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "2b56fc4f-c169-4d33-a6e0-bc6f800401f4", "3", "HR", "HR" },
                    { "97f3fa9f-961d-4c24-ae81-6a0d454e1152", "2", "User", "User" },
                    { "9af95476-096c-4707-b8b7-28018e48bbe4", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "2b56fc4f-c169-4d33-a6e0-bc6f800401f4");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "97f3fa9f-961d-4c24-ae81-6a0d454e1152");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9af95476-096c-4707-b8b7-28018e48bbe4");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "4abc78b2-1734-40b1-a164-6a91f19eb9c1", "1", "Admin", "Admin" },
                    { "8bbc29c8-396c-4e31-aae4-a51b10848ebf", "3", "HR", "HR" },
                    { "e6028346-524c-4989-9f8c-1859ae9ef8db", "2", "User", "User" }
                });
        }
    }
}
