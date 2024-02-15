using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace AuthenticationUsingIdentity.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddedCustomerUserIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5609f663-5a3e-47f3-9d45-26a3f5a7fe0e");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "d5f5f3f6-e2b3-4bd1-a032-1a27c1192d58");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e0facc37-1f16-4df7-8d16-e07173bdc18c");

            migrationBuilder.AddColumn<string>(
                name: "RefreshToken",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "RefreshTokenExpiry",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "22fbe8ea-1c32-4eed-bc36-05b3420b9c31", "2", "User", "User" },
                    { "4d6cb585-ea25-4c86-ad89-bfe69156f34f", "3", "HR", "HR" },
                    { "58657ea6-b2cc-48f8-8e1b-fd64a7f002cc", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "22fbe8ea-1c32-4eed-bc36-05b3420b9c31");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "4d6cb585-ea25-4c86-ad89-bfe69156f34f");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "58657ea6-b2cc-48f8-8e1b-fd64a7f002cc");

            migrationBuilder.DropColumn(
                name: "RefreshToken",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "RefreshTokenExpiry",
                table: "AspNetUsers");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "5609f663-5a3e-47f3-9d45-26a3f5a7fe0e", "3", "HR", "HR" },
                    { "d5f5f3f6-e2b3-4bd1-a032-1a27c1192d58", "2", "User", "User" },
                    { "e0facc37-1f16-4df7-8d16-e07173bdc18c", "1", "Admin", "Admin" }
                });
        }
    }
}
