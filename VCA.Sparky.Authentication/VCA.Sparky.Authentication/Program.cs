using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Redirect HTTP requests to HTTPS.
app.UseHttpsRedirection();

// Enable authorization.
app.UseAuthorization();

// Map the controllers.
app.MapControllers();

// Run the application.
app.Run();