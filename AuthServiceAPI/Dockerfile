# Use the official image as a base
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80

# Use the SDK image to build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["AuthServiceAPI/AuthServiceAPI.csproj", "AuthServiceAPI/"]
RUN dotnet restore "AuthServiceAPI/AuthServiceAPI.csproj"
COPY . .
WORKDIR "/src/AuthServiceAPI"
RUN dotnet build "AuthServiceAPI.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AuthServiceAPI.csproj" -c Release -o /app/publish

# Copy the build output and configure the entry point for the container
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AuthServiceAPI.dll"]
