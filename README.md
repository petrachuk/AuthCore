# AuthCore

**AuthCore** is a ready-to-use API solution for authentication and authorization using JWT tokens. The project is built with **C#**, **.NET 8.0**, and leverages **Entity Framework** and **ASP.NET Identity**.

## Features

- User authentication via JWT
- User registration and login
- Role-based authorization with Identity
- Extensible architecture
- PostgreSQL support

## Requirements

- [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
- PostgreSQL database

## Getting Started

1. **Clone the repository**:
    ```bash
    git clone https://github.com/petrachuk/AuthCore.git
    cd AuthCore
    ```

2. **Prepare PostgreSQL database** (if not already created):

    Connect to PostgreSQL (e.g., via `psql` or a GUI client) and run:
    
    ```sql
    CREATE DATABASE authcore_db;
    CREATE USER authcore_user WITH PASSWORD 'secure_password';
    ALTER DATABASE authcore_db OWNER TO authcore_user;
    GRANT ALL PRIVILEGES ON DATABASE authcore_db TO authcore_user;
    ```

3. **Set up environment variables** (or configure `appsettings.json`):

    - `ConnectionStrings__DefaultConnection` — connection string for your PostgreSQL database.
    - `JwtSettings__Key` — a unique secret key used for signing JWT tokens.

    Example connection string:
    ```
    Host=localhost;Port=5432;Database=authcore_db;Username=authcore_user;Password=secure_password
    ```

4. **Apply database migrations**:
    ```bash
    dotnet ef database update --project AuthCore.Persistence
    ```

5. **Run the application**:
    ```bash
    dotnet run
    ```

## Contributing

Everyone is welcome to use this project. **Pull requests are highly appreciated**, especially those that improve **security**.

## License

[MIT License](LICENSE)
