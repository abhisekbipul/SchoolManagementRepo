USE [master]
GO
/****** Object:  Database [SchoolDb]    Script Date: 09-09-2024 01:12:08 ******/
CREATE DATABASE [SchoolDb]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'SchoolDb', FILENAME = N'C:\Users\USER\SchoolDb.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'SchoolDb_log', FILENAME = N'C:\Users\USER\SchoolDb_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
 WITH CATALOG_COLLATION = DATABASE_DEFAULT
GO
ALTER DATABASE [SchoolDb] SET COMPATIBILITY_LEVEL = 150
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [SchoolDb].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [SchoolDb] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [SchoolDb] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [SchoolDb] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [SchoolDb] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [SchoolDb] SET ARITHABORT OFF 
GO
ALTER DATABASE [SchoolDb] SET AUTO_CLOSE ON 
GO
ALTER DATABASE [SchoolDb] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [SchoolDb] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [SchoolDb] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [SchoolDb] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [SchoolDb] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [SchoolDb] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [SchoolDb] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [SchoolDb] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [SchoolDb] SET  ENABLE_BROKER 
GO
ALTER DATABASE [SchoolDb] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [SchoolDb] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [SchoolDb] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [SchoolDb] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [SchoolDb] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [SchoolDb] SET READ_COMMITTED_SNAPSHOT ON 
GO
ALTER DATABASE [SchoolDb] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [SchoolDb] SET RECOVERY SIMPLE 
GO
ALTER DATABASE [SchoolDb] SET  MULTI_USER 
GO
ALTER DATABASE [SchoolDb] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [SchoolDb] SET DB_CHAINING OFF 
GO
ALTER DATABASE [SchoolDb] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [SchoolDb] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [SchoolDb] SET DELAYED_DURABILITY = DISABLED 
GO
ALTER DATABASE [SchoolDb] SET ACCELERATED_DATABASE_RECOVERY = OFF  
GO
ALTER DATABASE [SchoolDb] SET QUERY_STORE = OFF
GO
USE [SchoolDb]
GO
/****** Object:  Table [dbo].[__EFMigrationsHistory]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[__EFMigrationsHistory](
	[MigrationId] [nvarchar](150) NOT NULL,
	[ProductVersion] [nvarchar](32) NOT NULL,
 CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY CLUSTERED 
(
	[MigrationId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Administrators]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Administrators](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[AdministratorUserId] [nvarchar](max) NOT NULL,
	[Password] [nvarchar](max) NOT NULL,
 CONSTRAINT [PK_Administrators] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Subjects]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Subjects](
	[SubjectId] [int] IDENTITY(1,1) NOT NULL,
	[SubjectName] [nvarchar](max) NOT NULL,
 CONSTRAINT [PK_Subjects] PRIMARY KEY CLUSTERED 
(
	[SubjectId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Teachers]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Teachers](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[TeacherUserId] [nvarchar](max) NOT NULL,
	[Password] [nvarchar](max) NOT NULL,
	[FirstName] [nvarchar](max) NOT NULL,
	[LastName] [nvarchar](max) NOT NULL,
	[Qualification] [nvarchar](max) NOT NULL,
	[SubjectId] [int] NOT NULL,
	[Email] [nvarchar](max) NOT NULL,
	[HireDate] [date] NOT NULL,
 CONSTRAINT [PK_Teachers] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Users]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Users](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[UserId] [nvarchar](max) NOT NULL,
	[Password] [nvarchar](max) NOT NULL,
	[Urole] [nvarchar](max) NOT NULL,
 CONSTRAINT [PK_Users] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  StoredProcedure [dbo].[AddAdministrator]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create proc [dbo].[AddAdministrator]
@AdministratorUserId varchar(100),
@password varchar(100)
as
begin
	Insert into Administrators values(@AdministratorUserId,@password);
end
GO
/****** Object:  StoredProcedure [dbo].[AddSubjects]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE proc [dbo].[AddSubjects]
@SubjectName varchar(100)
as
begin
	Insert into Subjects values(@SubjectName);
end
GO
/****** Object:  StoredProcedure [dbo].[AddTeacher]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create proc [dbo].[AddTeacher]
@teacheruserid varchar(100),
@password varchar(100),
@firstname varchar(100),
@lastname varchar(100),
@Qualification varchar(100),
@SubjectId int,
@email varchar(100),
@HireDate date
as
begin
	Insert into Teachers values (@teacheruserid,@password,@firstname,@lastname,@Qualification,@SubjectId,@email,@HireDate);
end
GO
/****** Object:  StoredProcedure [dbo].[AuthUser]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create proc [dbo].[AuthUser]
@userid varchar(100),
@password varchar(100)
as
	begin
	select * from Users where UserId = @userid and Password= @password;
end
GO
/****** Object:  StoredProcedure [dbo].[DisplayAllUsers]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create proc [dbo].[DisplayAllUsers]
as 
begin
	select * from Users;
end
GO
/****** Object:  StoredProcedure [dbo].[FetchAdministratorByUserId]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create proc [dbo].[FetchAdministratorByUserId]
@AdministratorUserId varchar(100)
as
begin
	select * from Administrators where AdministratorUserId = @AdministratorUserId;
end
GO
/****** Object:  StoredProcedure [dbo].[FetchAllSubjects]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create proc [dbo].[FetchAllSubjects]
as
begin
	Select * from Subjects;
end
GO
/****** Object:  StoredProcedure [dbo].[FetchAllTeachers]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create proc [dbo].[FetchAllTeachers]
as
begin
	select * from teachers
end
GO
/****** Object:  StoredProcedure [dbo].[insertUser]    Script Date: 09-09-2024 01:12:09 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create proc [dbo].[insertUser]
@Userid varchar(100),
@Password varchar(100),
@Urole varchar(100)
as
begin
	Insert into users values(@Userid,@Password,@Urole);
end
GO
USE [master]
GO
ALTER DATABASE [SchoolDb] SET  READ_WRITE 
GO
