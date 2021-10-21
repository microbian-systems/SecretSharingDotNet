# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2021-10-07
### Added
- Introduced a new return type for the split method 'MakeShares'
- Added CLI building instructions in README.md

### Changed
- Updated examples in README.md based on the new return type for the split method
- Updated xUnit package references in CSharp projects 
- Updated Microsoft Test SDK package references in CSharp projects
- Updated Mircosoft .NET FX reference assemblies package references in CSharp projects

### Deprecated
- The tuple return type for the split method 'MakeShares' is obsolete

### Fixed
- Fixed CI version dependency
- Fixed code quality issues in CSharp code
- Fixed spelling mistakes in README.md
- Fixed .NET 5 solution filename in README.md
- Added missing target framework .NET 5 to SecretSharingDotNetTest.csproj 

## [0.4.2] - 2020-12-18
### Fixed
- Fixed wrong NuGet package version

## [0.4.1] - 2020-12-18
### Fixed
- NuGet build environment modified to build for .NET 5.0

## [0.4.0] - 2020-12-18
### Added
- Added .NET 5.0 support

### Fixed
- Fixed bug 40 (_Maximum exceeded!_) reported [@varshadqz](https://github.com/shinji-san/SecretSharingDotNet/issues/40)

## [0.3.0] - 2020-04-19
### Added
- Added .NET FX 4.6 support
- Added .NET FX 4.6.1 support
- Added .NET FX 4.6.2 support
- Added .NET FX 4.7 support
- Added .NET FX 4.7.1 support
- Added .NET FX 4.7.2 support
- Added .NET FX 4.8 support
- Added .NET Standard 2.1 support

### Changed
- README.md: Extend build & test status corresponding to the .NET versions

## [0.2.0] - 2020-04-12
### Added
- Addded full .NET Core 3.1 support

## [0.1.1] - 2020-04-11
### Fixed
- Fixed wrong NuGet package version

## [0.1.0] - 2020-04-11
### Added
- Added initial verion of SecretSharingDotNet
- Added .NET FX 4.5.2 support
- Added .NET Core 2.1 support
- Added limited .NET Core 3.1 support
- Added GitHub issue template
- Added CODE_OF_CONDUCT.md
- Added LICENSE.md
- Added README.md

[Unreleased]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/shinji-san/SecretSharingDotNet/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/shinji-san/SecretSharingDotNet/releases/tag/v0.1.0