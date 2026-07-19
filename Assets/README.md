# PackageModule Assets

PackageModule's default license is Apache-2.0. Assemblies, providers, mirrored
MIT infrastructure, and source-derived components retain the licenses stated
in their file headers and `THIRD-PARTY-NOTICES.md`.

Runtime assets are grouped by purpose:

- `Assemblies`: pinned third-party managed assemblies loaded by PackageModule.
- `Providers`: independently licensed companion providers with their complete source and license.
- `Schemas`: vendored, offline validation schemas.
- `Source`: auditable C# compiled in process with `Add-Type`, grouped by subsystem.
- `THIRD-PARTY-NOTICES.md`: source attribution and redistributed dependency licenses.

Pester files belong in `..\Tests`; do not place executable tests in this directory.
Load assets through their owning PowerShell module rather than relying on recursive discovery.
