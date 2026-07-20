# Third-Party Notices

Dumplings.PackageModule is distributed primarily under Apache-2.0. The
components and source-derived portions below retain their stated licenses and
attribution requirements. File-level SPDX headers take precedence over the
repository default for the files they accompany.

## Windows Package Manager (winget-cli)

Source: <https://github.com/microsoft/winget-cli>

The native call sequence in `Assets/Source/WinGet/WinGetDownloadProbe.cs` follows the MIT-licensed
`Downloader.cpp` and `DODownloader.cpp` implementations.

The vendored files in `Assets/Schemas/WinGetManifest` are the official manifest JSON
schemas. The PowerShell manifest validator follows the MIT-licensed
`YamlParser.cpp`, `ManifestSchemaValidation.cpp`, `ManifestYamlPopulator.cpp`,
`ManifestValidation.cpp`, `ManifestCommon.cpp`, `MsiExecArguments.cpp`, and `Locale.cpp`
implementations.

Copyright (c) Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## WiX Toolset DTF 3.14.1

Corresponding source: <https://github.com/wixtoolset/wix3/tree/wix3141rtm/src/DTF>

The following assemblies are distributed from WiX Toolset 3.14.1:

- `Assets/Assemblies/Microsoft.Deployment.Compression.Cab.dll`
- `Assets/Assemblies/Microsoft.Deployment.Compression.dll`
- `Assets/Assemblies/Microsoft.Deployment.WindowsInstaller.dll`
- `Assets/Assemblies/Microsoft.Deployment.WindowsInstaller.Package.dll`

Copyright (c) .NET Foundation and contributors.

This software is released under the Microsoft Reciprocal License (MS-RL) (the
"License"); you may not use the software except in compliance with the License.

Microsoft Reciprocal License (MS-RL)

This license governs use of the accompanying software. If you use the
software, you accept this license. If you do not accept the license, do not
use the software.

1. Definitions

The terms "reproduce," "reproduction," "derivative works," and
"distribution" have the same meaning here as under U.S. copyright law.

A "contribution" is the original software, or any additions or changes to the
software.

A "contributor" is any person that distributes its contribution under this
license.

"Licensed patents" are a contributor's patent claims that read directly on
its contribution.

2. Grant of Rights

(A) Copyright Grant - Subject to the terms of this license, including the
license conditions and limitations in section 3, each contributor grants you
a non-exclusive, worldwide, royalty-free copyright license to reproduce its
contribution, prepare derivative works of its contribution, and distribute its
contribution or any derivative works that you create.

(B) Patent Grant - Subject to the terms of this license, including the license
conditions and limitations in section 3, each contributor grants you a
non-exclusive, worldwide, royalty-free license under its licensed patents to
make, have made, use, sell, offer for sale, import, and/or otherwise dispose of
its contribution in the software or derivative works of the contribution in
the software.

3. Conditions and Limitations

(A) Reciprocal Grants - For any file you distribute that contains code from
the software (in source code or binary format), you must provide recipients
the source code to that file along with a copy of this license, which license
will govern that file. You may license other files that are entirely your own
work and do not contain code from the software under any terms you choose.

(B) No Trademark License - This license does not grant you rights to use any
contributors' name, logo, or trademarks.

(C) If you bring a patent claim against any contributor over patents that you
claim are infringed by the software, your patent license from such contributor
to the software ends automatically.

(D) If you distribute any portion of the software, you must retain all
copyright, patent, trademark, and attribution notices that are present in the
software.

(E) If you distribute any portion of the software in source code form, you may
do so only under this license by including a complete copy of this license
with your distribution. If you distribute any portion of the software in
compiled or object code form, you may only do so under a license that complies
with this license.

(F) The software is licensed "as-is." You bear the risk of using it. The
contributors give no express warranties, guarantees or conditions. You may
have additional consumer rights under your local laws which this license
cannot change. To the extent permitted under your local laws, the contributors
exclude the implied warranties of merchantability, fitness for a particular
purpose and non-infringement.

## Selenium WebDriver .NET 4.0.0

Source: <https://github.com/SeleniumHQ/selenium/tree/selenium-4.0.0>

`Assets/Assemblies/WebDriver.dll` is licensed under Apache-2.0. The complete
license text is included in the PackageModule `LICENSE` file.

Copyright 2011-2021 Software Freedom Conservancy

Copyright 2004-2011 Selenium committers

## Patchright for .NET 1.61.0

Sources:

- <https://github.com/DevEnterpriseSoftware/patchright-dotnet/tree/v1.61.0>
- <https://github.com/Kaliiiiiiiiii-Vinyzu/patchright/tree/v1.61.0>
- <https://github.com/microsoft/playwright-dotnet/tree/v1.61.0>

The runtime restored from the official `Patchright` NuGet package is licensed
under Apache-2.0. It is stored in the local or GitHub Actions cache and is not
committed to this repository. Package and driver license/notice files are
retained beside the cached runtime. Patchright's modifications are Apache-2.0;
it is an API-compatible derivative of MIT-licensed Microsoft Playwright and
retains the upstream notices.

## Scrapling

Source: <https://github.com/D4Vinci/Scrapling>

Scrapling's BSD-3-Clause `StealthyFetcher` is a behavioral reference for the
Patchright-backed PowerShell workflow. Scrapling code is not bundled or copied;
the implementation uses the documented Playwright/Patchright APIs directly.

## SharpCompress 0.39.0

Source: <https://github.com/adamhathcock/sharpcompress>

Copyright (c) 2014 Adam Hathcock

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## Gentee 3.6.1 GEA/LZGE

Source: <https://www.gentee.com/download/gentee3.6.1.zip>

The `Assets/Source/CreateInstall/GenteeLzgeDecoder.cs` implementation is an MIT-licensed adaptation of
the GEA archive and LZGE/Huffman decoder sources distributed with Gentee.

Copyright (c) 2006-2009 The Gentee Group. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## SharpCompress.Gentee / pyppmd-gentee 1.4.0

Source: <https://github.com/puigru/pyppmd-gentee>

The source-shipped `Assets/Providers/SharpCompress.Gentee` managed companion provider
uses SharpCompress 0.39.0's MIT-licensed PPMd-I object model and Gentee variant
behavior from pyppmd-gentee at commit
`a6e4dbcf8b600664c4b8ff47ec090e42588f9f14`. It is dynamically loaded as a
separate AnyCPU assembly and distributed under LGPL-2.1-or-later. Its complete
corresponding C# source and reproducible build instructions are included beside
the binary. The standard `SharpCompress.dll` remains unmodified.

Copyright (C) 2020-2021 Hiroshi Miura
Copyright (C) 2026 Joel Puig Rubio

The complete GNU Lesser General Public License version 2.1 is available in
`Assets/Providers/SharpCompress.Gentee/LICENSE` and at <https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html>.

## ZstdSharp.Port 0.8.4

Source: <https://github.com/oleg-st/ZstdSharp>

Copyright Oleg Stepanischev 2024

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
