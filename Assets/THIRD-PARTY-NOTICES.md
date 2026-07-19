# Third-Party Notices

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
