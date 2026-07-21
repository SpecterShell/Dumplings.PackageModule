# SPDX-License-Identifier: Apache-2.0

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..\Libraries\SourceIdentity.psm1') -Force
}

Describe 'Get-InstallerSourceIdentity' {
  It 'extracts GitHub owner/repo identities' {
    Get-InstallerSourceIdentity -Uri 'https://github.com/example/repo/releases/download/v1/app.exe' | Should -Be 'github.com/example/repo'
  }

  It 'extracts GitLab nested namespace identities' {
    Get-InstallerSourceIdentity -Uri 'https://gitlab.example/group/subgroup/project/-/releases/v1/downloads/app.exe' | Should -Be 'gitlab.example/group/subgroup/project'
  }

  It 'extracts SourceForge project identities' {
    Get-InstallerSourceIdentity -Uri 'https://sourceforge.net/projects/sevenzip/files/7z.exe/download' | Should -Be 'sourceforge.net/projects/sevenzip'
  }

  It 'extracts S3 path-style bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://s3.amazonaws.com/example-bucket/releases/app.exe' | Should -Be 's3.amazonaws.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://s3.us-west-2.amazonaws.com/example-bucket/releases/app.exe' | Should -Be 's3.us-west-2.amazonaws.com/bucket/example-bucket'
  }

  It 'extracts S3 virtual-hosted bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.s3.amazonaws.com/releases/app.exe' | Should -Be 's3.amazonaws.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.s3-us-west-2.amazonaws.com/releases/app.exe' | Should -Be 's3-us-west-2.amazonaws.com/bucket/example-bucket'
  }

  It 'extracts Google Cloud Storage bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://storage.googleapis.com/example-bucket/releases/app.exe' | Should -Be 'storage.googleapis.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.storage.googleapis.com/releases/app.exe' | Should -Be 'storage.googleapis.com/bucket/example-bucket'
  }

  It 'extracts DigitalOcean Spaces and Cloudflare R2 bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.nyc3.digitaloceanspaces.com/releases/app.exe' | Should -Be 'nyc3.digitaloceanspaces.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://1234567890abcdef.r2.cloudflarestorage.com/example-bucket/releases/app.exe' | Should -Be '1234567890abcdef.r2.cloudflarestorage.com/bucket/example-bucket'
  }

  It 'extracts Alibaba OSS bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://oss-cn-hangzhou.aliyuncs.com/example-bucket/releases/app.exe' | Should -Be 'oss-cn-hangzhou.aliyuncs.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://cn-hangzhou.oss.aliyuncs.com/example-bucket/releases/app.exe' | Should -Be 'cn-hangzhou.oss.aliyuncs.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://s3.oss-cn-hangzhou.aliyuncs.com/example-bucket/releases/app.exe' | Should -Be 's3.oss-cn-hangzhou.aliyuncs.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.oss-cn-hangzhou.aliyuncs.com/releases/app.exe' | Should -Be 'oss-cn-hangzhou.aliyuncs.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.cn-hangzhou.oss.aliyuncs.com/releases/app.exe' | Should -Be 'cn-hangzhou.oss.aliyuncs.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.s3.oss-cn-hangzhou.aliyuncs.com/releases/app.exe' | Should -Be 's3.oss-cn-hangzhou.aliyuncs.com/bucket/example-bucket'
  }

  It 'extracts Tencent COS bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://cos.ap-guangzhou.myqcloud.com/example-1250000000/releases/app.exe' | Should -Be 'cos.ap-guangzhou.myqcloud.com/bucket/example-1250000000'
    Get-InstallerSourceIdentity -Uri 'https://example-1250000000.cos.ap-guangzhou.myqcloud.com/releases/app.exe' | Should -Be 'cos.ap-guangzhou.myqcloud.com/bucket/example-1250000000'
    Get-InstallerSourceIdentity -Uri 'https://example-1250000000.cos.ap-guangzhou.tencentcos.cn/releases/app.exe' | Should -Be 'cos.ap-guangzhou.tencentcos.cn/bucket/example-1250000000'
  }

  It 'extracts Huawei OBS bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://obs.cn-east-3.myhuaweicloud.com/example-bucket/releases/app.exe' | Should -Be 'obs.cn-east-3.myhuaweicloud.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.obs.cn-east-3.myhuaweicloud.com/releases/app.exe' | Should -Be 'obs.cn-east-3.myhuaweicloud.com/bucket/example-bucket'
  }

  It 'extracts generic S3-compatible bucket identities for known providers' {
    Get-InstallerSourceIdentity -Uri 'https://s3.us-west-1.wasabisys.com/example-bucket/releases/app.exe' | Should -Be 's3.us-west-1.wasabisys.com/bucket/example-bucket'
    Get-InstallerSourceIdentity -Uri 'https://example-bucket.eu-central-1.linodeobjects.com/releases/app.exe' | Should -Be 'eu-central-1.linodeobjects.com/bucket/example-bucket'
  }

  It 'extracts provider-hinted S3-compatible bucket identities' {
    Get-InstallerSourceIdentity -Uri 'https://bucket.s3.fra1.leviia.com/releases/app.exe' | Should -Be 's3.fra1.leviia.com/bucket/bucket'
    Get-InstallerSourceIdentity -Uri 'https://s3.filelu.com/example-bucket/releases/app.exe' | Should -Be 's3.filelu.com/bucket/example-bucket'
  }

  It 'extracts Azure Blob account and container identities' {
    Get-InstallerSourceIdentity -Uri 'https://mystorage.blob.core.windows.net/mycontainer/releases/app.exe' | Should -Be 'mystorage.blob.core.windows.net/container/mycontainer'
    Get-InstallerSourceIdentity -Uri 'https://govstorage.blob.core.usgovcloudapi.net/mycontainer/releases/app.exe' | Should -Be 'govstorage.blob.core.usgovcloudapi.net/container/mycontainer'
    Get-InstallerSourceIdentity -Uri 'https://chinastorage.blob.core.chinacloudapi.cn/mycontainer/releases/app.exe' | Should -Be 'chinastorage.blob.core.chinacloudapi.cn/container/mycontainer'
    Get-InstallerSourceIdentity -Uri 'https://mystorage.z21.blob.storage.azure.net/mycontainer/releases/app.exe' | Should -Be 'mystorage.z21.blob.storage.azure.net/container/mycontainer'
    Get-InstallerSourceIdentity -Uri 'https://mystorage.blob.core.windows.net/releases/app.exe' | Should -Be 'mystorage.blob.core.windows.net/container/releases'
  }

  It 'falls back to the plain host for other URLs' {
    Get-InstallerSourceIdentity -Uri 'https://example.com/releases/app.exe' | Should -Be 'example.com'
    Get-InstallerSourceIdentity -Uri 'https://gitee.com/vendor/project/releases/download/v1/app.exe' | Should -Be 'gitee.com/vendor/project'
  }

  It 'returns null for unparseable URLs' {
    Get-InstallerSourceIdentity -Uri 'not a url' | Should -BeNullOrEmpty
  }
}
