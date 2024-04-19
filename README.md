# Control-M MFT Demo

Basic workflows for Control-M MAnaged File Transfer

These modules are for **educational** purposes.

## Core workflows and purpose

| Type | Name | Description |
| :---- | :---- | :---- |
| Folder | [AWS](src/jobs/zzm.uc.aws.json) | MFT with AWS Access |
| Folder | [Azure](src/jobs/zzm.uc.azure.json) | MFT with Azure Access |
| Folder | [GCS](src/jobs/zzm.uc.gcs.json) | MFT with Google Cloud Storage Access |
| Folder | [Multipath](src/jobs/zzm.uc.multipath.cloud.json) | MFT with AWS, Azure, GCS Access - parallel |
| Folder | [Multistep](src/jobs/zzm.uc.multistep.cloud.json) | MFT with AWS, Azure, GCS Access - sequential |
| Folder | [Watch Only](src/jobs/zzm.uc.wnly.json) | MFT Watch Only for file |
| Folder | [Watch Only Helper](src/jobs/zzm.uc.wnly.hlpr.json) | MFT Watch Only, Helper flow to create missing file |
| CCP | [AWS](src/ccp/zzm.aws.s3.json) | MFT with AWS Access |
| CCP | [Azure](src/ccp/zzm.azure.json) | MFT with Azure Access |
| CCP | [GCS](src/ccp/zzm.gcs.json) | MFT with Google Cloud Storage Access |
| CCP | [Local](src/ccp/zzm.lfs.json) | MFT with Local File System Access |
| CCP | [SFTP](src/ccp/zzm.lfs.json) | MFT with SFTP Agent 1 Access |
| CCP | [SFTP](src/ccp/zzm.lfs.json) | MFT with SFTP Agent 2 Access |



## License

**(c) 2024 Orch3strator**

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice (including the next paragraph) shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

https://opensource.org/license/GPL-2.0


### SPDX-License-Identifier: GPL-2.0
For information on SDPX, https://spdx.org/licenses/GPL-2.0.html
