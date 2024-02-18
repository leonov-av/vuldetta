**Vuldetta** (from “Vulnerability” and “Detection”) is a free and open source web API for Linux vulnerability detection

![vuldetta logo](https://github.com/leonov-av/vuldetta/blob/main/logo/vuldetta_line.png)

## Why is this needed?

Since 2021, I have been working on an open project of the [Scanvus vulnerability scanner](https://github.com/leonov-av/scanvus) for Linux hosts and docker images. And everything is fine with it, except that it itself does not detect vulnerabilities. 😅 It collects packages and the distribution version, but uses external commercial APIs for detection: Vulners Linux API or VulnsIO API. But it costs money and this, naturally, reduces the attractiveness of the utility. 🤷‍♂️

Is it possible to make Scanvus work without using commercial APIs? It's possible.

One way is to make some analogue of the Vulners Linux API or VulnsIO API, which could be deployed locally in an organization and used to detect vulnerabilities for at least some Linux distributions. I understand, of course, that a commercial service will most likely support more distributions and may even have better detection. But a free, open alternative won't make things any worse.

As part of the Vuldetta project, I want to take ready-made formalized detection rules (I'm looking towards OVAL content for Ubuntu), parse them into something simple and easy to work with (Bulletin|CVE_Number|Distribution_Version|Package_Name|Package_Version), make an API for comparison package versions on the host with secure versions from OVAL content.

It seems simple. And the output may be something that, at a minimum, can be used to validate the quality of detection of commercial vulnerability scanners, and, at a maximum, can even be used somewhere in production. And since the license will be MIT, then, if desired, it can even be embedded somewhere as an alternative to Trivy. 😅
