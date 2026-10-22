# wrt/ — OpenWrt 打包配方

这里放 CodeArts2API-Hub 的 OpenWrt 安装包配方。配方本身来自
[#190](https://github.com/ardeyouxipianyi/workbuddy2api-hub/issues/190) 引用的
`aodianjun/workbuddy2api-hub/wrt/`，逐项审计后并入本仓库，**只保留打包与运行
需要的东西**（审计结论见文末）。

## 内容

```
wrt/
├── README.md                      # 本文件
└── openwrt/
    ├── build-ipk.sh               # 打包 .ipk（opkg 系，OpenWrt <= 24.10），不需要 SDK
    ├── build-apk.sh               # 打包 .apk（apk-tools 3，OpenWrt 25.x），需要 OpenWrt SDK
    └── codearts2api/
        ├── Makefile               # 包定义（PKG_VERSION / PKG_RELEASE / 依赖 / postinst ...）
        └── files/                 # init.d、uci 配置、面板缓存预热脚本
```

两种包的内容一致：`ca_*.py` + `dashboard.html`（纯 Python 标准库）+
`/etc/init.d/codearts2api` + `/etc/config/codearts2api` + `/usr/bin/codearts2api-warm`。

| 产物 | 适用系统 | 安装方式 |
| --- | --- | --- |
| `codearts2api_<版本>-<发布号>_all.ipk` | opkg 系（OpenWrt 24.10 及更早） | `opkg install <文件>` |
| `codearts2api-<版本>-r<发布号>.apk` | apk-tools 3（OpenWrt 25.x） | `apk add --allow-untrusted <文件>`（未签名时） |

依赖（两套系统同名）：`python3-light`、`python3-urllib`、`python3-uuid`。

## 与发布的关系

仓库不使用 GitHub Actions（`.github/workflows/` 已于 2026-10-22 整体移除），
所以 `.ipk` / `.apk` 改为**本地构建后手工上传**到 GitHub Release：打 `v*` tag 前
先跑 `python tests/run_all.py`，再用本目录的两个脚本出包。

本目录的两个脚本自包含（脚本内嵌打包器并自检），不依赖任何 CI 步骤，也不从
网络拉源码：`--app-src` 不给时默认用当前仓库检出；以前 CI 传的是
`$GITHUB_WORKSPACE`，现在就是 `"$PWD"`。

## 本地构建

```sh
# .ipk：任意 POSIX sh + python3 即可，不需要 SDK（脚本内嵌打包器并自检）
sh wrt/openwrt/build-ipk.sh --app-src "$PWD"      # 产物在 wrt/ipk/

# .apk：需要 OpenWrt 25.x 的 x86_64 SDK（glibc 宿主机）
sh wrt/openwrt/build-apk.sh <SDK 目录> "$PWD"     # 产物在 wrt/apk/
```

## 升级版本

只改一处：`wrt/openwrt/codearts2api/Makefile` 的 `PKG_VERSION`（需要时
`PKG_RELEASE`）。两个脚本都会把源码 `ca_proxy.py` 的 `server_version` 与
`PKG_VERSION` 比对，不一致就拒绝出包——宁可不发，也不发一个版本号对不上的包。
以前 `release.yml` 的 version job 还会把 tag 一起比对，那份工作流已删除，
**打 tag 前请自己把 tag 与这两处对一遍**（`server_version` 的两处一致性仍由
`tests/_test_release_engineering.py` 钉住）。

## 数据目录与持久化

- 程序文件在 `/usr/lib/codearts2api`，升级时整体替换；
- 账号凭据与用量在 `/etc/codearts2api/`（`postinst` 会把它加进
  `/etc/sysupgrade.conf`，系统升级不丢）；
- 配置在 `/etc/config/codearts2api`（`conffiles`，权限 600）；
- 首次安装不自动启用服务：`uci set codearts2api.main.panel_password='...'`、
  `uci commit`，再 `enable` + `start`。

`postinst` 只装一条 cron：`codearts2api-warm` 每 2 分钟预热面板的统计缓存
（`uci main.warm=0` 可关），服务每次启动后也会在后台先预热一轮。init.d 把
`WB_STATS_TTL` 默认调到 900 秒，配合预热器让面板点开即出数；这两个默认值是
配套的，改一个要一起看。

## 审计结论（相对 #190 的参考配方）

保留：`.ipk`/`.apk` 两个打包脚本、包 Makefile、init.d、uci 配置、缓存预热脚本，
以及 `.ipk` 的可复现构建约定（GNU tar + `SOURCE_DATE_EPOCH`，同一份源码逐字节相同）。

去掉：

- **`files/usr/bin/codearts2api-update` 及其 cron / `auto_update` 选项**：那是
  fork 自带的 GitHub 自更新器，属于 #190 里的 fork 专属自动化，本 issue 明确
  不引入；OpenWrt 安装本来就走包管理器升级（#29 也把包管理器安装排除在自更新
  之外）。去掉后 `postrm` 只清 `codearts2api-warm`。
- **`wrt/ci/activate-workflows.py` 与 `wrt-sync-upstream.yml`**：fork 用来把
  工作流塞进 `.github/workflows/` 和每天 merge 上游的机制，与本仓库无关。
- **`PIN_SHA` / `PIN_VER` 钉死上游 commit**：配方进入上游仓库后，"从 GitHub 拉
  另一个 commit 的上游源码"没有意义，版本改为直接取自当前检出的 `ca_proxy.py`。
- `PKG_MAINTAINER` 由 `aodianjun` 改回仓库维护者。
