# NOTICE — 镜像来源与许可

本仓库是第三方项目的**个人镜像备份**，非原作者发布渠道。

| 项 | 内容 |
|---|---|
| 上游项目 | https://github.com/ardeyouxipianyi/workbuddy2api-hub |
| 原作者 | ardeyouxipianyi |
| 许可证 | MIT（自 2026-09-12 首次发布起未变更，见 `LICENSE`） |
| 镜像版本 | v1.9.0（上游 commit `a6a967e`，2026-10-28） |
| 镜像日期 | 2026-10-28 |
| 镜像方式 | 完整历史 + 全部 tag（90 个） |

## 与本仓库相对上游做的改动

1. **移除了 `.github/workflows/`（含历史提交中的同一路径）**
   原因：推送环境使用的 GitHub OAuth 令牌无 `workflow` scope，无法写入工作流文件；且个人镜像不需要上游 CI。
   影响：不能直接用 GitHub 的「Sync fork」按钮快进同步；更新需重新拉取上游后重放本改动（见下）。

2. **新增本 `NOTICE.md`**，记录来源、版本、许可与改动。

## 如何更新到上游新版

在维护机上运行一键脚本（自动：克隆上游 → 剥 workflows → 补本 NOTICE → 强推本仓库）：

```bash
bash /root/wbhub_mirror_build.sh          # 同步并推送
bash /root/wbhub_mirror_build.sh --dry    # 只构建不推送
```

手动等价步骤：

```bash
git clone https://github.com/ardeyouxipianyi/workbuddy2api-hub.git build
cd build && printf 'y\n' | git filter-repo --path .github/workflows --invert-paths --force
git remote add mirror https://github.com/2451713845/workbuddy2api-hub.git
git push -f mirror HEAD:main --tags
```

注意：因为历史被重写，**不要用 GitHub 的「Sync fork」按钮**（会因 workflow 权限被拒），也不要把本仓库的提交往上游推。

## 免责

本镜像仅供个人学习与自用部署，不对外分发，不提供任何担保。
原作者如对本镜像有异议，删除即可。
