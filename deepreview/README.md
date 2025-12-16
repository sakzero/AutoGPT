# DeepReview – Python 代码自动审计引擎

DeepReview 聚合 Git diff、Tree-sitter 语义上下文、静态启发式（ruff/bandit/污点/风格）与 LLM 审计，输出 CI 友好的 JSON、SARIF、Markdown 摘要与运行元数据，可直接在 GitHub Actions 中无人值守地扫描 Python 仓库。

## 快速开始

```bash
uv sync
export NVIDIA_API_KEY=...
uv run python -m deepreview.cli path/to/project \
  --scan-mode standard \
  --metadata-path run_meta.json
```

- CLI 日志末尾会展示 Severity distribution & Top findings
- `--summary-path summary.md` 会生成 Markdown 摘要
- `deepreview_report.json/.sarif` 与 `run_meta.json` 适合上传到 CI

## 自动生成 deepreview.yml

```bash
uv run python -m deepreview.cli . --init-config deepreview.yml
```

- `defaults` 预置 `scan_mode`、`diff_target`、`metadata_path`、`summary_path`、`suppress_patterns`
- `targets` 包含仓库根目录 `.`，并自动发现最多 5 个含 Python 代码的子目录
- 仓库内附带 `deepreview/deepreview.example.yml` 可直接参考

## GitHub Actions 示例

```yaml
name: deepreview
on:
  push:
    branches: [ main ]
  pull_request:
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - run: uv sync
      - name: Ensure deepreview config
        if: ${{ !exists('deepreview.yml') }}
        run: uv run python -m deepreview.cli . --init-config deepreview.yml
      - name: Run DeepReview audit
        env:
          NVIDIA_API_KEY: ${{ secrets.NVIDIA_API_KEY }}
          PYTHONPATH: ${{ github.workspace }}/deepreview/src
        run: |
          mkdir -p artifacts
          uv run python -m deepreview.cli deepreview \
            --scan-mode standard \
            --diff-target origin/main \
            --fail-on-confirmed \
            --metadata-path artifacts/run_meta.json \
            --archive-run artifacts/deepreview-run.zip
      - uses: actions/upload-artifact@v4
        with:
          name: deepreview-artifacts
          path: |
            deepreview_report.json
            deepreview_report.sarif
            artifacts/
            deepreview_runs/
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: deepreview_report.sarif
```

> `PYTHONPATH=${{ github.workspace }}/deepreview/src` 可以直接运行 `deepreview.cli`；如需只扫描子目录可把 `deepreview` 改为目标路径。

## 复现脚本与调试

- 污点分析命中高危链路时会在 `deepreview_runs/<run>/repro_attempts/` 生成最小复现脚本并执行，stdout/stderr 写入 `deepreview_report.json -> reproduction`
- SARIF `properties.reproduction_summary`、run metadata 与 artifacts 可帮助安全团队快速定位可复现风险
- 下载 `deepreview_runs/` 后即可在本地重跑脚本，复现漏洞细节

## 主要特性

- **LLM 结构化审计**：summary/insights/findings 严格输出 JSON，scan-mode 控制数量
- **上下文增强**：Tree-sitter 索引 + diff/snapshot，`--changed-files` 支持增量索引与上下文检索
- **静态信号**：启发式、污点、Radon 风格、ruff/bandit 统一整合
- **复现脚本**：对高危污点链生成/运行脚本，辅助 CI 审计闭环
- **配置驱动**：`--config` + YAML 多目标执行，`--init-config` 一键生成模版

如需扩展其他语言或静态规则，可在 `deepreview/src/deepreview/core/` 对应模块基础上继续开发。
