# 共同学习与贡献

[中文](#) · [English](CONTRIBUTING.en.md)

[项目首页](README.zh-CN.md) · [学习手册](docs/learning/README.md)

欢迎提交文档修正、翻译、合成攻击样本、正常对照、复现报告和防护改进。项目定位是学习实验平台，结论应限于有证据的样本与接入路径。

## 从一个小问题开始

1. 选择一个安全主题，先运行它的正常和边界实验。
2. 说明预期与实测差异，找到对应代码和证据。
3. 文档改动核对链接与命令；规则或实现改动提供相关攻击与正常对照回归。
4. 提交时注明改动、原因、验证方式和剩余限制。没有运行的项目写“未执行”，不要用已有案例的结果代替本次运行。

请使用自己的分支与学习记录。基础安装见 README；离线测试环境见[手册前置条件](docs/learning/README.md#前置条件与命令约定)。不需要为文档贡献配置云模型或第三方凭据。

## 怎样报告一个问题

```text
环境：操作系统、Python、项目提交或文件版本
范围：离线 / 本机网关 / 本地模型 / 第三方接入
复现：最少命令，样本库版本 + 样本 ID
预期：该控制应保护什么
事实：决定、实际副作用、草稿、实际展示，分别记录
证据：脱敏报告或固定测试节点
限制：未尝试、待审批、unknown、环境故障、未测路径
```

不要附 `.env`、PAT、管理员密码、授权令牌、Cookie、`.local/` 凭据文件或日常业务原文。截图也要核对一次性令牌和展开的原始参数；仅删除字段名不构成脱敏。复现优先用合成数据和临时租户，不扫描未授权目标，不在他人仓库写入。

发现可能涉及真实凭据或可利用漏洞时，先移除敏感材料并联系维护者约定私下复核方式；不要在公开 Issue 贴秘密或真实业务攻击轨迹。

## 文档与生成关系

| 文件 | 维护方法 |
| --- | --- |
| 当前总纲、架构、学习章节 | 直接编辑，更新与实现和证据相关的引用 |
| `docs/threat-framework-map.yaml` | 结构化矩阵源数据；改后运行映射生成与校验 |
| `docs/threat-framework-mapping.md` | 生成文档，不直接修改 |
| `src/agentsentry/learning_tasks.json` | 任务卡内容与固定节点源数据 |
| `scripts/check_learning_assessment.py` | 任务卡公共版式；改后重新生成 |
| `docs/learning/assessment/*.md` | 生成任务卡，不直接修改 |
| 进阶案例 | 按安全问题说明原因、控制、前后事实与局限；注明实验模式、日期、样本与规则版本 |

```bash
.venv/bin/python scripts/check_threat_mapping.py --write
.venv/bin/python scripts/check_threat_mapping.py --check
.venv/bin/python scripts/check_learning_assessment.py --write
.venv/bin/python scripts/check_learning_assessment.py --check
```

只在修改相应源数据或版式后使用 `--write`。具体测试入口见 [README](README.zh-CN.md#回归检查)与[实验索引](docs/learning/experiment-index.md)。界面翻译目录和维护约定见[语言说明](docs/web-language.md)。

## 安全改动的证据要求

- 区分固定提案检验边界与真实模型检验行为。
- 草稿污染与实际展示污染分开；合法副作用与禁止副作用分开。
- 身份、跨租户、凭据和执行前审计失败等边界不能为提高小样本成绩而放宽。
- 规则阈值改变需记录基线、建议、人工决定及保留集表现；不自动发布或自动批准攻击。
- 来源关联、签名和框架映射均不能证明内容真实或某类风险已全面解决。

目前尚未提供 `LICENSE`，不要自行推定开源授权或替维护者添加未经选择的许可。发布准备见[公开分享说明](docs/public-sharing.md)。

## 中英文文档维护

中文 README 为 `README.zh-CN.md`，其余中文文档保持原路径；英文默认入口为 `README.md`、`PROJECT-PLAN.en.md` 和 `CONTRIBUTING.en.md`；英文专题、手册和案例集中在 `docs/en/`，正文不交错排版。新增或修改文档时请同步对应版本及语言链接。命令、接口、样本 ID 和证据版本保持一致；原始样本、数据与命令行枚举不因文档翻译改写。

英文任务卡和矩阵分别由 `docs/en/learning/task-translations.json`、`docs/en/threat-translations.json` 结合中文的规范数据生成。规范数据变化后需人工核对翻译并更新源文件摘要，不能只刷新摘要而不复核。英文表述不改变运行时映射条件。

```bash
.venv/bin/python scripts/check_english_docs.py --write
.venv/bin/python scripts/check_english_docs.py --check
```

校验覆盖英文对应文件、语言导航、文件／锚点、代码与测试节点，以及生成内容一致性；安全 CI 同步执行。
