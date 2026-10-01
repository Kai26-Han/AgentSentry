"""离线核对个人任务目录、测试节点和生成的中文任务卡。"""
import argparse
import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agentsentry.learning_assessment import catalog


def render(topic, version):
    number = topic['id']
    normal_file = topic['normal_node'].split('::')[0]
    boundary_file = topic['boundary_node'].split('::')[0]
    return f'''# {number} {topic['title']}：个人验收任务卡

[中文](#) · [English](../../en/learning/assessment/{number}.md)

任务版本：`{version}`。先读[学习章节](../{topic['chapter']})，环境与状态规则见[验收指南](../personal-assessment.md)。

> 本卡由任务目录生成，不直接编辑。新学习者先按[项目安装说明](../../../README.zh-CN.md#快速启动)安装测试依赖，在项目根目录执行以下命令；基础任务无需 Docker 或真实模型。案例中的通过结果不作为你的学习成绩。

## 运行前预测

先在自己的学习目录记录正常与边界实验的决定、实际执行及展示预期，不复制下面的核对提示。说明攻击者可控制什么、哪些事实由网关核验。

```bash
.venv/bin/python -m agentsentry.learning_assessment predict --directory .local/learning-assessment/first-run --topic {number} --normal '填写自己的正常预测' --boundary '填写自己的边界预测'
.venv/bin/python -m agentsentry.learning_assessment run --directory .local/learning-assessment/first-run --topic {number}
```

目录先用指南中的 `init` 初始化。两项预测不会因实验通过而自动补写；重做会保留旧实验及其预测快照。

## 两个实验单元

| 单元 | 固定测试节点 | 操作与事实核对 |
|---|---|---|
| 正常 | `{topic['normal_node']}` | {topic['normal_expectation']} |
| 边界 | `{topic['boundary_node']}` | {topic['boundary_expectation']} |

这是复用已有测试的正常与边界部分；有些节点同时含多个对照，参数化测试保留每个参数结果，不把通过数当作独立安全能力数量。

- **环境**：临时 SQLite、Redis 替身、测试客户端；第 05 章正常项实际启动本地 stdio MCP。离线子进程使用测试凭据与临时策略，不连接云模型、GitHub 或日常数据库。
- **证据位置**：{topic['evidence_location']}
- **必须核对**：{topic['facts']}
- **代码入口**：{topic['code']}
- **副作用与收尾**：只操作临时合成数据。临时库和 JUnit 原文结束清理，保存脱敏计数、版本和固定节点；报告不出现在运行中 Web。中断不能当通过。

源码：[正常测试](../../../{normal_file}) · [边界测试](../../../{boundary_file})。

## 独立解释与变化题

1. **解释任务**：{topic['explanation']}
2. **自检**：{topic['questions']}
3. **变化题**：{topic['variation']}
4. **局限**：先自己写出一条；再与提示对照：{topic['limitation']}

变化题改动只限临时样本或临时文件；先说明预期再运行。未经核对的产品问题记录为问题，不修改正式规则以获得通过。

## 填写与验收

在 `record.json` 的主题 `{number}` 填写 `review.explanation`、`evidence`、`answers`、`variation`、`limitation`、`reviewer`、`reviewed_at`；自评 `personal_status` 为“待学习／待复核／已掌握”。证据用报告相对路径、测试节点和可核对事实；不贴密钥、业务原文或自由回答全文。

完成正常与边界实验、找到事实证据、解释控制位置、完成变化题、说明局限后，才由你或人工复核者声明掌握。工具仅检查材料完整性，不判断答案正确与否。产品实验失败可以保留，同时记录你对缺口的正确解释；两种结论分别复核。
'''


def check(write=False):
    data = catalog()
    ids = [x['id'] for x in data['topics']]
    if ids != [f'{x:02d}' for x in range(1, 16)]:
        raise ValueError('需要 15 个唯一且有序的主题')
    folder = ROOT / 'docs/learning/assessment'
    folder.mkdir(parents=True, exist_ok=True)
    for topic in data['topics']:
        if not (ROOT / 'docs/learning' / topic['chapter']).is_file():
            raise ValueError('学习章节缺失')
        for kind in ('normal', 'boundary'):
            node = topic[kind + '_node']
            path, function = node.split('::')
            if not path.startswith('tests/test_') or Path(path).is_absolute() or '..' in Path(path).parts:
                raise ValueError('测试路径无效')
            tree = ast.parse((ROOT / path).read_text())
            names = [x.name for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if function.split('[')[0] not in names:
                raise ValueError('任务卡测试函数不存在')
        target = folder / (topic['id'] + '.md')
        content = render(topic, data['version'])
        if write: target.write_text(content, encoding='utf-8')
        elif not target.is_file() or target.read_text(encoding='utf-8') != content:
            raise ValueError('生成任务卡与目录不一致')
    return len(ids)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = p.parse_args()
    print(f'个人学习任务校验通过：{check(args.write)} 个主题／30 个实验单元')


if __name__ == '__main__': main()
