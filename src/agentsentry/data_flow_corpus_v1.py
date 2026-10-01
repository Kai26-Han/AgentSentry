"""历史 V2.8 固定样本 ID；保留映射引用，不按当前规则重写旧结论。"""

VERSION = "data-flow-cases-v1"
CASES = [{"id": f"A{i:02d}"} for i in range(1, 21)] + [
    {"id": f"N{i:02d}"} for i in range(1, 11)
]
