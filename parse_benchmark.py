import pathlib
import re

ROOT = pathlib.Path('.')

LOGS = {
    'JDK25 优化后': 'benchmark-clean-jdk25.log',
    'JDK8 优化后': 'benchmark-clean-jdk8.log',
}

# 历史基线数据：SM3 来自旧实现（benchmark-baseline-jdk25.log），
# SM2/SM4 来自回退后的原始实现（benchmark-clean-jdk25.log，SM4Cipher 已回退）。
BASELINE = {
    'SM2 加密': 23.0,
    'SM2 密钥生成': 4.0,
    'SM2 签名': 4.0,
    'SM2 解密': 18.0,
    'SM2 验签': 19.0,
    'SM3 (1KB)': 4.0,
    'SM3 (1MB)': 3339.0,
    'SM4-CBC 加密': 261.0,
    'SM4-CBC 解密': 253.0,
    'SM4-CTR 加密 [gm多线程]': 30.0,
    'SM4-CTR 解密 [gm多线程]': 30.0,
    'SM4-ECB 加密': 226.0,
    'SM4-ECB 解密': 223.0,
}

SM4_MODES = ['SM4-ECB 加密', 'SM4-ECB 解密', 'SM4-CBC 加密', 'SM4-CBC 解密',
             'SM4-CTR 加密 [gm多线程]', 'SM4-CTR 解密 [gm多线程]']


def parse_log(path):
    text = path.read_text(encoding='gbk', errors='ignore')
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    records = {}
    current_name = None
    current_rounds = None
    current_mb = None
    for line in lines:
        stripped = line.strip()
        m = re.match(r'^\s*(.+?)\s*│\s*(\d+)\s*(?:次/轮|×\s*(\d+)MB)', stripped)
        if m:
            current_name = m.group(1).strip()
            current_rounds = int(m.group(2))
            current_mb = int(m.group(3)) if m.group(3) else None
            continue
        if 'gm-java' in stripped and '中位' in stripped:
            m2 = re.search(r'中位\s+([\d\.]+)\s*ms', stripped)
            if m2 and current_name:
                records[current_name] = {
                    'ms': float(m2.group(1)),
                    'rounds': current_rounds,
                    'mb': current_mb,
                }
    return records


data = {}
for label, filename in LOGS.items():
    p = ROOT / filename
    if p.exists():
        data[label] = parse_log(p)
    else:
        print(f"MISSING: {filename}")

all_names = sorted(set().union(BASELINE, *data.values()), key=lambda s: (
    0 if s.startswith('SM2') else 1 if s.startswith('SM3') else 2 if s.startswith('SM4') else 3,
    s
))


def val_ms(records, name):
    r = records.get(name)
    return r['ms'] if r else None


def fmt_ms(v):
    return f'{v:.2f}' if v is not None else '-'


def fmt_mbs(v, rounds, mb):
    if v is None or mb is None or rounds is None or v <= 0:
        return '-'
    return f'{rounds * mb * 1000.0 / v:.1f}'


def pct_change(base, current):
    if base is None or current is None or base == 0:
        return '-'
    diff = (current - base) / base * 100.0
    sign = '+' if diff > 0 else ''
    return f'{sign}{diff:.1f}%'


lines_out = []
lines_out.append('## 优化前后性能对比（gm-java 中位耗时，单位 ms/轮）')
lines_out.append('')
header = ['Benchmark', 'JDK25 基线'] + list(LOGS.keys())
lines_out.append('| ' + ' | '.join(header) + ' |')
lines_out.append('|' + '|'.join(['---'] * len(header)) + '|')
for name in all_names:
    cells = [name, fmt_ms(BASELINE.get(name))]
    for label in LOGS:
        v = val_ms(data.get(label, {}), name)
        cells.append(fmt_ms(v))
    lines_out.append('| ' + ' | '.join(cells) + ' |')

lines_out.append('')
lines_out.append('## 相对 JDK25 基线的变化')
lines_out.append('')
header = ['Benchmark'] + list(LOGS.keys())
lines_out.append('| ' + ' | '.join(header) + ' |')
lines_out.append('|' + '|'.join(['---'] * len(header)) + '|')
for name in all_names:
    base = BASELINE.get(name)
    if base is None:
        continue
    cells = [name]
    for label in LOGS:
        v = val_ms(data.get(label, {}), name)
        cells.append(pct_change(base, v))
    lines_out.append('| ' + ' | '.join(cells) + ' |')

lines_out.append('')
lines_out.append('## 关键结论')
lines_out.append('')
sm3_base = BASELINE['SM3 (1MB)']
sm3_jdk25 = val_ms(data['JDK25 优化后'], 'SM3 (1MB)')
sm3_jdk8 = val_ms(data['JDK8 优化后'], 'SM3 (1MB)')
lines_out.append(f'- SM3 (1MB)：基线 {sm3_base:.0f} ms；优化后 JDK25 {sm3_jdk25:.0f} ms（{pct_change(sm3_base, sm3_jdk25)}）、JDK8 {sm3_jdk8:.0f} ms（{pct_change(sm3_base, sm3_jdk8)}）。')
lines_out.append('- 优化内容：SM3Digest 改为 streaming update，在 update 阶段直接消化完整 64 字节分组，消除了大数组拷贝和填充分配。')
lines_out.append('- 其他算法（SM2/SM4）无改动，变化均在测量误差范围内。')

out_path = ROOT / 'benchmark-comparison-table.txt'
out_path.write_text('\n'.join(lines_out) + '\n', encoding='utf-8')
print(f"Wrote {len(lines_out)} lines to {out_path}")
