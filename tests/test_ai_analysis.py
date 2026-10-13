"""AI 旁路分析算法测试（迭代 49 · AI 能力规划 P0-2/P0-3）。

覆盖：
  A. DGA 检测
     1. 正常域名全部低于阈值（零误报）；
     2. 明确 DGA 样本全部高于阈值（召回）；
     3. 证据结构完整可解释（contributions/threshold/特征原值）；
     4. 主标签与父域提取边界（子域/单标签/空值）；
     5. bigram 语言模型对正常/异常词的区分。
  B. 隧道检测
     6. 正常业务场景低分；
     7. 典型隧道（海量长随机子域 + TXT）高分；
     8. 证据结构完整（查询数/平均长度/类型分布）；
     9. 空输入安全返回。

纯算法测试：无 DB、无网络依赖。

运行：cd platform && python -m pytest ../tests/test_ai_analysis.py -v
"""

import random
import string

import pytest

import ai_analysis as A


# ---------------------------------------------------------------------------
# A. DGA 检测
# ---------------------------------------------------------------------------

NORMAL_DOMAINS = [
    "google.com", "baidu.com", "taobao.com", "github.com", "mail.example.com",
    "www.shopify.com", "static.cdn.example.com", "cloud.tencent.com",
    "login.microsoftonline.com", "news.sina.com.cn", "img.alicdn.com",
    "video.bilibili.com", "docs.python.org", "help.aliyun.com",
    "portal.office.com", "account.apple.com", "update.microsoft.com",
    "payment.taobao.com", "map.baidu.com", "search.jd.com",
]

# 明确 DGA 样本（随机字符/键盘序主标签，实测得分 > 0.60）
DGA_DOMAINS = [
    "xj3k9d2mz7qp.icu", "mx7bq2v9n4kd.sbs", "fwjvbqkzxmnrpl.shop",
    "ylc5n8wq3tbv7m.online", "dfghjklzxcvbnm.site", "p9k3m7x2v5q8z4.icu",
    "a1b2c3d4e5f6g7h8.top", "n7m3k9x2v5q8.cyou", "vlkqjwpxmnzh.sbs",
]


class TestDga:
    def test_normal_domains_below_threshold(self):
        """正常域名零误报——这是硬要求（AI 只出建议，但噪音越低越好）。"""
        for d in NORMAL_DOMAINS:
            score, _ = A.dga_score(d)
            assert score < A.DGA_THRESHOLD, f"{d} 误报 score={score}"

    def test_dga_samples_above_threshold(self):
        """明确 DGA 样本应被识别（召回）。"""
        missed = []
        for d in DGA_DOMAINS:
            score, _ = A.dga_score(d)
            if score < A.DGA_THRESHOLD:
                missed.append((d, score))
        assert not missed, f"漏检：{missed}"

    def test_evidence_is_explainable(self):
        """证据须可解释：含各特征原值与贡献分。"""
        score, ev = A.dga_score("xj3k9d2mz7qp.icu")
        assert 0 < score <= 1
        for k in ("label", "len", "digit_ratio", "entropy", "consonant_run",
                  "vowel_ratio", "bigram_logprob", "contributions", "threshold"):
            assert k in ev, f"证据缺字段 {k}"
        assert set(ev["contributions"]) == {
            "len", "digit", "entropy", "consonant", "vowel", "bigram"}
        assert ev["threshold"] == A.DGA_THRESHOLD
        # 贡献分求和应等于总分（可解释性：分数来自哪里一目了然）
        assert abs(sum(ev["contributions"].values()) - score) < 0.01

    def test_label_extraction(self):
        assert A.label_of("a.b.example.com") == "example"
        assert A.label_of("example.com") == "example"
        assert A.label_of("single") == "single"
        assert A.label_of("") == ""

    def test_registrable_parent(self):
        assert A.registrable_parent("a.b.example.com") == "example.com"
        assert A.registrable_parent("example.com") == "example.com"
        assert A.registrable_parent("evil-c2.top") == "evil-c2.top"

    def test_empty_and_single_label_safe(self):
        assert A.dga_score("")[0] == 0.0
        assert A.dga_score("localhost")[0] >= 0.0

    def test_bigram_discriminates(self):
        """正常词的 bigram 对数概率应显著高于随机串。"""
        assert A.bigram_logprob("google") > A.bigram_logprob("kq3vz8xw2m")
        assert A.bigram_logprob("") < -10        # 空标签安全返回极低值


# ---------------------------------------------------------------------------
# B. DNS 隧道检测
# ---------------------------------------------------------------------------


class TestTunnel:
    def test_normal_scenarios_low(self):
        cases = [
            (["www.example.com", "mail.example.com", "api.example.com"], ["A"] * 3),
            (["www.baidu.com"] * 5, ["A"] * 5),
        ]
        for subs, qts in cases:
            score, _ = A.tunnel_score(subs, qts)
            assert score < A.TUNNEL_THRESHOLD, f"误报 {subs[:2]} score={score}"

    def test_classic_tunnel_high(self):
        """海量超长随机子域 + TXT——典型 DNS 隧道特征。"""
        random.seed(7)
        subs = ["".join(random.choices(string.ascii_lowercase + string.digits,
                                       k=45)) + ".evil-c2.com"
                for _ in range(150)]
        score, ev = A.tunnel_score(subs, ["TXT"] * 150)
        assert score >= A.TUNNEL_THRESHOLD, f"隧道漏检 score={score}"
        assert score > 0.9
        assert ev["abnormal_type_ratio"] == 1.0
        assert ev["unique_prefixes"] == 150

    def test_mixed_tunnel_medium(self):
        """中等规模隧道（30 长随机子域 + 半 TXT）也应在阈值上。"""
        random.seed(11)
        subs = ["".join(random.choices(string.ascii_lowercase + string.digits,
                                       k=30)) + ".t.evil.com"
                for _ in range(60)]
        score, _ = A.tunnel_score(subs, ["A"] * 30 + ["TXT"] * 30)
        assert score >= A.TUNNEL_THRESHOLD

    def test_evidence_shape(self):
        random.seed(3)
        subs = ["".join(random.choices(string.ascii_lowercase, k=40)) +
                ".c2.top" for _ in range(100)]
        score, ev = A.tunnel_score(subs, ["TXT"] * 100)
        for k in ("queries", "unique_prefixes", "avg_prefix_len", "avg_entropy",
                  "abnormal_type_ratio", "type_counter", "sample_prefixes",
                  "contributions", "threshold"):
            assert k in ev, f"证据缺字段 {k}"
        assert ev["type_counter"]["TXT"] == 100

    def test_empty_input_safe(self):
        score, ev = A.tunnel_score([], [])
        assert score == 0.0
        assert ev["queries"] == 0
