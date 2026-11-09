"""Canary people: plausible customers that exist nowhere else.

Design rules
  * Detection rests on fields that are *globally unique by construction*:
    an email at a domain the registrant controls with a random suffix, and a
    phone number the registrant controls. Names and addresses only confirm.
  * Names are rare-but-real readings combined so that the full name is
    vanishingly unlikely to belong to anyone (measured against corpora in
    demo/measure.py, not assumed).
  * Phone numbers: in production, use numbers you own (a block of virtual
    numbers), so a canary can never coincide with a real person's number and
    a call or SMS to it is itself a second tripwire. The demo draws random
    070 numbers, which is NOT safe for production.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field

# (kanji, katakana, romaji): uncommon but genuine surnames and given names
SURNAMES = [
    ("鷲見", "スミ", "Sumi"), ("東海林", "ショウジ", "Shoji"), ("小鳥遊", "タカナシ", "Takanashi"),
    ("薬袋", "ミナイ", "Minai"), ("十河", "ソゴウ", "Sogo"), ("百目鬼", "ドウメキ", "Domeki"),
    ("九十九", "ツクモ", "Tsukumo"), ("御手洗", "ミタライ", "Mitarai"), ("月見里", "ヤマナシ", "Yamanashi"),
    ("寒河江", "サガエ", "Sagae"), ("猪狩", "イガリ", "Igari"), ("朝比奈", "アサヒナ", "Asahina"),
    ("宍戸", "シシド", "Shishido"), ("蓬莱", "ホウライ", "Horai"), ("伊集院", "イジュウイン", "Ijuin"),
    ("綾小路", "アヤノコウジ", "Ayanokoji"), ("轟木", "トドロキ", "Todoroki"), ("左右田", "ソウダ", "Soda"),
    ("勅使河原", "テシガワラ", "Teshigawara"), ("五百旗頭", "イオキベ", "Iokibe"),
]
GIVEN = [
    ("朔眞", "サクマ", "Sakuma"), ("瑛璃", "エイリ", "Eiri"), ("柊吾", "シュウゴ", "Shugo"),
    ("澪央", "レオ", "Reo"), ("樹璃", "ジュリ", "Juri"), ("琥太郎", "コタロウ", "Kotaro"),
    ("雫玖", "シズク", "Shizuku"), ("楓真", "フウマ", "Fuma"), ("珀斗", "ハクト", "Hakuto"),
    ("凛桜", "リオ", "Rio"), ("叶羽", "カナウ", "Kanau"), ("蒼梧", "ソウゴ", "Sogo"),
    ("侑李", "ユウリ", "Yuri"), ("眞白", "マシロ", "Mashiro"), ("稜真", "リョウマ", "Ryoma"),
    ("緋鞠", "ヒマリ", "Himari"), ("迅彌", "ジンヤ", "Jinya"), ("紗耶禾", "サヤカ", "Sayaka"),
    ("瑠珂", "ルカ", "Ruka"), ("篤斐", "アツヒ", "Atsuhi"),
]
# Common surnames / given names: canaries that look like everyone else, so a
# summarizing or grouping model is less likely to drop them as noise.
ORD_SURNAMES = [
    ("佐藤", "サトウ", "Sato"), ("鈴木", "スズキ", "Suzuki"), ("高橋", "タカハシ", "Takahashi"),
    ("田中", "タナカ", "Tanaka"), ("伊藤", "イトウ", "Ito"), ("渡辺", "ワタナベ", "Watanabe"),
    ("山本", "ヤマモト", "Yamamoto"), ("中村", "ナカムラ", "Nakamura"), ("加藤", "カトウ", "Kato"),
    ("吉田", "ヨシダ", "Yoshida"), ("山田", "ヤマダ", "Yamada"), ("佐々木", "ササキ", "Sasaki"),
    ("山口", "ヤマグチ", "Yamaguchi"), ("松本", "マツモト", "Matsumoto"), ("井上", "イノウエ", "Inoue"),
    ("木村", "キムラ", "Kimura"), ("斎藤", "サイトウ", "Saito"), ("清水", "シミズ", "Shimizu"),
    ("山崎", "ヤマザキ", "Yamazaki"), ("池田", "イケダ", "Ikeda"), ("橋本", "ハシモト", "Hashimoto"),
    ("阿部", "アベ", "Abe"), ("石川", "イシカワ", "Ishikawa"), ("山下", "ヤマシタ", "Yamashita"),
    ("中島", "ナカジマ", "Nakajima"), ("石井", "イシイ", "Ishii"), ("小川", "オガワ", "Ogawa"),
    ("前田", "マエダ", "Maeda"), ("藤田", "フジタ", "Fujita"), ("岡田", "オカダ", "Okada"),
]
ORD_GIVEN = [
    ("健太", "ケンタ", "Kenta"), ("翔太", "ショウタ", "Shota"), ("大輔", "ダイスケ", "Daisuke"),
    ("拓也", "タクヤ", "Takuya"), ("直樹", "ナオキ", "Naoki"), ("和也", "カズヤ", "Kazuya"),
    ("達也", "タツヤ", "Tatsuya"), ("浩二", "コウジ", "Koji"), ("健一", "ケンイチ", "Kenichi"),
    ("優子", "ユウコ", "Yuko"), ("真由美", "マユミ", "Mayumi"), ("陽子", "ヨウコ", "Yoko"),
    ("美咲", "ミサキ", "Misaki"), ("結衣", "ユイ", "Yui"), ("智子", "トモコ", "Tomoko"),
    ("千尋", "チヒロ", "Chihiro"), ("涼子", "リョウコ", "Ryoko"), ("美穂", "ミホ", "Miho"),
    ("奈々", "ナナ", "Nana"), ("恵美", "エミ", "Emi"),
]
PLACES = [("東京都", "港区赤坂"), ("神奈川県", "横浜市青葉区美しが丘"), ("大阪府", "吹田市千里山東"),
          ("愛知県", "名古屋市千種区覚王山通"), ("福岡県", "福岡市中央区薬院"), ("北海道", "札幌市中央区宮の森"),
          ("京都府", "京都市左京区下鴨"), ("宮城県", "仙台市青葉区国分町")]
BUILDINGS = ["ハイツ", "コーポ", "レジデンス", "メゾン", "パレス"]


@dataclass
class Canary:
    canary_id: str
    dataset: str          # which dataset / system / contractor this copy was planted in
    person: dict = field(default_factory=dict)


def _suffix(rng, n=5) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(n))


def make_canaries(n: int, dataset: str, email_domain: str, rng=None,
                  style: str = "mixed", rare_ratio: float = 0.2) -> list[Canary]:
    """`email_domain` must be a domain the registrant controls.

    style
      rare     : uncommon names. Unique enough to detect a name-only extract
                 (two such names together confirm), but measured to be dropped
                 more often by summarizing/grouping models.
      ordinary : common names. Blend in; detection rests on email, phone and
                 address (names only count together with a partner).
      mixed    : `rare_ratio` of them rare, the rest ordinary (default).

    Measured with qwen2.5:7b on a "group customers by family" task: rare
    canaries survived 55% (11/20) vs 81% for the real rows around them
    (p=0.007); ordinary canaries 75% (15/20) vs 78% (p=0.78). Rare ones are
    singled out; ordinary ones blend in. See README.
    """
    if style not in ("rare", "ordinary", "mixed"):
        raise ValueError("style must be rare, ordinary or mixed")
    rng = rng or secrets.SystemRandom()
    used, out = set(), []
    while len(out) < n:
        kind = style if style != "mixed" else ("rare" if rng.random() < rare_ratio else "ordinary")
        S, G = (SURNAMES, GIVEN) if kind == "rare" else (ORD_SURNAMES, ORD_GIVEN)
        s, g = rng.choice(S), rng.choice(G)
        if (s, g) in used:
            continue
        used.add((s, g))
        pref, town = rng.choice(PLACES)
        person = {
            "last": s[0], "first": g[0], "last_kana": s[1], "first_kana": g[1],
            "last_roma": s[2], "first_roma": g[2],
            "email": f"{g[2].lower()}.{s[2].lower()}.{_suffix(rng)}@{email_domain}",
            "phone": f"070-{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}",
            "address": f"{pref}{town}{rng.randint(1, 9)}丁目{rng.randint(1, 30)}番{rng.randint(1, 20)}号 "
                       f"{s[0]}{rng.choice(BUILDINGS)}{rng.randint(1, 9)}0{rng.randint(1, 9)}",
            "style": kind,
        }
        out.append(Canary(f"{dataset}-{_suffix(rng, 8)}", dataset, person))
    return out
