# Data notices

## addresses_jp.tsv.gz

Derived from **Geolonia 住所データ** (Geolonia Japanese address data),
https://github.com/geolonia/japanese-addresses, `data/latest.csv`, downloaded 2026-11-09.
License: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Geolonia builds it from 国土交通省 位置参照情報 (MLIT location reference information)
and 日本郵便 郵便番号データ (Japan Post postal code data).

Changes: only towns with numbered 丁目 are kept, reduced to
prefecture, municipality, town name and the list of 丁目 numbers
(`scripts/build_tables.py`). Coordinates, kana, romaji and 小字 are dropped.

## names_jp.tsv

Surnames (with frequency weights) and given names, each with katakana and romaji,
from the `ja_JP` person provider of **Faker** (https://github.com/joke2k/faker),
MIT License, Copyright (c) 2012 Daniele Faraglia. Combined with the ordinary
given names in `shinafure/canary.py`.
