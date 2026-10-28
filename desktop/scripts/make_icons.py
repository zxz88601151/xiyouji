# -*- coding: utf-8 -*-
"""生成 S1 占位图标（无品牌设计，仅避免 Tauri 打包缺图标）。

用法: python scripts/make_icons.py
"""
import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "src-tauri", "icons")
os.makedirs(OUT, exist_ok=True)

SIZE = 1024
BG = (30, 31, 34, 255)
ACCENT = (55, 138, 221, 255)
TEXT = (232, 234, 237, 255)


def render() -> Image.Image:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius=220, fill=BG)
    d.rounded_rectangle([90, 90, SIZE - 90, SIZE - 90], radius=160, outline=ACCENT, width=26)
    font_path = r"C:\Windows\Fonts\msyhbd.ttc"
    if not os.path.exists(font_path):
        font_path = r"C:\Windows\Fonts\msyh.ttc"
    font = ImageFont.truetype(font_path, 470)
    text = "同"
    box = d.textbbox((0, 0), text, font=font)
    w, h = box[2] - box[0], box[3] - box[1]
    d.text(((SIZE - w) / 2 - box[0], (SIZE - h) / 2 - box[1]), text, font=font, fill=TEXT)
    return img


def main() -> None:
    img = render()
    img.save(os.path.join(OUT, "icon.png"))
    for name, size in (("32x32.png", 32), ("128x128.png", 128), ("128x128@2x.png", 256)):
        img.resize((size, size), Image.LANCZOS).save(os.path.join(OUT, name))
    img.resize((256, 256), Image.LANCZOS).save(
        os.path.join(OUT, "icon.ico"),
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("icons ->", os.path.normpath(OUT))


if __name__ == "__main__":
    main()
