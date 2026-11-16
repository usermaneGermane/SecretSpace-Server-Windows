"""
Draw the installer's wizard pictures from the app's logo and font.

    py installer\\make_wizard_images.py

Writes installer\\wizard-*.bmp, which SecretSpace-Server.iss uses: the tall
picture on the Welcome and Finished pages and the small one in the top
right of every other page, each at 100%, 150% and 200% display scaling
(Inno Setup picks the size that fits the screen). Run it again after the
logo or the colours change, and commit the pictures; the build only reads
them, so it needs no Pillow for this. The logo and the font in art/ are
copies of the app's (SecretSpace-Client-Windows/sourceFiles); the font's
licence is art/Manrope-OFL.txt. Nothing in art/ is installed.
"""

import os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "art")

# The logo's own black background, so the logo has no visible edge; then
# the app's (theme.py) dark accent and text colours.
BG = (0x03, 0x05, 0x07)
ACCENT = (0x56, 0xE3, 0x9F)
TEXT = (0xF2, 0xF4, 0xF7)
MUTED = (0x9A, 0xA1, 0xAD)

# (width, height) at 100%, 150% and 200%, as Inno Setup 6 documents them.
LARGE = ((164, 314), (246, 471), (328, 628))
SMALL = (55, 83, 110)


def logo(size):
    image = Image.open(os.path.join(SRC, "SecretSpace-logo.png")).convert("RGBA")
    return image.resize((size, size), Image.LANCZOS)


def font(bold, size):
    name = "Manrope-Bold.ttf" if bold else "Manrope-Regular.ttf"
    return ImageFont.truetype(os.path.join(SRC, name), size)


def large(width, height):
    scale = width / 164
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    mark = round(120 * scale)
    top = round(52 * scale)
    left = (width - mark) // 2
    picture = logo(mark)
    image.paste(picture, (left, top), picture)

    title = font(True, round(19 * scale))
    y = top + mark + round(24 * scale)
    draw.text((width / 2, y), "SecretSpace", font=title, fill=TEXT, anchor="mt")
    y += round(24 * scale)
    draw.text((width / 2, y), "Server", font=font(False, round(14 * scale)),
              fill=TEXT, anchor="mt")
    y += round(30 * scale)
    line = round(26 * scale)
    draw.rounded_rectangle((width / 2 - line, y, width / 2 + line, y + max(2, round(3 * scale))),
                           radius=2, fill=ACCENT)
    y += round(14 * scale)
    small = font(False, round(10.5 * scale))
    for words in ("Your own sync server,", "on your own network."):
        draw.text((width / 2, y), words, font=small, fill=MUTED, anchor="mt")
        y += round(15 * scale)
    return image


def small(side):
    # The page header behind it is the window colour (white in the light
    # theme Windows Setup uses), so the logo sits on white.
    # The logo square gets rounded corners, like an app icon.
    image = Image.new("RGB", (side, side), (255, 255, 255))
    mark = round(side * 0.9)
    picture = logo(mark)
    mask = Image.new("L", (mark, mark), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, mark - 1, mark - 1),
                                           radius=round(mark * 0.22), fill=255)
    offset = (side - mark) // 2
    image.paste(picture, (offset, offset), mask)
    return image


def main():
    for percent, size in zip((100, 150, 200), LARGE):
        large(*size).save(os.path.join(HERE, f"wizard-large-{percent}.bmp"))
    for percent, side in zip((100, 150, 200), SMALL):
        small(side).save(os.path.join(HERE, f"wizard-small-{percent}.bmp"))
    print("wrote", len(LARGE) + len(SMALL), "pictures to", HERE)


if __name__ == "__main__":
    main()
