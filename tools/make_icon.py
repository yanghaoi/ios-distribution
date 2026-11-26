"""Generate CydiaIcon.png for the repo.

Sileo and Zebra read <repo>/CydiaIcon.png as the source icon. 512x512 is
the size Sileo asks for; the file is small enough to sit in Git.
"""

import os

from PIL import Image, ImageDraw

OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "website", "assets", "CydiaIcon.png"
)
SIZE = 512


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def main():
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    top = (32, 52, 94)
    bottom = (18, 26, 48)

    # vertical gradient background with rounded corners
    grad = Image.new("RGB", (1, SIZE))
    gd = ImageDraw.Draw(grad)
    for y in range(SIZE):
        gd.point((0, y), lerp(top, bottom, y / (SIZE - 1)))
    grad = grad.resize((SIZE, SIZE))

    mask = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, SIZE - 1, SIZE - 1), radius=112, fill=255)
    img.paste(grad, (0, 0), mask)

    # a stylised hook: an arc plus a vertical stem
    accent = (79, 140, 255)
    lw = 34
    d.arc((126, 104, 386, 364), start=200, end=20, fill=accent, width=lw)
    d.line((256, 234, 256, 400), fill=accent, width=lw)

    # small node at the stem tip
    d.ellipse((256 - 26, 400 - 26, 256 + 26, 400 + 26), fill=accent)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img.save(OUT, "PNG", optimize=True)
    print(OUT, os.path.getsize(OUT), "bytes")


if __name__ == "__main__":
    main()