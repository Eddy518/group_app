import os
import secrets
from PIL import Image
from flask import current_app


def save_picture(form_picture, is_banner=False):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext

    if is_banner:
        # For group banner images
        output_size = (1200, 400)  # Good size for banner images
        folder = "group_banners"
    else:
        # For group icon/avatar images
        output_size = (300, 300)  # Larger size for group icons
        folder = "group_icons"

    picture_path = os.path.join(
        current_app.root_path, "static/assets", folder, picture_fn
    )

    # Open and resize the image while maintaining aspect ratio
    i = Image.open(form_picture)

    # Convert image to RGB if it's not
    if i.mode != "RGB":
        i = i.convert("RGB")

    # Calculate aspect ratio
    aspect_ratio = i.width / i.height

    if is_banner:
        # For banners, we might want to crop to maintain the aspect ratio
        target_ratio = output_size[0] / output_size[1]

        if aspect_ratio > target_ratio:
            # Image is wider than needed
            new_width = int(output_size[1] * aspect_ratio)
            i = i.resize((new_width, output_size[1]), Image.Resampling.LANCZOS)
            left = (i.width - output_size[0]) // 2
            i = i.crop((left, 0, left + output_size[0], output_size[1]))
        else:
            # Image is taller than needed
            new_height = int(output_size[0] / aspect_ratio)
            i = i.resize((output_size[0], new_height), Image.Resampling.LANCZOS)
            top = (i.height - output_size[1]) // 2
            i = i.crop((0, top, output_size[0], top + output_size[1]))
    else:
        # For icons, maintain square aspect ratio
        if i.width != i.height:
            # Crop to square
            min_dim = min(i.width, i.height)
            left = (i.width - min_dim) // 2
            top = (i.height - min_dim) // 2
            i = i.crop((left, top, left + min_dim, top + min_dim))

        i = i.resize(output_size, Image.Resampling.LANCZOS)

    # Ensure the directory exists
    os.makedirs(os.path.dirname(picture_path), exist_ok=True)

    # Save with good quality
    i.save(picture_path, quality=95, optimize=True)

    return picture_fn
