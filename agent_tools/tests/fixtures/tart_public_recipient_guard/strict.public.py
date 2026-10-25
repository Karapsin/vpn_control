def recipient_guard():
                bound_source_guard()
                image=Image.open(io.BytesIO(view.capture_png())).convert("RGB")
                if image.size!=baseline.size or any(image.crop(box).tobytes()!=want for box,want in zip(boxes,expected)):
                    raise RuntimeError("normal_admin_prompt_or_account_changed")
