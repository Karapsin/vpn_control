def public_header_matches(before,after):
    if before.size!=after.size:return False
    for index,(left,right)in enumerate(zip(before.getdata(),after.getdata())):
        if (max(left)<128)!=(max(right)<128):return False
        if left==right:continue
        x=index%before.width;y=index//before.width
        if not(187<=x<198 and 29<=y<38):return False
        if sum(c*w for c,w in zip(left,(299,587,114)))<200000 or sum(c*w for c,w in zip(right,(299,587,114)))<200000 or max(abs(a-b)for a,b in zip(left,right))>1:return False
    return True

def public_submit_once():
    helper = immutable_phase_guard()
    fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if (DIRECTORY / 'submit-original-unknown.json').exists():
        raise RuntimeError('existing_field_submit_unknown_no_replay')
    image = Image.open(io.BytesIO(view.capture_png())).convert('RGB')
    if image.size != baseline.size or not public_header_matches(baseline.crop((420, 220, 620, 295)), image.crop((420, 220, 620, 295))) or baseline.crop((405, 302, 620, 322)).tobytes() != image.crop((405, 302, 620, 322)).tobytes():
        raise RuntimeError('existing_field_recipient_still_unproven')
    immutable_phase_guard()
    helper['record'](DIRECTORY / 'submit-original-unknown.json', {'operationId': OPERATION, 'state': 'unknown', 'action': 'once_submit_existing_typed_admin_field_no_retype', 'originalSecretOperation': runpy.run_path(str(ORIGINAL / 'normal-continuation-admin-authorization.inert.py'))['SECRET_OPERATION']})
    view.mouse(568, 382, buttons=1)
    view.mouse(568, 382, buttons=0)
    helper['record'](DIRECTORY / 'submit-transport-complete.json', {'operationId': OPERATION, 'state': 'submitted_awaiting_original_continuation_observation'})
