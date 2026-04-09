from flask import abort, flash, jsonify, redirect, render_template, request, url_for
from app import db
from app.models import Switch, SwitchNote, VlanNote
from . import switches_bp
from .arista_utils import (
    get_arp_table,
    get_config_hash,
    get_switch_data,
    get_switch_logging_last,
    get_vlan_detail,
    get_vlan_table,
    push_interface_admin_state,
    push_switch_config,
)

@switches_bp.route('/')
def index():
    switches = Switch.query.all()
    return render_template('index.html', switches=switches)

@switches_bp.route('/add', methods=['GET', 'POST'])
def add_switch():
    if request.method == 'POST':
        ip = request.form.get('ip_address')
        user = request.form.get('username')
        desc = request.form.get('description')
        
        new_switch = Switch(ip_address=ip, username=user, description=desc)
        db.session.add(new_switch)
        db.session.commit()
        return redirect(url_for('switches.index'))
        
    return render_template('add_switch.html')

def _switch_notes_for(switch_id: int):
    return (
        SwitchNote.query.filter_by(switch_id=switch_id)
        .order_by(SwitchNote.created_at.asc())
        .all()
    )


def _json_switch_update_payload():
    """Parse JSON body for async manage POSTs; returns dict or None if not JSON."""
    if not request.is_json:
        return None
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _wants_manage_json_response():
    """True when the client expects JSON (Accept or JSON request body)."""
    accept = (request.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    return bool(request.is_json)


@switches_bp.route('/manage/<int:id>', methods=['GET'])
def manage_switch(id):
    switch = Switch.query.get_or_404(id)
    data = get_switch_data(switch.ip_address, switch.username)
    notes = _switch_notes_for(switch.id)
    return render_template(
        'manage_switch.html',
        switch=switch,
        data=data,
        switch_notes=notes,
    )


@switches_bp.route('/manage/<int:id>/notes', methods=['POST'])
def switch_note_add(id):
    switch = Switch.query.get_or_404(id)
    json_body = _json_switch_update_payload()
    if json_body is not None:
        body = (json_body.get("body") or "").strip()
    else:
        body = (request.form.get("body") or "").strip()

    if not body:
        if json_body is not None:
            return jsonify({"ok": False, "error": "Note text cannot be empty."})
        flash("Note text cannot be empty.", "warning")
        return redirect(url_for("switches.manage_switch", id=switch.id))

    note = SwitchNote(switch_id=switch.id, body=body)
    db.session.add(note)
    db.session.commit()

    if json_body is not None:
        return jsonify(
            {
                "ok": True,
                "message": "Note added.",
                "note": {
                    "id": note.id,
                    "body": note.body,
                    "created_at": note.created_at.strftime("%Y-%m-%d %H:%M UTC"),
                },
            }
        )
    flash("Note added.", "success")
    return redirect(url_for("switches.manage_switch", id=switch.id))


@switches_bp.route('/manage/<int:id>/notes/<int:note_id>/delete', methods=['POST'])
def switch_note_delete(id, note_id):
    switch = Switch.query.get_or_404(id)
    note = SwitchNote.query.get_or_404(note_id)
    if note.switch_id != switch.id:
        if _wants_manage_json_response():
            return jsonify({"ok": False, "error": "Not found."}), 404
        abort(404)
    db.session.delete(note)
    db.session.commit()
    if _wants_manage_json_response():
        return jsonify(
            {"ok": True, "message": "Note removed.", "note_id": note_id}
        )
    flash("Note removed.", "success")
    return redirect(url_for("switches.manage_switch", id=switch.id))


@switches_bp.route('/manage/<int:id>/update', methods=['POST'])
def update_switch(id):
    switch = Switch.query.get_or_404(id)
    json_body = _json_switch_update_payload()
    if json_body is not None:
        interface = (json_body.get("interface") or "").strip()
        description = json_body.get("description")
        mode = json_body.get("mode")
        if mode == "access":
            av = json_body.get("access_vlan")
            vlans = [str(av)] if av is not None and str(av) != "" else []
        elif mode == "trunk":
            raw = json_body.get("trunk_vlans")
            vlans = [str(x) for x in raw] if isinstance(raw, list) else []
        else:
            vlans = []
    else:
        interface = request.form.get("interface")
        description = request.form.get("description")
        mode = request.form.get("mode")
        if mode == "access":
            vlans = [request.form.get("access_vlan")]
        else:
            vlans = request.form.getlist("trunk_vlans")

    if json_body is not None and (not interface or mode not in ("access", "trunk")):
        return jsonify(
            {"ok": False, "error": "Invalid interface or switchport mode."}
        )

    success, err_detail = push_switch_config(
        switch.ip_address, switch.username, interface, description, mode, vlans
    )

    if json_body is not None:
        if success:
            new_hash, _ = get_config_hash(switch.ip_address, switch.username)
            return jsonify(
                {
                    "ok": True,
                    "message": (
                        f"Successfully updated {interface} and saved to startup-config."
                    ),
                    "hash": new_hash,
                }
            )
        return jsonify({"ok": False, "error": f"Failed to update {interface}. {err_detail}"})

    if success:
        flash(
            f"Successfully updated {interface} and saved to startup-config.", "success"
        )
    else:
        flash(f"Failed to update {interface}. {err_detail}", "danger")

    return redirect(url_for("switches.manage_switch", id=switch.id))


@switches_bp.route('/manage/<int:id>/interface-admin', methods=['POST'])
def set_interface_admin(id):
    switch = Switch.query.get_or_404(id)
    json_body = _json_switch_update_payload()

    if json_body is not None:
        interface = (json_body.get("interface") or "").strip()
        admin_state = json_body.get("admin_state")
    else:
        interface = (request.form.get("interface") or "").strip()
        admin_state = request.form.get("admin_state")

    if not interface or admin_state not in ("up", "down"):
        if json_body is not None:
            return jsonify({"ok": False, "error": "Invalid port or admin state."})
        flash("Invalid port or admin state.", "danger")
        return redirect(url_for("switches.manage_switch", id=switch.id))

    enabled = admin_state == "up"
    success, err_detail = push_interface_admin_state(
        switch.ip_address, switch.username, interface, enabled
    )

    if json_body is not None:
        if success:
            action = "enabled" if enabled else "disabled"
            new_hash, _ = get_config_hash(switch.ip_address, switch.username)
            return jsonify(
                {
                    "ok": True,
                    "message": (
                        f"Port {interface} was {action} and startup-config was saved."
                    ),
                    "admin_up": enabled,
                    "interface": interface,
                    "hash": new_hash,
                }
            )
        return jsonify(
            {
                "ok": False,
                "error": f"Failed to change admin state for {interface}. {err_detail}",
            }
        )

    if success:
        action = "enabled" if enabled else "disabled"
        flash(
            f"Port {interface} was {action} and startup-config was saved.",
            "success",
        )
    else:
        flash(f"Failed to change admin state for {interface}. {err_detail}", "danger")
    return redirect(url_for("switches.manage_switch", id=switch.id))


@switches_bp.route('/api/hash/<int:id>')
def check_hash(id):
    switch = Switch.query.get_or_404(id)
    current_hash, err = get_config_hash(switch.ip_address, switch.username)
    payload = {'hash': current_hash}
    if err:
        payload['error'] = err
    return jsonify(payload)

@switches_bp.route('/manage/<int:id>/arp', methods=['GET'])
def arp_table(id):
    switch = Switch.query.get_or_404(id)
    arp_data, connection_error = get_arp_table(switch.ip_address, switch.username)
    return render_template(
        'arp_table.html',
        switch=switch,
        arp_data=arp_data,
        connection_error=connection_error,
    )


LOG_TAIL_LINES = 50


@switches_bp.route('/manage/<int:id>/logs', methods=['GET'])
def switch_logs(id):
    switch = Switch.query.get_or_404(id)
    initial_log, initial_error = get_switch_logging_last(
        switch.ip_address, switch.username, LOG_TAIL_LINES
    )
    return render_template(
        'switch_logs.html',
        switch=switch,
        initial_log=initial_log if initial_log is not None else "",
        initial_error=initial_error,
        log_tail_lines=LOG_TAIL_LINES,
    )


@switches_bp.route('/manage/<int:id>/logs/poll', methods=['GET'])
def switch_logs_poll(id):
    switch = Switch.query.get_or_404(id)
    log_text, log_err = get_switch_logging_last(
        switch.ip_address, switch.username, LOG_TAIL_LINES
    )
    if log_err:
        resp = jsonify({"log": "", "error": log_err})
    else:
        resp = jsonify({"log": log_text if log_text is not None else "", "error": None})
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@switches_bp.route('/manage/<int:id>/vlans', methods=['GET'])
def vlan_table(id):
    switch = Switch.query.get_or_404(id)
    vlans, connection_error = get_vlan_table(switch.ip_address, switch.username)
    return render_template(
        'vlan_table.html',
        switch=switch,
        vlans=vlans,
        connection_error=connection_error,
    )


def _vlan_notes_for(switch_id: int, vlan_id: int):
    return (
        VlanNote.query.filter_by(switch_id=switch_id, vlan_id=vlan_id)
        .order_by(VlanNote.created_at.asc())
        .all()
    )


@switches_bp.route('/manage/<int:id>/vlans/<int:vlan_id>', methods=['GET'])
def vlan_detail(id, vlan_id):
    if vlan_id < 1 or vlan_id > 4094:
        abort(404)
    switch = Switch.query.get_or_404(id)
    payload, err, not_found = get_vlan_detail(
        switch.ip_address, switch.username, vlan_id
    )
    if not_found:
        abort(404)
    notes = _vlan_notes_for(switch.id, vlan_id)
    return render_template(
        'vlan_detail.html',
        switch=switch,
        vlan_id=vlan_id,
        detail=payload,
        connection_error=err,
        vlan_notes=notes,
    )


@switches_bp.route('/manage/<int:id>/vlans/<int:vlan_id>/notes', methods=['POST'])
def vlan_note_add(id, vlan_id):
    if vlan_id < 1 or vlan_id > 4094:
        abort(404)
    switch = Switch.query.get_or_404(id)
    body = (request.form.get('body') or '').strip()
    if body:
        db.session.add(
            VlanNote(switch_id=switch.id, vlan_id=vlan_id, body=body)
        )
        db.session.commit()
        flash("Note added.", "success")
    else:
        flash("Note text cannot be empty.", "warning")
    return redirect(url_for('switches.vlan_detail', id=switch.id, vlan_id=vlan_id))


@switches_bp.route(
    '/manage/<int:id>/vlans/<int:vlan_id>/notes/<int:note_id>/delete',
    methods=['POST'],
)
def vlan_note_delete(id, vlan_id, note_id):
    if vlan_id < 1 or vlan_id > 4094:
        abort(404)
    switch = Switch.query.get_or_404(id)
    note = VlanNote.query.get_or_404(note_id)
    if note.switch_id != switch.id or note.vlan_id != vlan_id:
        abort(404)
    db.session.delete(note)
    db.session.commit()
    flash("Note removed.", "success")
    return redirect(url_for('switches.vlan_detail', id=switch.id, vlan_id=vlan_id))

